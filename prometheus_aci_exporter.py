#!/usr/bin/env python3
import argparse
import re
import signal
import time
import urllib.parse as up
from prometheus_client import REGISTRY, start_http_server
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily
import requests
import yaml


DEFAULT_PORT = 9377
DEFAULT_TIMEOUT = 10
APIC_COOKIE_NAME = "APIC-cookie"
METRIC_TYPES = {
    'gauge': GaugeMetricFamily,
    'counter': CounterMetricFamily,
    # TODO: histogram and summary
}


class AciSession(object):
    def __init__(self, controller):
        self.controller = controller
        self.timeout = DEFAULT_TIMEOUT
        self.auth_token = None
        self.tls_verify = False

    def auth(self, auth_config):
        # TODO: certificate auth

        controller_ca_cert = auth_config.get('controller_ca_cert', None)
        if controller_ca_cert is not None:
            self.tls_verify = controller_ca_cert

        auth_payload = {
            "aaaUser": {
                "attributes": {
                    "name": auth_config['username'],
                    "pwd": auth_config['password']
                }
            }
        }
        response = requests.post(
            f"https://{self.controller}/api/aaaLogin.json",
            json=auth_payload,
            timeout=self.timeout,
            verify=self.tls_verify
        )
        response.raise_for_status()

        self.auth_token = response.cookies[APIC_COOKIE_NAME]

    def obtain_instances(self, class_name, filter_string=None, scope="self"):
        escaped_class = up.quote(class_name)

        query_options = {
            "query-target": scope,
        }
        if filter_string is not None:
            query_options['query-target-filter'] = filter_string

        response = requests.get(
            f"https://{self.controller}/api/class/{escaped_class}.json",
            params=query_options,
            cookies={APIC_COOKIE_NAME: self.auth_token},
            timeout=self.timeout,
            verify=self.tls_verify
        )
        response.raise_for_status()

        return response.json()


class AciCollector(object):
    def __init__(self, config):
        self.config = config
        self.pending_config = None
        self.timeout = DEFAULT_TIMEOUT
        self.regex_cache = {}

    def collect(self):
        if self.pending_config is not None:
            self.config = self.pending_config
            self.pending_config = None

        for fabric_name, fabric in self.config.items():
            controllers = fabric['controllers']

            # FIXME: actually support multiple controllers
            session = AciSession(controllers[0])
            session.auth(fabric['auth'])

            for query_name, query in fabric['queries'].items():
                class_name = query['class_name']
                scope = query.get('scope', 'self')
                filter_string = query.get('filter', None)

                instances = session.obtain_instances(class_name, filter_string, scope)
                all_values_labels = []
                metric_definitions = {}
                for instance in instances['imdata']:
                    drop_instance = False
                    class_name = list(instance.keys())[0]
                    attributes = instance[class_name]['attributes']

                    labels = {}
                    if not query.get('omit_query_name_label', False):
                        labels['queryName'] = query_name
                    if not query.get('omit_fabric_label', False):
                        labels['fabric'] = fabric_name
                    if not query.get('omit_class_name_label', False):
                        labels['className'] = class_name
                    for label_definition in query['labels']:
                        updated_labels = self.process_value(attributes, label_definition)
                        if updated_labels is None:
                            drop_instance = True
                            break
                        labels.update(self.process_value(attributes, label_definition))

                    if drop_instance:
                        continue

                    values = {}

                    for value_definition in query['metrics']:
                        # extract the definition
                        metric_name = value_definition['key']
                        metric_type = value_definition['type']
                        help_text = value_definition.get('help_text', '')
                        family = METRIC_TYPES[metric_type]

                        metric_object = family(metric_name, help_text, labels=labels.keys())
                        metric_definitions[metric_name] = metric_object

                        # store the value
                        value = self.process_value(attributes, value_definition)
                        if value is None:
                            drop_instance = True
                            break
                        values.update(self.process_value(attributes, value_definition))

                    if drop_instance:
                        continue

                    all_values_labels.append((values, labels))

                if not all_values_labels:
                    continue

                for values, labels in all_values_labels:
                    for key, value in values.items():
                        metric_object = metric_definitions[key]
                        metric_object.add_metric(labels.values(), float(value))

                for metric_object in metric_definitions.values():
                    yield metric_object


    def process_value(self, attributes, definition):
        property_name = definition['property_name']
        property_value = attributes.get(property_name, None)
        if property_value is None:
            return None

        # transformations?

        # regex extraction
        regex_str = definition.get('regex', None)
        regex_must_match = definition.get('regex_must_match', False)
        if regex_str is not None:
            try:
                regex = self.regex_cache[regex_str]
            except KeyError:
                regex = re.compile(regex_str)
                self.regex_cache[regex_str] = regex

            match = regex.match(property_value)
            if match is not None:
                match_dict = match.groupdict()
                property_value = {k: v if v is not None else "" for (k, v) in match_dict.items()}
            elif regex_must_match:
                # it didn't match, though
                return None

        # key renaming
        key_renaming = definition.get('key_renaming', None)
        if key_renaming is not None:
            new_values = {}
            for old_key, value in property_value.items():
                new_key = key_renaming.get(old_key, old_key)
                if new_key is None:
                    # skip this value
                    continue
                new_values[new_key] = value
            property_value = new_values

        # select-case
        cases = definition.get('cases', None)
        if cases is not None:
            for old_value, new_value in cases.items():
                if property_value == old_value:
                    property_value = new_value
                    break

        # key attachment (dictionarification)
        key = definition.get('key', None)
        if key is not None:
            property_value = {key: property_value}

        return property_value


def load_config(config_file_name):
    with open(config_file_name, "r", encoding="utf-8") as config_file:
        return yaml.safe_load(config_file)


def get_sighup_handler(aci_collector, config_file_name):

    def handle_sighup(signal_number, stack_frame):
        config = load_config(config_file_name)
        aci_collector.pending_config = config

    return handle_sighup


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config.file", dest="config_file", default="aci.yml")
    parser.add_argument("--web.listen-port", dest="web_listen_port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--web.listen-address", dest="web_listen_address", type=str, default="")
    args = parser.parse_args()

    config = load_config(args.config_file)

    aci_collector = AciCollector(config)
    REGISTRY.register(aci_collector)

    if 'SIGHUP' in dir(signal):
        sighup_handler = get_sighup_handler(aci_collector, args.config_file)
        signal.signal(signal.SIGHUP, sighup_handler)

    start_http_server(args.web_listen_port, args.web_listen_address)

    while True:
        time.sleep(9001)

if __name__ == '__main__':
    main()
