#!/usr/bin/env python3
import argparse
from itertools import chain
import re
import signal
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Pattern, Union
import urllib.parse as up
from prometheus_client import REGISTRY, start_http_server
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily, Metric
import requests
import yaml


RealNumber = Union[int, float]
JsonType = Union[None, str, int, float, bool, List['JsonType'], Dict[str, 'JsonType']]


DEFAULT_PORT = 9377
DEFAULT_TIMEOUT = 10
APIC_COOKIE_NAME = "APIC-cookie"
METRIC_TYPES = {
    'gauge': GaugeMetricFamily,
    'counter': CounterMetricFamily,
    # TODO: histogram and summary
}


class AciSession(object):
    def __init__(self, controller: str) -> None:
        self.controller: str = controller
        self.timeout: RealNumber = DEFAULT_TIMEOUT
        self.auth_user: Optional[str] = None
        self.auth_token: Optional[str] = None
        self.tls_verify: Union[str, bool] = False

    def auth(self, auth_config: Dict[str, JsonType]) -> None:
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

        self.auth_user = auth_config['username']
        self.auth_token = response.cookies[APIC_COOKIE_NAME]


    def logout(self) -> None:
        if self.auth_user is None:
            return

        logout_payload = {
            "aaaUser": {
                "attributes": {
                    "name": self.auth_user,
                }
            }
        }
        response = requests.post(
            f"https://{self.controller}/api/aaaLogout.json",
            json=logout_payload,
            cookies={APIC_COOKIE_NAME: self.auth_token},
            timeout=self.timeout,
            verify=self.tls_verify,
        )
        response.raise_for_status()

        self.auth_user = None
        self.auth_token = None


    def obtain_instances(
            self, class_name: str, filter_string: Optional[str] = None,
            scope: str = "self"
    ) -> Dict[str, JsonType]:
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
    def __init__(self, config: Dict[str, JsonType]) -> None:
        self.config: Dict[str, JsonType] = config
        self.pending_config: Optional[Dict[str, JsonType]] = None
        self.timeout: RealNumber = DEFAULT_TIMEOUT
        self.regex_cache: Dict[str, Pattern] = {}

    def collect(self) -> Iterable[Metric]:
        if self.pending_config is not None:
            self.config = self.pending_config
            self.pending_config = None

        scrape_duration_metric = GaugeMetricFamily(
            'aci_scrape_duration_seconds',
            'The duration, in seconds, of the last scrape of the fabric.',
            labels=['fabric']
        )

        common_queries = self.config.get('common_queries', dict())

        for fabric_name, fabric in self.config['fabrics'].items():
            time_start = time.perf_counter()

            # try each controller in turn
            working_index = None
            for i, controller in enumerate(fabric['controllers']):
                try:
                    yield from self.collect_fabric(fabric_name, fabric, controller, common_queries)

                    working_index = i
                    break

                except requests.exceptions.Timeout:
                    # try the next controller
                    pass

            time_end = time.perf_counter()

            # reorder controllers?
            if working_index is not None and working_index > 0:
                # yes
                cur_ctrls = fabric['controllers']
                fabric['controllers'] = cur_ctrls[working_index:] + cur_ctrls[:working_index]

                # note that the order is reset when the configuration is reloaded (e.g. SIGHUP)

            scrape_duration_metric.add_metric([fabric_name], time_end - time_start)

        yield scrape_duration_metric

    def collect_fabric(
            self, fabric_name: str, fabric: Dict[str, JsonType], controller: str,
            common_queries: Dict[str, JsonType]
    ) -> Iterable[Metric]:
        session = AciSession(controller)
        session.auth(fabric['auth'])

        all_queries = chain(
            fabric.get('queries', dict()).items(),
            common_queries.items()
        )
        for query_name, query in all_queries:
            class_name = query['class_name']
            scope = query.get('scope', 'self')
            filter_string = query.get('filter', None)

            instances = session.obtain_instances(class_name, filter_string, scope)

            metric_definitions = {}

            count_metric = query.get('count_metric', None)
            if count_metric is not None:
                count_labels = {}
                self._add_common_labels(count_labels, query, query_name, fabric_name, class_name)

                count_help_text = query.get('count_metric_help_text', '')
                # instance counts are always gauges
                count_metric_object = GaugeMetricFamily(
                    count_metric, count_help_text, labels=count_labels.keys()
                )
                count_metric_object.add_metric(count_labels.values(), len(instances['imdata']))
                metric_definitions[count_metric] = count_metric_object

            all_values_labels = []
            for instance in instances['imdata']:
                drop_instance = False
                class_name = list(instance.keys())[0]
                attributes = instance[class_name]['attributes']

                labels = {}
                self._add_common_labels(labels, query, query_name, fabric_name, class_name)
                for label_definition in query.get('labels', list()):
                    updated_labels = self.process_value(attributes, label_definition)
                    if updated_labels is None:
                        drop_instance = True
                        break
                    labels.update(updated_labels)

                if drop_instance:
                    continue

                values = {}

                for value_definition in query.get('metrics', list()):
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
                    values.update(value)

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

        session.logout()


    @staticmethod
    def _add_common_labels(
            labels: Dict[str, str], query: Dict[str, JsonType],
            query_name: str, fabric_name: str, class_name: str
    ) -> None:
        if not query.get('omit_query_name_label', False):
            labels['queryName'] = query_name
        if not query.get('omit_fabric_label', False):
            labels['fabric'] = fabric_name
        if not query.get('omit_class_name_label', False):
            labels['className'] = class_name


    def process_value(
            self, attributes: Dict[str, JsonType], definition: Dict[str, JsonType]
    ) -> JsonType:
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


def load_config(config_file_name: str) -> JsonType:
    with open(config_file_name, "r", encoding="utf-8") as config_file:
        return yaml.safe_load(config_file)


def get_sighup_handler(
        aci_collector: AciCollector, config_file_name: str
) -> Callable[[Any, Any], None]:

    def handle_sighup(_signal_number, _stack_frame) -> None:
        config = load_config(config_file_name)
        aci_collector.pending_config = config

    return handle_sighup


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config.file", dest="config_file", default="aci.yml")
    parser.add_argument("--web.listen-port", dest="web_listen_port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--web.listen-address", dest="web_listen_address", type=str, default="")
    args = parser.parse_args()

    config = load_config(args.config_file)

    aci_collector = AciCollector(config)
    REGISTRY.register(aci_collector)

    if hasattr(signal, 'SIGHUP'):
        sighup_handler = get_sighup_handler(aci_collector, args.config_file)
        signal.signal(signal.SIGHUP, sighup_handler)

    start_http_server(args.web_listen_port, args.web_listen_address)

    while True:
        time.sleep(9001)

if __name__ == '__main__':
    main()
