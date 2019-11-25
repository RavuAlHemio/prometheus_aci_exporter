#!/usr/bin/env python3
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from itertools import chain
import re
import signal
from socketserver import ThreadingMixIn
from threading import Thread
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Pattern, Union
import urllib.parse as up
import requests
import yaml


RealNumber = Union[int, float]
JsonType = Union[None, str, int, float, bool, List['JsonType'], Dict[str, 'JsonType']]


DEFAULT_PORT = 9377
DEFAULT_TIMEOUT = 10
APIC_COOKIE_NAME = "APIC-cookie"
PROM_METRIC_NAME_RE = re.compile("^[a-zA-Z_:][a-zA-Z0-9_:]*$")
PROM_LABEL_NAME_RE = re.compile("^[a-zA-Z_][a-zA-Z0-9_]*$")


class Metric:
    def __init__(self, metric_name, metric_type, help_text=None, label_keys=None):
        if label_keys is None:
            label_keys = ()

        if PROM_METRIC_NAME_RE.match(metric_name) is None:
            raise ValueError(f"invalid metric_name {metric_name!r} (must match {PROM_METRIC_NAME_RE.pattern!r})")

        for key in label_keys:
            if PROM_LABEL_NAME_RE.match(key) is None:
                raise ValueError(f"invalid entry {key!r} in label_keys (must match {PROM_LABEL_NAME_RE.pattern!r})")

        self.metric_name = metric_name
        self.metric_type = metric_type
        self.help_text = help_text
        self.label_keys = tuple(label_keys)
        self.unit = None

        self._values = []

    def add_value(self, value, label_values=None, timestamp=None):
        # timestamp: seconds since Unix epoch (or None)
        if label_values is None:
            label_values = ()

        label_values = tuple(label_values)
        if len(label_values) != len(self.label_keys):
            raise ValueError(f"len(label_values) ({len(label_values)}) does not equal len(self.label_keys) ({len(self.label_keys)})")

        self._values.append((value, timestamp, label_values))

    @staticmethod
    def sanitize_help_text(help_text):
        return help_text.replace("\\", "\\\\").replace("\n", "\\n")

    @staticmethod
    def escape_label_value(lbl_val):
        ret = []
        for c in lbl_val:
            if c == '\\':
                ret.append('\\\\')
            elif c == '"':
                ret.append('\\"')
            elif c == '\n':
                ret.append('\\n')
            else:
                ret.append(c)
        return "".join(ret)

    @staticmethod
    def quote_label_value(lbl_val):
        return f'"{Metric.escape_label_value(lbl_val)}"'

    def generate(self, fmt='prometheus'):
        if fmt not in ('prometheus', 'openmetrics'):
            raise ValueError(f"unknown format: {fmt!r}")

        lines = []

        metric_type = (
            self.metric_type
            if self.metric_type in ("counter", "gauge", "histogram", "summary")
            else "untyped"
        )

        metric_name, metric_name_tail = self.metric_name, ""
        if metric_type == 'counter' and fmt != 'prometheus':
            if metric_name.endswith("_total"):
                metric_name = metric_name[:len("_total")]
            metric_name_tail = "_total"

        lines.append(f"# TYPE {metric_name} {metric_type}")

        if self.help_text is not None:
            if fmt == 'prometheus':
                help_text_sanitized = self.help_text.replace("\\", "\\\\").replace("\n", "\\n")
            else:
                help_text_sanitized = Metric.escape_label_value(self.help_text)
            lines.append(f"# HELP {metric_name} {help_text_sanitized}")

        if self.unit is not None and fmt != 'prometheus':
            lines.append(f"# UNIT {metric_name} {self.unit}")

        for val, tstamp, lbl_vals in self._values:
            ob, cb = '{', '}'
            line_pieces = [metric_name, metric_name_tail]

            lbl_kvps = [
                f"{k}={Metric.quote_label_value(v)}"
                for (k, v)
                in sorted(zip(self.label_keys, lbl_vals))
            ]
            if lbl_kvps:
                line_pieces.append(f"{ob}{','.join(lbl_kvps)}{cb}")

            line_pieces.append(f" {val}")

            if tstamp is not None:
                if fmt == 'prometheus':
                    # milliseconds instead of seconds
                    tstamp *= 1000
                line_pieces.append(f" {tstamp}")

            lines.append("".join(line_pieces))

        return "".join(f"{ln}\n" for ln in lines)


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

        scrape_duration_metric = Metric(
            'aci_scrape_duration_seconds',
            'gauge',
            'The duration, in seconds, of the last scrape of the fabric.',
            label_keys=('fabric',)
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

            scrape_duration_metric.add_value(time_end - time_start, (fabric_name,))

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
                count_metric_object = Metric(
                    count_metric, 'gauge', count_help_text, label_keys=count_labels.keys()
                )
                count_metric_object.add_value(len(instances['imdata']), count_labels.values())
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

                    metric_object = Metric(
                        metric_name, metric_type, help_text,
                        label_keys=labels.keys()
                    )
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
                    metric_object.add_value(float(value), labels.values())

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

        # type conversion
        type_key = definition.get('value_type', None)
        if type_key is not None:
            type_func = {
                'str': str,
                'int': int,
                'float': float,
            }.get(type_key, None)
            if type_func is None:
                raise ValueError(f"unknown type conversion function {type_func!r}")
            property_value = type_func(property_value)

        # range validity
        invalid_below = definition.get('invalid_below', None)
        clamp_bottom = definition.get('clamp_bottom', None)
        if invalid_below is not None:
            # convert property_value to the type of invalid_below before comparing
            if type(invalid_below)(property_value) < invalid_below:
                return None
        elif clamp_bottom is not None:
            if type(clamp_bottom)(property_value) < clamp_bottom:
                property_value = clamp_bottom

        invalid_above = definition.get('invalid_above', None)
        clamp_top = definition.get('clamp_top', None)
        if invalid_above is not None:
            if type(invalid_above)(property_value) > invalid_above:
                return None
        if clamp_top is not None:
            if type(clamp_top)(property_value) > clamp_top:
                property_value = clamp_top

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


class MetricsHandler(BaseHTTPRequestHandler):
    collector = None
    args = None

    def do_GET(self):
        output_format = 'prometheus'
        if getattr(self.args, 'web_openmetrics', False):
            accept_header = self.headers.get('Accept', '')
            for accepted_type in accept_header.split(','):
                if accepted_type.split(';')[0].strip() == 'application/openmetrics-text':
                    output_format = 'openmetrics'

        collector = self.collector
        generated_lines = [
            metric.generate(fmt=output_format).encode('utf-8')
            for metric
            in collector.collect()
        ]
        self.send_response(200)
        if output_format == 'prometheus':
            self.send_header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
        else:
            self.send_header('Content-Type', 'application/openmetrics-text; version=0.0.1; charset=utf-8')
        self.end_headers()

        for line in generated_lines:
            # lines are already terminated appropriately
            self.wfile.write(line)

        if output_format != 'prometheus':
            self.wfile.write(b'# EOF\n')

    def log_message(self, format, *args):
        return

    @classmethod
    def factory(cls, collector, args):
        cls_name = str(cls.__name__)
        CustomizedMetricsHandler = type(
            cls_name,
            (cls, object),
            {"collector": collector, "args": args}
        )
        return CustomizedMetricsHandler


class ThreadingSimpleHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def start_http_server(collector, port, addr='', args=None):
    CustomMetricsHandler = MetricsHandler.factory(collector, args)
    server = ThreadingSimpleHTTPServer((addr, port), CustomMetricsHandler)
    server_thread = Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config.file", dest="config_file", default="aci.yml")
    parser.add_argument("--web.listen-port", dest="web_listen_port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--web.listen-address", dest="web_listen_address", type=str, default="")
    parser.add_argument("--web.openmetrics", dest="web_openmetrics", action="store_true")
    args = parser.parse_args()

    config = load_config(args.config_file)

    aci_collector = AciCollector(config)

    if hasattr(signal, 'SIGHUP'):
        sighup_handler = get_sighup_handler(aci_collector, args.config_file)
        signal.signal(signal.SIGHUP, sighup_handler)

    start_http_server(aci_collector, args.web_listen_port, args.web_listen_address, args)

    while True:
        time.sleep(9001)

if __name__ == '__main__':
    main()
