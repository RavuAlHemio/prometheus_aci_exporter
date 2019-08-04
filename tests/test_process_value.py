import importlib.util


def get_module():
    spec = importlib.util.spec_from_file_location(
        "prometheus_aci_exporter",
        "../prometheus_aci_exporter.py",
    )
    mdl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mdl)
    return mdl

def process_value(attributes, definition):
    mdl = get_module()
    collector = mdl.AciCollector(config={})
    return collector.process_value(attributes, definition)


def test_direct_str():
    attributes = {
        'name': 'spine2',
    }
    definition = {
        'property_name': 'name',
    }
    val = process_value(attributes, definition)

    assert isinstance(val, str)
    assert val == 'spine2'

def test_direct_int():
    attributes = {
        'id': 152,
    }
    definition = {
        'property_name': 'id',
    }
    val = process_value(attributes, definition)

    assert isinstance(val, int)
    assert val == 152

def test_direct_float():
    attributes = {
        'val': 123.4,
    }
    definition = {
        'property_name': 'val',
    }
    val = process_value(attributes, definition)

    assert isinstance(val, float)
    assert val == 123.4

def test_clamp_within():
    attributes = {
        'healthLast': 71,
    }
    definition = {
        'property_name': 'healthLast',
        'clamp_bottom': 0,
        'clamp_top': 100,
    }
    val = process_value(attributes, definition)

    assert isinstance(val, int)
    assert val == 71

def test_clamp_above():
    attributes = {
        'healthLast': -5,
    }
    definition = {
        'property_name': 'healthLast',
        'clamp_bottom': 0,
        'clamp_top': 100,
    }
    val = process_value(attributes, definition)

    assert isinstance(val, int)
    assert val == 0

def test_clamp_below():
    attributes = {
        'healthLast': 105,
    }
    definition = {
        'property_name': 'healthLast',
        'clamp_bottom': 0,
        'clamp_top': 100,
    }
    val = process_value(attributes, definition)

    assert isinstance(val, int)
    assert val == 100

def test_valid_within():
    attributes = {
        'healthLast': 71,
    }
    definition = {
        'property_name': 'healthLast',
        'invalid_below': 0,
        'invalid_above': 100,
    }
    val = process_value(attributes, definition)

    assert isinstance(val, int)
    assert val == 71

def test_valid_above():
    attributes = {
        'healthLast': -5,
    }
    definition = {
        'property_name': 'healthLast',
        'invalid_below': 0,
        'invalid_above': 100,
    }
    val = process_value(attributes, definition)

    assert val is None

def test_valid_below():
    attributes = {
        'healthLast': 105,
    }
    definition = {
        'property_name': 'healthLast',
        'invalid_below': 0,
        'invalid_above': 100,
    }
    val = process_value(attributes, definition)

    assert val is None

def test_regex_success():
    attributes = {
        'dn': 'topology/pod-1/node-102/sys/ch/supslot-1/sup/sensor-1/CDeqptTemp5min',
    }
    definition = {
        'property_name': 'dn',
        'regex': '^topology/pod-(?P<pod>[1-9][0-9]*)/node-(?P<node>[1-9][0-9]*)/sys/ch/(?P<slotType>[a-z]+)(?:-(?P<slot>[^/]+))?/(?P<device>[^/]+)/sensor-(?P<sensorNumber>[^/]+)/',
    }
    val = process_value(attributes, definition)

    assert val['pod'] == '1'
    assert val['node'] == '102'
    assert val['slotType'] == 'supslot'
    assert val['slot'] == '1'
    assert val['device'] == 'sup'
    assert val['sensorNumber'] == '1'
    assert len(val) == 6

def text_regex_failure():
    attributes = {
        'dn': 'topology/pod-1/node-102/sys/notchassis/supslot-1/sup/sensor-1/CDeqptTemp5min',
    }
    definition = {
        'property_name': 'dn',
        'regex': '^topology/pod-(?P<pod>[1-9][0-9]*)/node-(?P<node>[1-9][0-9]*)/sys/ch/(?P<slotType>[a-z]+)(?:-(?P<slot>[^/]+))?/(?P<device>[^/]+)/sensor-(?P<sensorNumber>[^/]+)/',
    }
    val = process_value(attributes, definition)

    assert val is None

def test_key_renaming():
    attributes = {
        'dn': 'topology/pod-1/node-102/sys/ch/supslot-1/sup/sensor-1/CDeqptTemp5min',
    }
    definition = {
        'property_name': 'dn',
        'regex': '^topology/pod-(?P<pod>[1-9][0-9]*)/node-(?P<node>[1-9][0-9]*)/sys/ch/(?P<slotType>[a-z]+)(?:-(?P<slot>[^/]+))?/(?P<device>[^/]+)/sensor-(?P<sensorNumber>[^/]+)/',
        'key_renaming': {
            'slotType': 'slot-type',
            'sensorNumber': 'sensor-number',
        },
    }
    val = process_value(attributes, definition)

    assert val['pod'] == '1'
    assert val['node'] == '102'
    assert val['slot-type'] == 'supslot'
    assert val['slot'] == '1'
    assert val['device'] == 'sup'
    assert val['sensor-number'] == '1'
    assert len(val) == 6

def test_cases():
    attributes = {
        'operSpeed': '40G',
    }
    definition = {
        'property_name': 'operSpeed',
        'cases': {
            'unknown':            0,
            '100M':     100_000_000,
            '1G':     1_000_000_000,
            '10G':   10_000_000_000,
            '25G':   25_000_000_000,
            '40G':   40_000_000_000,
            '100G': 100_000_000_000,
        },
    }
    val = process_value(attributes, definition)

    assert val == 40_000_000_000

def test_attach_key():
    attributes = {
        'name': 'leaf1',
    }
    definition = {
        'key': 'aci_node_name',
        'property_name': 'name',
    }
    val = process_value(attributes, definition)

    assert val['aci_node_name'] == 'leaf1'
    assert len(val) == 1

def test_multi():
    attributes = {
        'operSpeed': '40G',
    }
    definition = {
        'key': 'aci_interface_oper_speed',
        'property_name': 'operSpeed',
        'cases': {
            'unknown':            0,
            '100M':     100_000_000,
            '1G':     1_000_000_000,
            '10G':   10_000_000_000,
            '25G':   25_000_000_000,
            '40G':   40_000_000_000,
            '100G': 100_000_000_000,
        },
    }
    val = process_value(attributes, definition)

    assert val['aci_interface_oper_speed'] == 40_000_000_000
    assert len(val) == 1
