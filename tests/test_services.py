import unittest
from unittest.mock import Mock
from firewall_auditor.services import parse_listeners
from firewall_auditor.tools import Inspector
from firewall_auditor.transport import InspectionError, Operation


class ListenerTests(unittest.TestCase):
    def test_ipv4_ipv6_udp_and_optional_process_metadata(self):
        text = ('Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n'
                'udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n'
                'tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n'
                'tcp LISTEN 0 128 [::]:3306 [::]:* users:(("db",pid=42,fd=3))\n')
        rows = parse_listeners(text)
        self.assertEqual(rows[0]['local'], {'address': '127.0.0.53%lo', 'port': 53})
        self.assertIsNone(rows[0]['peer']['port'])
        self.assertIsNone(rows[1]['process_metadata'])
        self.assertEqual(rows[2]['local'], {'address': '::', 'port': 3306})
        self.assertIn('pid=42', rows[2]['process_metadata'])

    def test_empty_listener_output(self):
        self.assertEqual(parse_listeners('Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\n'), [])

    def test_malformed_rows_fail(self):
        for text in ('unexpected text', 'tcp LISTEN 0 0 missing 0.0.0.0:*',
                     'tcp LISTEN 0 0 0.0.0.0:99999 0.0.0.0:*'):
            with self.subTest(text=text), self.assertRaises(InspectionError):
                parse_listeners(text)

    def test_tool_preserves_raw_and_parsed_listeners(self):
        transport = Mock()
        transport.read.return_value = 'tcp LISTEN 0 128 *:22 *:*\n'
        result = Inspector({'vm': object()}, transport).call(Operation.SERVICES.value, 'vm')
        self.assertEqual(result['data']['text'], transport.read.return_value)
        self.assertEqual(result['data']['listeners'][0]['local']['port'], 22)
        self.assertTrue(result['data']['process_metadata_may_be_incomplete'])
