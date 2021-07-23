import unittest
from net import address

class TestSplitHostPort(unittest.TestCase):

    def test_host_port_split(self):
        test_table = [
            { 'arg': 'python.org:http', 'expected': ('python.org', 'http') },
            { 'arg': 'us.pool.ntp.org:ntp', 'expected': ('us.pool.ntp.org', 'ntp') },
            { 'arg': '192.168.116.2:5555', 'expected': ('192.168.116.2', '5555') },
            { 'arg': '[2001:db8::1]:53', 'expected': ('[2001::db8::1]:53') },
            { 'arg': ':80', 'expected': ('', '80') },
            { 'arg': '[::]:1234', 'expected': ('::', '1234') },
            { 'arg': '[ffff::/128]:1199', 'expected': ('ffff::/128', '1199') },
            { 'arg': '[2001:fed:bed::1%eth0]:65536', 'expected': ('2001:fed:bed::1%eth0', '65536') }
        ]

        for _, tc in enumerate(test_table):
            self.assertEqual(address.split_host_port(tc['arg']), tc['expected'])

    def host_port_split_errors(self):
        pass
