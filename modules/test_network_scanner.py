
import unittest
from unittest.mock import patch

from network_scanner import (
    validate_network,
    enumerate_hosts,
    discover_hosts
)


class NetworkScannerTests(unittest.TestCase):

    def test_valid_network(self):
        network = validate_network("192.168.1.0/24")
        self.assertEqual(network.num_addresses, 256)

    def test_host_enumeration(self):
        hosts = enumerate_hosts("192.168.1.0/29")

        self.assertEqual(len(hosts), 6)
        self.assertEqual(hosts[0], "192.168.1.1")

    def test_invalid_network(self):
        with self.assertRaises(ValueError):
            validate_network("invalid-network")

    def test_large_network_rejected(self):
        with self.assertRaises(ValueError):
            validate_network("10.0.0.0/8")

    def test_ipv6_rejected(self):
        with self.assertRaises(ValueError):
            validate_network("2001:db8::/64")

    @patch("network_scanner.is_host_alive")
    def test_discover_hosts(self, mock_alive):
        mock_alive.side_effect = lambda host: host.endswith(".1")

        hosts = discover_hosts("192.168.1.0/30")

        self.assertEqual(hosts, ["192.168.1.1"])

    def test_invalid_worker_count(self):
        with self.assertRaises(ValueError):
            discover_hosts("192.168.1.0/30", max_workers=0)


if __name__ == "__main__":
    unittest.main()
