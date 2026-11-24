
import socket
import threading
import unittest

from port_scanner import validate_target, scan_ports


class PortScannerTests(unittest.TestCase):

    def test_valid_ip(self):
        self.assertTrue(validate_target("127.0.0.1"))

    def test_invalid_ip(self):
        self.assertFalse(validate_target("999.999.999.999"))

    def test_open_local_port(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)

        port = server.getsockname()[1]

        try:
            results = scan_ports("127.0.0.1", [port])
            self.assertIn(port, results)
        finally:
            server.close()


if __name__ == "__main__":
    unittest.main()
