
import unittest
from service_detector import identify_service


class ServiceDetectorTests(unittest.TestCase):

    def test_ssh_detection(self):
        self.assertEqual(identify_service(22), "SSH")

    def test_http_detection(self):
        self.assertEqual(identify_service(80), "HTTP")

    def test_https_detection(self):
        self.assertEqual(identify_service(443), "HTTPS")

    def test_unknown_port(self):
        self.assertEqual(identify_service(9999), "Unknown")


if __name__ == "__main__":
    unittest.main()
