
import unittest
from unittest.mock import patch, Mock

from web_recon import validate_url, inspect_web_service


class WebReconTests(unittest.TestCase):

    def test_valid_http_url(self):
        parsed = validate_url("http://127.0.0.1:8888")
        self.assertEqual(parsed.scheme, "http")

    def test_valid_https_url(self):
        parsed = validate_url("https://example.com")
        self.assertEqual(parsed.scheme, "https")

    def test_invalid_scheme(self):
        with self.assertRaises(ValueError):
            validate_url("ftp://example.com")

    def test_missing_hostname(self):
        with self.assertRaises(ValueError):
            validate_url("http://")

    @patch("web_recon.requests.get")
    def test_http_response_inspection(self, mock_get):
        response = Mock()
        response.status_code = 200
        response.headers = {
            "Server": "Python HTTP Server",
            "X-Content-Type-Options": "nosniff",
        }

        mock_get.return_value = response

        result = inspect_web_service("http://127.0.0.1:8888")

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["server"], "Python HTTP Server")
        self.assertIn(
            "X-Frame-Options",
            result["missing_security_headers"]
        )


if __name__ == "__main__":
    unittest.main()
