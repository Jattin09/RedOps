
import json
import tempfile
import unittest

from pathlib import Path
from report_generator import generate_report


class ReportGeneratorTests(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.temp_dir.name)

        self.sample_data = {
            "target": "192.168.1.7",
            "scan_time": "2026-11-24T10:00:00Z",
            "open_ports": [8888],
            "services": [
                {
                    "port": 8888,
                    "service": "HTTP",
                    "banner": "Python HTTP Server"
                }
            ],
            "web_results": [
                {
                    "url": "http://192.168.1.7:8888",
                    "status_code": 200,
                    "server": "Python HTTP Server",
                    "security_headers": {
                        "X-Frame-Options": None,
                        "X-Content-Type-Options": "nosniff"
                    }
                }
            ]
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_json_report_generation(self):
        path = generate_report(
            self.sample_data,
            "json",
            self.output_dir
        )

        self.assertTrue(path.exists())

        with path.open(encoding="utf-8") as file:
            data = json.load(file)

        self.assertEqual(data["target"], "192.168.1.7")

    def test_html_report_generation(self):
        path = generate_report(
            self.sample_data,
            "html",
            self.output_dir
        )

        self.assertTrue(path.exists())

        content = path.read_text(encoding="utf-8")

        self.assertIn("RedOps Security Assessment Report", content)
        self.assertIn("192.168.1.7", content)
        self.assertIn("Python HTTP Server", content)

    def test_invalid_report_format(self):
        with self.assertRaises(ValueError):
            generate_report(
                self.sample_data,
                "pdf",
                self.output_dir
            )


if __name__ == "__main__":
    unittest.main()
