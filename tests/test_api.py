import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from urlscanx.api import ScanError, fetch_result
from urlscanx.cli import save_scan


SCAN = "01a0e84d-e186-775a-b6b8-ec96c96fccf0"


class ApiTests(unittest.TestCase):
    def test_malformed_api_response(self):
        with patch("urlscanx.api.urlopen") as urlopen:
            urlopen.return_value.__enter__.return_value.headers.get.return_value = ""
            urlopen.return_value.__enter__.return_value.read.return_value = b"[]"
            with self.assertRaisesRegex(ScanError, "unexpected result format"):
                fetch_result(SCAN, "key")
            urlopen.return_value.__enter__.return_value.read.return_value = b"not json"
            with self.assertRaisesRegex(ScanError, "invalid JSON"):
                fetch_result(SCAN, "key")

    def test_http_and_connection_errors(self):
        with patch("urlscanx.api.urlopen", side_effect=HTTPError("url", 401, "Unauthorized", {}, io.BytesIO())):
            with self.assertRaisesRegex(ScanError, "HTTP 401"):
                fetch_result(SCAN, "key")
        with patch("urlscanx.api.urlopen", side_effect=URLError("offline")):
            with self.assertRaisesRegex(ScanError, "Could not connect"):
                fetch_result(SCAN, "key")

    def test_save_preserves_raw_result_and_optional_assets(self):
        with tempfile.TemporaryDirectory() as root:
            old = os.getcwd()
            os.chdir(root)
            try:
                source = {"task": {"url": "https://example.test/?token=secret"}}
                output, warnings = save_scan(SCAN, source, "redacted report", b"<html></html>", b"\x89PNG\r\n\x1a\nDATA")
                self.assertEqual(warnings, [])
                self.assertEqual({path.name for path in output.iterdir()},
                                 {"result.json", "report.txt", "dom.html", "screenshot.png"})
                self.assertEqual(json.loads((output / "result.json").read_text()), source)
                self.assertEqual((output / "report.txt").read_text().strip(), "redacted report")
            finally:
                os.chdir(old)
