import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from urlscanx.api import ScanError
from urlscanx.cli import main


SCAN1 = "01a0e84d-e186-775a-b6b8-ec96c96fccf0"
SCAN2 = "01a0e84d-e186-775a-b6b8-ec96c96fccf1"
RESULT = {"task": {"url": "https://example.com/"}, "page": {"title": "Example"}}


class CliTests(unittest.TestCase):
    def test_views_and_compare_do_not_write(self):
        with tempfile.TemporaryDirectory() as root:
            old = os.getcwd()
            os.chdir(root)
            try:
                with patch("urlscanx.cli.api_key", return_value="key"), patch("urlscanx.cli.fetch_result", return_value=RESULT), patch("urlscanx.cli.fetch_asset", return_value=None):
                    for options, expected in (([], "urlscanx report"), (["--json"], '"task"'),
                                              (["--iocs"], "Domains (1):"), (["--requests"], "HTTP requests (0):")):
                        output = io.StringIO()
                        with contextlib.redirect_stdout(output):
                            self.assertEqual(main([SCAN1, *options]), 0)
                        self.assertIn(expected, output.getvalue())
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        self.assertEqual(main(["compare", SCAN1, SCAN2]), 0)
                    self.assertIn("Request counts: 0 vs 0", output.getvalue())
                self.assertFalse(Path("urlscanx-output").exists())
            finally:
                os.chdir(old)

    def test_raw_json_keeps_secret_while_report_redacts(self):
        source = {"task": {"url": "https://example.test/?token=secret"}}
        with patch("urlscanx.cli.api_key", return_value="key"), patch("urlscanx.cli.fetch_result", return_value=source), patch("urlscanx.cli.fetch_asset", return_value=None):
            raw, report = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(raw):
                self.assertEqual(main([SCAN1, "--json"]), 0)
            with contextlib.redirect_stdout(report):
                self.assertEqual(main([SCAN1]), 0)
        self.assertIn("token=secret", raw.getvalue())
        self.assertNotIn("token=secret", report.getvalue())

    def test_verbose_console_and_compare_without_dom(self):
        source = {"task": {}, "data": {"console": [{"message": {"level": "log", "text": "debug output"}}]}}
        with patch("urlscanx.cli.api_key", return_value="key"), patch("urlscanx.cli.fetch_result", return_value=source), patch("urlscanx.cli.fetch_asset", side_effect=ScanError("DOM blocked")):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["compare", SCAN1, SCAN2, "--verbose"]), 0)
            self.assertIn("urlscanx comparison", output.getvalue())
        with patch("urlscanx.cli.api_key", return_value="key"), patch("urlscanx.cli.fetch_result", return_value=source), patch("urlscanx.cli.fetch_asset", return_value=None):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main([SCAN1, "--verbose"]), 0)
            self.assertIn("debug output", output.getvalue())
