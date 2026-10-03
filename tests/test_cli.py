import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from urlscanx.api import ScanError
from urlscanx.cli import main
from urlscanx.compare import format_comparison


SCAN1 = "01a0e84d-e186-775a-b6b8-ec96c96fccf0"
SCAN2 = "01a0e84d-e186-775a-b6b8-ec96c96fccf1"
SCAN3 = "01a0e84d-e186-775a-b6b8-ec96c96fccf2"
RESULT = {"task": {"url": "https://example.com/"}, "page": {"title": "Example"}}


class CliTests(unittest.TestCase):
    def test_binary_cli_output_is_unchanged(self):
        with patch("urlscanx.cli.api_key", return_value="key"), patch("urlscanx.cli.fetch_result", return_value=RESULT), patch("urlscanx.cli.fetch_asset", return_value=None):
            for options in ([], ["--verbose"], ["--min-shared", "2"]):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(main(["compare", SCAN1, SCAN2, *options]), 0)
                self.assertEqual(output.getvalue(), format_comparison(RESULT, RESULT, SCAN1, SCAN2, verbose="--verbose" in options) + "\n")

    def test_multi_cli_parsing_missing_dom_and_minimum(self):
        sources = [{"lists": {"hashes": ["all", "subset"]}}, {"lists": {"hashes": ["all", "subset"]}}, {"lists": {"hashes": ["all"]}}]
        with patch("urlscanx.cli.api_key", return_value="key"), patch("urlscanx.cli.fetch_result", side_effect=sources) as fetch, patch("urlscanx.cli.fetch_asset", side_effect=[None, ScanError("blocked"), b""]):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["compare", SCAN1, f"https://urlscan.io/result/{SCAN2}/", SCAN3, "--min-shared", "3", "--verbose"]), 0)
            self.assertEqual([call.args[0] for call in fetch.call_args_list], [SCAN1, SCAN2, SCAN3])
            self.assertIn("urlscanx comparison: 3 scans", output.getvalue())
            self.assertIn("Form actions unavailable for scans 1, 2", output.getvalue())
            self.assertNotIn("subset", output.getvalue())

    def test_compare_invalid_arguments_fail_before_fetch(self):
        cases = [[SCAN1], [SCAN1, SCAN2, SCAN3, "--min-shared", "1"],
                 [SCAN1, SCAN2, SCAN3, "--min-shared", "4"],
                 [SCAN1, SCAN2, SCAN3, "--min-shared", "abc"],
                 [SCAN1, SCAN2, f"https://urlscan.io/result/{SCAN1}/"]]
        with patch("urlscanx.cli.fetch_result") as fetch:
            for args in cases:
                with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    main(["compare", *args])
                self.assertEqual(error.exception.code, 2)
            fetch.assert_not_called()

    def test_multi_result_failure_identifies_scan(self):
        with patch("urlscanx.cli.api_key", return_value="key"), patch("urlscanx.cli.fetch_result", side_effect=[RESULT, ScanError("not ready", 3)]), patch("urlscanx.cli.fetch_asset") as assets:
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                self.assertEqual(main(["compare", SCAN1, SCAN2, SCAN3]), 3)
            self.assertIn(SCAN2, output.getvalue())
            self.assertIn("not ready", output.getvalue())
            assets.assert_not_called()

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
