import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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
                with patch("urlscanx.cli.api_key", return_value="key"), patch("urlscanx.cli.fetch_result", return_value=RESULT):
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
