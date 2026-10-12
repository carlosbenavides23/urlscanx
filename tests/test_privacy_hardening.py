"""Privacy regressions: semantic secrets never get display fingerprints."""

import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from urlscanx.analysis import analyze, analysis_envelope
from urlscanx.analysis.adapters import safe_url
from urlscanx.analysis.render import format_analysis
from urlscanx.cli import main
from urlscanx.display import display_text, display_url
from urlscanx.report import format_iocs, format_report, format_requests, iocs
from test_analysis import request, SCAN


SEMANTIC_NAMES = (
    "password", "passwd", "otp", "passcode", "pin", "code",
    "verificationcode", "authenticationcode", "cvc", "cvv", "pan",
    "cardnumber", "securitycode",
)
CASES = (
    ("https://e.test/?password=hunter2", "hunter2"),
    ("https://e.test/?otp=123456", "123456"),
    ("https://e.test/?code=123456", "123456"),
    ("https://e.test/?cvv=123", "123"),
    ("https://e.test/?pan=4111111111111111", "4111111111111111"),
    ("https://e.test/otp/123456", "123456"),
    ("https://e.test/passcode/123456", "123456"),
    ("https://e.test/verification-code/123456", "123456"),
    ("https://e.test/cvv/123", "123"),
    ("https://alice:hunter2@e.test/", "hunter2"),
)


class PrivacyHardeningTests(unittest.TestCase):
    def test_required_examples_omit_without_even_hashing(self):
        with patch("urlscanx.display.hashlib.sha256", side_effect=AssertionError("secret hashed")):
            for url, secret in CASES:
                with self.subTest(url=url):
                    for rendered in (display_url(url), safe_url(url), display_text(url, limit=None)):
                        self.assertNotIn(secret, rendered)
                        self.assertIn("[omitted]", rendered)
                        self.assertNotIn("sha256", rendered)

    def test_all_semantic_names_in_query_and_path_use_existing_normalization(self):
        with patch("urlscanx.display.hashlib.sha256", side_effect=AssertionError("secret hashed")):
            for name in SEMANTIC_NAMES:
                for spelling in (name, name.upper(), "-".join(name), "_".join(name), f"%{ord(name[0]):02X}" + name[1:]):
                    for url in (f"https://e.test/?{spelling}=hunter2", f"https://e.test/{spelling}/hunter2"):
                        with self.subTest(url=url):
                            self.assertIn("[omitted]", display_url(url))
                            self.assertNotIn("hunter2", display_url(url))
                            self.assertNotIn("hunter2", safe_url(url))

    def test_semantics_override_high_entropy_shape(self):
        with patch("urlscanx.display.hashlib.sha256", side_effect=AssertionError("secret hashed")):
            for name in SEMANTIC_NAMES:
                for value in ("ghp_exampleSecretToken", "sk-exampleSecretToken", "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.c2ln", "Q" * 100):
                    for url in (f"https://e.test/?{name}={value}", f"https://e.test/{name}/{value}"):
                        self.assertNotIn(value, display_url(url))
                        self.assertIn("[omitted]", display_url(url))

    def test_userinfo_omitted_including_encoded_password_and_token_shape(self):
        with patch("urlscanx.display.hashlib.sha256", side_effect=AssertionError("userinfo hashed")):
            for credentials in ("alice:hunter2", "alice:hunter%32", "alice:ghp_exampleSecretToken", "ghp_exampleSecretToken", ":123456", "alice:p%40ssword"):
                url = f"https://{credentials}@e.test/path?item=42"
                self.assertEqual(display_url(url), "https://[omitted]@e.test/path?item=42")
                self.assertEqual(safe_url(url), "https://[omitted]@e.test/path?item=[omitted]")

    def test_nested_secret_assignment_is_not_fingerprinted(self):
        with patch("urlscanx.display.hashlib.sha256", side_effect=AssertionError("nested secret hashed")):
            for name in SEMANTIC_NAMES:
                url = f"https://e.test/?next=https%3A%2F%2Fother.test%2F%3F{name}%3Dhunter2"
                self.assertEqual(display_url(url), "https://e.test/?next=[omitted]")

    def test_path_context_survives_masking_previous_segment(self):
        for url in ("https://e.test/token/password/hunter2", "https://e.test/password/otp/123456"):
            self.assertNotIn(url.rsplit("/", 1)[-1], display_url(url))
            self.assertTrue(display_url(url).endswith("/[omitted]"))
            self.assertTrue(safe_url(url).endswith("/[omitted]"))

    def test_fragment_and_empty_secret_parameters(self):
        with patch("urlscanx.display.hashlib.sha256", side_effect=AssertionError("secret hashed")):
            self.assertEqual(display_url("https://e.test/#verification_code=123456"), "https://e.test/#verification_code=[omitted]")
            self.assertEqual(display_url("https://e.test/?password=&item=42"), "https://e.test/?password=[omitted]&item=42")

    def test_existing_token_fingerprints_and_nonsecret_values_retained(self):
        for token in ("ghp_exampleSecretToken", "sk-exampleSecretToken", "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.c2ln", "Q" * 100):
            fingerprint = hashlib.sha256(token.encode()).hexdigest()[:12]
            for url in (f"https://e.test/?access_token={token}", f"https://e.test/{token}", f"https://e.test/?{token}"):
                self.assertIn(f"[REDACTED sha256:{fingerprint}]", display_url(url))
                self.assertNotIn("sha256", safe_url(url))
        self.assertEqual(display_url("https://e.test/products/123?item=42"), "https://e.test/products/123?item=42")

    def test_human_views_and_derived_analysis_keep_raw_result_unchanged(self):
        for url, secret in CASES:
            with self.subTest(url=url):
                result = {"task": {"url": url}, "page": {"url": url},
                          "lists": {"urls": [url]}, "data": {"requests": [request(url), request(url)],
                          "console": [{"message": {"level": "error", "text": url}}]}}
                before = copy.deepcopy(result)
                dom = f'<form action="{url}"><input type="password"></form>'.encode()
                output = analyze(result, SCAN, dom)
                envelope = analysis_envelope(result, SCAN, dom, output)
                digest = hashlib.sha256(secret.encode()).hexdigest()[:12]
                views = [format_iocs(result), format_requests(result), json.dumps(envelope["analysis"])]
                for verbose in (False, True):
                    views.extend([format_report(result, SCAN, dom, verbose=verbose), format_analysis(envelope, verbose=verbose)])
                for view in views:
                    # Short decimal secrets can occur incidentally inside provenance IDs.
                    self.assertNotRegex(view, rf"(?<![A-Za-z0-9]){re.escape(secret)}(?![A-Za-z0-9])")
                    self.assertNotIn(f"sha256:{digest}", view)
                self.assertEqual(result, before)
                self.assertEqual(envelope["result"], before)
                self.assertIn(url, iocs(result)["urls"])

    def test_cli_verbose_omits_and_raw_json_retains(self):
        url = "https://alice:hunter2@e.test/otp/123456?cvv=123&pan=4111111111111111"
        result = {"task": {"url": url}, "data": {"requests": [request(url)]}}
        for options in (["--verbose"], ["--analyze", "--verbose"], ["--json"], ["--analyze", "--json"]):
            out = io.StringIO()
            with patch("urlscanx.cli.api_key", return_value="offline"), patch("urlscanx.cli.fetch_result", return_value=result), \
                 patch("urlscanx.cli.fetch_asset", return_value=None), contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main([SCAN, *options]), 0)
            if "--json" in options:
                raw = json.loads(out.getvalue())
                self.assertEqual(raw["result"] if "--analyze" in options else raw, result)
            else:
                for secret in ("hunter2", "123456", "4111111111111111"):
                    self.assertNotIn(secret, out.getvalue())
                self.assertNotIn("cvv=123", out.getvalue())

    def test_saved_raw_artifacts_preserved(self):
        url = "https://e.test/password/hunter2?code=123456"
        result = {"task": {"url": url}, "data": {"requests": [request(url)]}}
        dom = f'<form action="{url}"></form>'.encode()
        png = b"\x89PNG\r\n\x1a\noriginal-screenshot"
        with tempfile.TemporaryDirectory() as directory:
            previous = os.getcwd()
            try:
                os.chdir(directory)
                with patch("urlscanx.cli.api_key", return_value="offline"), patch("urlscanx.cli.fetch_result", return_value=result), \
                     patch("urlscanx.cli.fetch_asset", side_effect=[dom, png]), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(main([SCAN, "--analyze", "--save"]), 0)
            finally:
                os.chdir(previous)
            target = Path(directory) / "urlscanx-output" / SCAN
            self.assertEqual(json.loads((target / "result.json").read_text(encoding="utf-8")), result)
            self.assertEqual((target / "dom.html").read_bytes(), dom)
            self.assertEqual((target / "screenshot.png").read_bytes(), png)
            for name in ("report.txt", "analysis.txt", "analysis.json"):
                text = (target / name).read_text(encoding="utf-8")
                self.assertNotIn("hunter2", text)
                self.assertNotIn("123456", text)
