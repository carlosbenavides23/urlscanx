"""Final Slice 2 corrections: structural guards, ambiguous brands and encoding."""

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import quote, unquote_plus

from urlscanx.analysis import analyze, analysis_envelope
from urlscanx.analysis.adapters import safe_url
from urlscanx.analysis.presentation import candidates
from urlscanx.analysis.semantics import classify
from urlscanx.cli import main
from urlscanx.display import _decode_component, display_text, display_url
from test_analysis import fixture, request, SCAN
from test_privacy_hardening import SEMANTIC_NAMES


URL_CASES = (
    ("https://e.test/#route?otp=123456", "https://e.test/#route?otp=[omitted]"),
    ("https://e.test/#route?password=hunter2", "https://e.test/#route?password=[omitted]"),
    ("https://e.test/otp%3D123456", "https://e.test/otp=[omitted]"),
    ("https://e.test/otp%253D123456", "https://e.test/otp=[omitted]"),
    ("https://e.test/cvv%253D123", "https://e.test/cvv=[omitted]"),
    ("https://e.test/pan%253D4111111111111111", "https://e.test/pan=[omitted]"),
)
NEGATIVE_COPY = (
    "a blue stripe across the page", "discord among the committee",
    "use the intercom at the gate", "apply for a visa", "BAC level 0.08",
)


class StructuralCompatibilityTests(unittest.TestCase):
    def assert_role(self, tag, attrs, expected):
        role, support = classify(tag, attrs, [])
        self.assertEqual(role, expected)
        if expected == "unknown":
            self.assertEqual(support, [])
        return role

    def test_checkbox_email(self):
        self.assert_role("input", {"type": "checkbox", "name": "email"}, "unknown")

    def test_checkbox_password(self):
        self.assert_role("input", {"type": "checkbox", "name": "password"}, "unknown")

    def test_checkbox_card_number(self):
        self.assert_role("input", {"type": "checkbox", "name": "cardNumber"}, "unknown")

    def test_radio_otp(self):
        self.assert_role("input", {"type": "radio", "name": "otp"}, "unknown")

    def test_select_password(self):
        self.assert_role("select", {"name": "password"}, "unknown")

    def test_select_otp(self):
        self.assert_role("select", {"name": "otp"}, "unknown")

    def test_submit_password(self):
        self.assert_role("input", {"type": "submit", "name": "password"}, "unknown")
        output = analyze({"task": {}}, SCAN, b'<form><input type="submit" name="password"></form>')
        self.assertEqual(output.dom_inventory["controls"], [])
        self.assertEqual(len(output.dom_inventory["forms"][0]["submit_controls"]), 1)

    def test_hidden_password(self):
        self.assert_role("input", {"type": "hidden", "name": "password"}, "password")

    def test_hidden_payment(self):
        for attrs, expected in (({"type": "hidden", "name": "cardNumber"}, "payment_pan"),
                                ({"type": "hidden", "autocomplete": "cc-csc"}, "payment_cvc")):
            self.assert_role("input", attrs, expected)

    def test_normal_text_email_password_fields(self):
        for attrs, expected in (({"type": "text", "name": "email"}, "email"), ({"type": "email"}, "email"),
                                ({"type": "password"}, "password"), ({"autocomplete": "username"}, "username"),
                                ({"autocomplete": "cc-number"}, "payment_pan"), ({"name": "otp"}, "otp_candidate")):
            self.assert_role("input", attrs, expected)

    def test_actions_toggles_uploads_sliders_colors_block_even_strong_autocomplete(self):
        for kind in ("checkbox", "radio", "submit", "button", "reset", "image", "file", "range", "color"):
            for token in ("username", "email", "current-password", "one-time-code", "cc-number", "cc-exp", "cc-csc"):
                with self.subTest(kind=kind, autocomplete=token):
                    self.assert_role("input", {"type": kind, "autocomplete": token, "name": "password"}, "unknown")
        for token in ("username", "email", "current-password", "one-time-code", "cc-number", "cc-csc"):
            self.assert_role("select", {"autocomplete": token}, "unknown")

    def test_local_label_and_id_hints_cannot_bypass_structural_guard(self):
        output = analyze({"task": {}}, SCAN, b'<label for="x">Password</label><input type="checkbox" id="x" placeholder="otp"><input type="radio" id="cardNumber"><select name="email"></select>')
        self.assertEqual([c["semantic_role"] for c in output.dom_inventory["controls"]], ["unknown"] * 3)
        self.assertEqual([c["control_kind"] for c in output.dom_inventory["controls"]], ["checkbox", "radio", "select"])
        self.assertEqual(output.findings, [])

    def test_compatible_selects_and_textarea_keep_value_semantics(self):
        self.assert_role("select", {"autocomplete": "cc-exp-month"}, "payment_expiry")
        self.assert_role("select", {"name": "country"}, "contact_data")
        self.assert_role("textarea", {"name": "company"}, "company")


class AmbiguousBrandTests(unittest.TestCase):
    def test_exact_negative_phrases_in_visible_text(self):
        for text in NEGATIVE_COPY:
            with self.subTest(text=text):
                output = analyze({"task": {}}, SCAN, f"<p>{text}</p>".encode())
                self.assertEqual(output.brand_candidates, [])
                self.assertEqual(candidates(text), [])

    def test_negative_phrases_in_titles_or_image_alt_are_not_exact_brand_labels(self):
        for text in NEGATIVE_COPY:
            with self.subTest(text=text):
                output = analyze({"task": {}, "page": {"title": text}}, SCAN, f'<title>{text}</title><img class="logo" alt="{text}" src="/logo.svg">'.encode())
                self.assertEqual(output.brand_candidates, [])

    def test_exact_brand_titles_positive(self):
        for name in ("Stripe", "Discord", "Intercom", "Visa", "BAC Credomatic", "MasterCard", "Link", "JCB"):
            with self.subTest(name=name):
                output = analyze({"task": {}, "page": {"title": name}}, SCAN, f"<title>{name}</title>".encode())
                self.assertEqual([b["name"] for b in output.brand_candidates], [name])
                self.assertTrue(all(b["assessment"] == "presentation_only" for b in output.brand_candidates))

    def test_exact_image_logo_labels_and_explicit_metadata_positive(self):
        for name in ("Stripe", "Discord", "Intercom", "Visa", "BAC Credomatic", "MasterCard", "Link"):
            with self.subTest(name=name):
                for markup in (f'<img class="logo" alt="{name}" title="unrelated description" src="/logo.svg">',
                               f'<img class="logo" title="{name}" src="/logo.svg">', f'<svg><title>{name}</title></svg>'):
                    output = analyze({"task": {}}, SCAN, markup.encode())
                    self.assertEqual([b["name"] for b in output.brand_candidates], [name])
                output = analyze({"task": {}, "brands": [{"name": name}]}, SCAN)
                self.assertEqual([b["name"] for b in output.brand_candidates], [name])

    def test_high_specificity_visible_aliases_remain_and_bac_short_removed(self):
        for name in ("PayPal", "OneDrive", "Microsoft", "BAC Credomatic", "ShareGate", "Akamai"):
            self.assertEqual(candidates("Welcome to " + name), [name])
        for text in ("BAC", "BAC level 0.08", "Stripe", "Discord", "Intercom", "Visa", "Mastercard", "Link", "JCB"):
            self.assertEqual(candidates(text), [])
        self.assertEqual(candidates("BAC", title_or_logo=True), [])

    def test_ambiguous_word_in_source_url_cannot_create_brand_or_ownership(self):
        output = analyze({"task": {}, "page": {"url": "https://tenant.pages.dev/"}}, SCAN,
                         b'<img class="logo" alt="ordinary icon" src="https://stripe.example.test/logo.svg">')
        self.assertEqual(output.brand_candidates, [])
        self.assertTrue(all(h["provider_relationship"] == "unresolved" for h in output.trust_hints))


class EncodedPrivacyTests(unittest.TestCase):
    def test_exact_adversarial_outputs_and_safe_url_no_sha_invocation(self):
        with patch("urlscanx.display.hashlib.sha256", side_effect=AssertionError("low-entropy secret hashed")):
            for url, expected in URL_CASES:
                with self.subTest(url=url):
                    self.assertEqual(display_url(url), expected)
                    self.assertEqual(display_text(url, limit=None), expected)
                    self.assertEqual(safe_url(url), expected.split("#", 1)[0])

    def test_all_secret_names_encoded_assignments_and_normalization(self):
        names = (*SEMANTIC_NAMES, "verification-code", "authentication_code", "card-number", "security_code", "PASSWORD")
        with patch("urlscanx.display.hashlib.sha256", side_effect=AssertionError("secret hashed")):
            for name in names:
                for passes in (0, 1, 2):
                    component = name + "=hunter2"
                    for _ in range(passes):
                        component = quote(component, safe="")
                    url = "https://e.test/" + component
                    with self.subTest(name=name, passes=passes):
                        self.assertEqual(display_url(url), f"https://e.test/{name}=[omitted]")
                        self.assertEqual(safe_url(url), f"https://e.test/{name}=[omitted]")
                        self.assertEqual(display_url("https://e.test/#route?" + component), f"https://e.test/#route?{name}=[omitted]")

    def test_benign_percent_encoded_components_keep_original_representation(self):
        for component in ("some%20file", "item%3D42", "item%253D42", "normal%2520name", "percent%25value"):
            url = "https://e.test/" + component
            self.assertEqual(display_url(url), url)
            self.assertEqual(safe_url(url), url)

    def test_decoder_two_pass_limit_and_triple_encoding_unchanged(self):
        with patch("urlscanx.display.unquote_plus", wraps=unquote_plus) as decode:
            self.assertEqual(_decode_component("otp%25253D123456"), "otp%3D123456")
            self.assertEqual(decode.call_count, 2)
        for url in ("https://e.test/otp%25253D123456", "https://e.test/ot%252570=123456", "https://e.test/#route?otp%25253D123456"):
            with patch("urlscanx.display.hashlib.sha256", side_effect=AssertionError("secret hashed")):
                self.assertEqual(display_url(url), url)
                self.assertEqual(safe_url(url), url.split("#", 1)[0])

    def test_fragment_query_preserves_route_normal_values_and_masks_high_tokens(self):
        shown = display_url("https://e.test/#route?otp=123456&item=42")
        self.assertEqual(shown, "https://e.test/#route?otp=[omitted]&item=42")
        self.assertIn("access_token=[REDACTED sha256:", display_url("https://e.test/#route?access_token=ghp_exampleToken"))
        self.assertEqual(display_url("https://e.test/#route?item=42"), "https://e.test/#route?item=42")

    def test_verbose_cli_and_json_raw_preservation(self):
        for url, expected in URL_CASES:
            result = {"task": {"url": url}, "page": {"url": url}, "data": {"requests": [request(url)]}}
            before = copy.deepcopy(result)
            for options in (["--verbose"], ["--analyze", "--verbose"], ["--json"], ["--analyze", "--json"]):
                out = io.StringIO()
                with patch("urlscanx.cli.api_key", return_value="offline"), patch("urlscanx.cli.fetch_result", return_value=result), \
                     patch("urlscanx.cli.fetch_asset", return_value=None), contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(main([SCAN, *options]), 0)
                if "--json" in options:
                    value = json.loads(out.getvalue())
                    self.assertEqual(value["result"] if "--analyze" in options else value, before)
                else:
                    self.assertNotIn(url, out.getvalue())
                    for fragment in ("otp=123456", "password=hunter2", "otp%3D123456", "otp%253D123456", "cvv%253D123", "pan%253D4111111111111111"):
                        self.assertNotIn(fragment, out.getvalue())
            self.assertEqual(result, before)

    def test_saved_result_dom_png_exact_new_secrets_derived_omitted(self):
        url = "https://e.test/otp%253D123456#route?password=hunter2"
        result = {"task": {"url": url}, "data": {"requests": [request(url)]}}
        before = copy.deepcopy(result)
        dom = f'<form action="{url}"><input type="hidden" name="password" value="raw-value"></form>'.encode()
        png = b"\x89PNG\r\n\x1a\noriginal"
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
            self.assertEqual(json.loads((target / "result.json").read_text(encoding="utf-8")), before)
            self.assertEqual((target / "dom.html").read_bytes(), dom)
            self.assertEqual((target / "screenshot.png").read_bytes(), png)
            for filename in ("report.txt", "analysis.txt", "analysis.json"):
                text = (target / filename).read_text(encoding="utf-8")
                self.assertNotIn("123456", text)
                self.assertNotIn("hunter2", text)
                self.assertNotIn("raw-value", text)
        self.assertEqual(result, before)


class HardeningFixtureTests(unittest.TestCase):
    def test_f001_f005_f006_f010_keep_roles_and_markup_only(self):
        expected = {1: {"username", "password"}, 5: {"username", "password"},
                    6: {"payment_pan", "payment_expiry", "payment_cvc"}, 10: {"email", "phone", "person_name", "company"}}
        for number, required in expected.items():
            result, scan, dom = fixture(number)
            before = copy.deepcopy(result)
            output = analyze(result, scan, dom)
            self.assertTrue(required <= {c["semantic_role"] for c in output.dom_inventory["controls"]})
            if number in (1, 5):
                self.assertEqual(output.dom_inventory["forms"][0]["markup_method"], "GET" if number == 1 else "POST")
            self.assertTrue(all(f["runtime_submission"] == "not_established" for f in output.dom_inventory["forms"]))
            self.assertEqual(output.findings, [])
            self.assertEqual(result, before)
            self.assertEqual(analysis_envelope(result, scan, dom, output)["result"], before)

    def test_f008_f009_f010_f011_network_and_no_invented_controls(self):
        for number in (8, 9, 10, 11):
            result, scan, dom = fixture(number)
            output = analyze(result, scan, dom)
            if number == 8:
                self.assertEqual(output.heartbeat_requests[0]["request_count"], 1)
                self.assertEqual(output.heartbeat_requests[0]["cadence"], "unresolved")
            elif number == 9:
                pattern = next(p for p in output.network_patterns if p.kind == "socket_io_http_polling")
                self.assertEqual(pattern.request_count, 7)
                self.assertEqual(pattern.method_counts, {"GET": 4, "POST": 3})
                self.assertEqual([p["request_count"] for p in pattern.session_partitions], [1, 6])
                self.assertEqual(output.evidence_coverage["websockets"].count, 0)
            elif number == 10:
                self.assertEqual(output.heartbeat_requests, [])
                self.assertTrue(all(p.kind == "repeated_endpoint" for p in output.network_patterns))
            else:
                self.assertEqual(output.dom_inventory["controls"], [])
            self.assertEqual(output.findings, [])
