"""Second MVP-a slice: local markup/presentation facts and bounded URL privacy."""

import contextlib
import copy
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.parse import quote, unquote

from urlscanx.analysis import analyze, analysis_envelope
from urlscanx.analysis.adapters import safe_url
from urlscanx.analysis.render import format_analysis
from urlscanx.cli import main
from urlscanx.display import display_url
from test_analysis import fixture, request, SCAN, FIXTURES, FORBIDDEN


def inventory(markup, url="https://example.test/path/page?item=42"):
    return analyze({"task": {}, "page": {"url": url}}, SCAN, markup.encode())


class SlicePrivacyTests(unittest.TestCase):
    def test_deferred_paths_and_fragments_never_hash(self):
        cases = ("/otp=123456", "/passcode=123456", "#otp/123456", "#verification-code/123456",
                 "#otp=123456", "/verification_code%3D123456", "/cvv=123", "/password=hunter2")
        with patch("urlscanx.display.hashlib.sha256", side_effect=AssertionError("secret hashed")):
            for suffix in cases:
                with self.subTest(suffix=suffix):
                    for shown in (display_url("https://e.test/" + suffix.lstrip("/")), safe_url("https://e.test/" + suffix.lstrip("/"))):
                        for value in ("123456", "hunter2", "cvv=123"):
                            self.assertNotIn(value, shown)
                        self.assertNotIn("sha256", shown)
                    self.assertIn("[omitted]", display_url("https://e.test/" + suffix.lstrip("/")))

    def test_nested_url_secret_paths_and_userinfo_are_sanitized_without_hashes(self):
        with patch("urlscanx.display.hashlib.sha256", side_effect=AssertionError("secret hashed")):
            for nested in ("https://example.test/otp/123456", "https://example.test/passcode=123456",
                           "https://example.test/#verification-code/123456", "https://alice:hunter2@example.test/",
                           "https://example.test/?otp=123456"):
                for value in (nested, quote(nested, safe=""), quote(quote(nested, safe=""), safe="")):
                    with self.subTest(nested=nested, value=value):
                        shown = unquote(display_url("https://e.test/?next=" + value))
                        self.assertNotIn("123456", shown)
                        self.assertNotIn("hunter2", shown)
                        self.assertIn("[omitted]", shown)

    def test_nested_depth_two_retains_normal_values_three_omits(self):
        leaf = "https://third.test/products/42?item=7"
        second = "https://second.test/?next=" + quote(leaf, safe="")
        first = "https://first.test/?next=" + quote(second, safe="")
        self.assertEqual(display_url(second, limit=16384), second)
        # Two nested URLs below the top level are permitted.
        self.assertIn("products", unquote(unquote(display_url(first, limit=16384))))
        too_deep = "https://outer.test/?next=" + quote(first, safe="")
        shown = unquote(unquote(unquote(display_url(too_deep, limit=16384))))
        self.assertNotIn("products", shown)
        self.assertIn("[omitted]", shown)

    def test_malformed_and_oversized_nested_values_degrade_safely(self):
        for nested in ("https://[bad/otp/123456", "https:///otp/123456", "https://e.test:bad/otp/123456"):
            shown = unquote(display_url("https://e.test/?next=" + quote(nested, safe="")))
            self.assertNotIn("123456", shown)
            self.assertIn("[invalid URL omitted]", shown)
        self.assertEqual(display_url("https://e.test/?next=" + "x" * 17000), "[oversized URL omitted]")

    def test_normal_assignments_and_fragments_retained(self):
        for suffix in ("/item=42", "#products/42", "#item=42"):
            url = "https://e.test/" + suffix.lstrip("/")
            self.assertEqual(display_url(url), url)

    def test_nested_url_under_token_name_cannot_hash_password(self):
        with patch("urlscanx.display.hashlib.sha256", side_effect=AssertionError("secret hashed")):
            shown = display_url("https://e.test/?access_token=" + quote("https://e.test/password/hunter2", safe=""))
            self.assertEqual(shown, "https://e.test/?access_token=[omitted]")

    def test_cli_verbose_and_json_raw_contract_for_deferred_secrets(self):
        url = "https://e.test/otp=123456#verification-code/123456"
        result = {"task": {"url": url}, "data": {"requests": [request(url)]}}
        before = copy.deepcopy(result)
        for options in (["--verbose"], ["--analyze", "--verbose"], ["--analyze", "--json"]):
            out = io.StringIO()
            with patch("urlscanx.cli.api_key", return_value="offline"), patch("urlscanx.cli.fetch_result", return_value=result), \
                 patch("urlscanx.cli.fetch_asset", return_value=None), contextlib.redirect_stdout(out):
                self.assertEqual(main([SCAN, *options]), 0)
            if "--json" in options:
                envelope = json.loads(out.getvalue())
                self.assertEqual(envelope["result"], before)
                self.assertNotIn("123456", json.dumps(envelope["analysis"]))
            else:
                self.assertNotIn("123456", out.getvalue())
        self.assertEqual(result, before)


class SliceControlTests(unittest.TestCase):
    def test_strong_local_signals_structure_and_semantics(self):
        markup = '<input type="hidden" name="password"><input autocomplete="identifier"><input autocomplete="username">' \
                 '<input autocomplete="email"><input type="password"><input autocomplete="new-password">' \
                 '<input autocomplete="current-password"><input autocomplete="one-time-code">' \
                 '<input autocomplete="cc-number"><input autocomplete="cc-exp"><input autocomplete="cc-csc">'
        controls = inventory(markup).dom_inventory["controls"]
        self.assertEqual([c["semantic_role"] for c in controls], ["password", "username", "username", "email", "password", "password", "password", "otp_candidate", "payment_pan", "payment_expiry", "payment_cvc"])
        self.assertEqual(controls[0]["html_type"], "hidden")
        self.assertEqual(controls[0]["structural_control"], "input")
        self.assertEqual(controls[0]["semantic_type"], "hidden")  # Legacy field preserved.
        self.assertTrue(all(c["semantic_support"] and c["evidence_refs"] and c["id"] for c in controls))

    def test_code_alone_length_and_page_text_cannot_create_otp(self):
        controls = inventory('<h1>Password OTP verification code</h1><input name="code" maxlength="6" inputmode="numeric" pattern="[0-9]{6}"><input id="recovery"><input id="promoCode"><input id="postalCode"><input aria-label="CAPTCHA code"><input aria-label="Card security code">').dom_inventory["controls"]
        self.assertEqual([c["semantic_role"] for c in controls], ["generic_text", "generic_text", "generic_text", "postal_code", "captcha_or_challenge", "payment_cvc"])
        self.assertEqual(controls[0]["supporting_hints"]["maxlength"], "6")

    def test_local_otp_signals_and_label_provenance(self):
        markup = '<label for="v">Two-factor authentication code</label><input id="v">' \
                 '<span id="a">Authenticator</span><input aria-labelledby="a"><input name="passcode"><input aria-label="Verification code">'
        controls = inventory(markup).dom_inventory["controls"]
        self.assertTrue(all(c["semantic_role"] == "otp_candidate" for c in controls))
        self.assertEqual(controls[0]["semantic_support"][0]["source"], "associated_label")
        self.assertEqual(controls[0]["semantic_support"][0]["location"], {"line": 1, "column": 0})
        self.assertEqual(controls[1]["semantic_support"][0]["source"], "aria-labelledby")
        self.assertIsNotNone(controls[1]["semantic_support"][0]["location"])

    def test_contact_semantics_are_separate_and_neutral(self):
        controls = inventory('<input type="email"><input type="tel" name="Phone"><input autocomplete="name"><input name="Company"><input autocomplete="postal-code"><input aria-label="Contact address"><input type="tel"><select></select><textarea></textarea>').dom_inventory["controls"]
        self.assertEqual([c["semantic_role"] for c in controls], ["email", "phone", "person_name", "company", "postal_code", "contact_data", "unknown", "unknown", "generic_text"])
        self.assertIsNone(controls[-1]["html_type"])

    def test_marketing_challenge_language_is_not_captcha_and_template_is_explicit(self):
        output = inventory('<label for="m">Business challenge</label><input id="m"><template><input type="password"></template>')
        self.assertEqual(output.dom_inventory["controls"][0]["semantic_role"], "generic_text")
        self.assertEqual(output.dom_inventory["controls"][1]["markup_context"], "inert_markup")


class SliceFormTests(unittest.TestCase):
    def test_defaults_resolve_markup_without_runtime_submission(self):
        output = inventory('<form id="f"><input name="email"><button>Send</button></form>')
        form = output.dom_inventory["forms"][0]
        self.assertEqual(form["markup_method"], "GET")
        self.assertEqual(form["method_basis"], "html_default")
        self.assertEqual(form["target_basis"], "current_document")
        self.assertEqual(form["resolved_markup_target"], "https://example.test/path/page?item=[omitted]")
        self.assertEqual(form["runtime_submission"], "not_established")
        self.assertEqual(len(form["control_refs"]), 1)
        self.assertEqual(len(form["submit_controls"]), 1)
        self.assertTrue(form["limitations"])

    def test_explicit_association_precedes_ancestry_and_submit_overrides(self):
        output = inventory('<form id="a"><input id="x" form="b"><button form="b" formaction="../other?otp=123456" formmethod="post">Go</button><input form="missing"></form><form id="b" method="post" action="/login"></form>')
        forms = output.dom_inventory["forms"]
        self.assertEqual(forms[0]["control_indices"], [])
        self.assertEqual(forms[1]["control_indices"], [0])
        submit = forms[1]["submit_controls"][0]
        self.assertEqual(submit["association"], "explicit")
        self.assertEqual(submit["formmethod"], "POST")
        self.assertEqual(submit["resolved_formaction"], "https://example.test/other?otp=[omitted]")
        self.assertNotIn("123456", json.dumps(output.to_dict()))

    def test_duplicate_form_ids_and_unsupported_targets_are_unresolved(self):
        output = inventory('<input form="a"><form id="a" action="javascript:void(0)"></form><form id="a" method="dialog"></form>')
        self.assertEqual(output.dom_inventory["controls"][0]["form_association"], "unresolved")
        self.assertTrue(all(f["target_resolution"] == "unresolved" for f in output.dom_inventory["forms"]))
        self.assertEqual(output.dom_inventory["forms"][1]["markup_method"], "DIALOG")

    def test_missing_document_relative_action_unresolved_absolute_resolves(self):
        output = inventory('<form action="relative"></form><form action="https://other.test/post"></form>', url=None)
        forms = output.dom_inventory["forms"]
        self.assertEqual(forms[0]["target_resolution"], "unresolved")
        self.assertEqual(forms[1]["resolved_markup_target"], "https://other.test/post")

    def test_dom_evidence_independent_of_result_and_computed_forms_composed(self):
        dom = '<form><input autocomplete="username"></form>'
        first, other = inventory(dom), inventory(dom, url="https://different.test/")
        records = lambda output: [e for e in output.evidence if e.origin == "urlscan_dom"]
        self.assertEqual(records(first), records(other))
        self.assertNotEqual(first.dom_inventory["forms"][0]["id"], other.dom_inventory["forms"][0]["id"])

    def test_base_href_cannot_silently_produce_guessed_relative_target(self):
        forms = inventory('<base href="https://different.test/"><form action="relative"></form><form></form><form action="https://absolute.test/"></form>').dom_inventory["forms"]
        self.assertEqual(forms[0]["target_resolution"], "unresolved")
        self.assertEqual(forms[1]["target_basis"], "current_document")
        self.assertEqual(forms[2]["target_resolution"], "resolved")


class SlicePresentationTests(unittest.TestCase):
    def test_titles_logos_copy_links_metadata_have_provenance(self):
        source = {"task": {}, "page": {"url": "https://tenant.pages.dev/", "title": "Microsoft sign in"}, "brands": [{"name": "Example Brand"}]}
        dom = b'<title>Microsoft</title><img class="logo" alt="Microsoft" src="https://assets.test/logo.svg"><p>OneDrive</p><a href="https://other.test/privacy">Privacy help</a>'
        output = analyze(source, SCAN, dom)
        self.assertTrue({"Microsoft", "OneDrive", "Example Brand"} <= {b["name"] for b in output.brand_candidates})
        self.assertTrue({"page_title", "document_title", "logo_alt", "image_source", "local_brand_text", "legal_help_link", "urlscan_brand_metadata"} <= {s["kind"] for s in output.brand_signals})
        self.assertTrue(all(s["id"] and s["evidence_refs"] and s["location"] and s["state"] == "observed" for s in output.brand_signals))
        self.assertTrue(all(b["provider_relationship"] == "unresolved" for b in output.brand_candidates))
        self.assertEqual(next(s for s in output.brand_signals if s["kind"] == "image_source")["source_host"], "assets.test")

    def test_script_style_comment_template_and_ambiguous_link_are_not_brand_copy(self):
        dom = '<script>Microsoft</script><style>PayPal</style><!-- Stripe --><template><p>Discord</p></template><p>Click this Link</p><svg><title>Twitter</title></svg>'
        self.assertEqual(inventory(dom).brand_candidates, [])
        output = inventory('<svg><title>Stripe</title></svg><title>Link</title>')
        self.assertEqual({b["name"] for b in output.brand_candidates}, {"Stripe", "Link"})

    def test_brand_copy_does_not_classify_controls_and_does_not_expose_identity(self):
        output = inventory('<p>Microsoft password OTP card number alice@example.test</p><input name="code"><img alt="Microsoft alice@example.test" class="logo" src="/logo.svg?otp=123456">')
        self.assertEqual(output.dom_inventory["controls"][0]["semantic_role"], "generic_text")
        self.assertNotIn("alice@example.test", json.dumps(output.to_dict()))
        self.assertNotIn("123456", json.dumps(output.to_dict()))

    def test_no_dom_keeps_result_title_but_not_dom_signals(self):
        output = analyze({"task": {}, "page": {"title": "Discord"}}, SCAN)
        self.assertEqual([s["kind"] for s in output.brand_signals], ["page_title"])
        self.assertEqual([b["name"] for b in output.brand_candidates], ["Discord"])

    def test_dom_brand_provenance_stable_and_relative_urls_have_document_refs(self):
        dom = '<img class="logo" alt="Microsoft" src="/logo.svg"><a href="/terms">Terms</a>'
        first, other = inventory(dom), inventory(dom, url="https://different.test/")
        dom_records = lambda out: [e for e in out.evidence if e.origin == "urlscan_dom"]
        self.assertEqual(dom_records(first), dom_records(other))
        source = next(s for s in first.brand_signals if s["kind"] == "image_source")
        self.assertEqual(len(source["evidence_refs"]), 2)
        self.assertNotEqual(first.brand_candidates[0]["id"], other.brand_candidates[0]["id"])

    def test_budget_breach_withholds_forms_controls_and_dom_brand_signals(self):
        for target, limit, dom in (("MAX_ENTRIES", 2, b'<title>Microsoft</title><form><input></form>'),
                                   ("MAX_DEPTH", 2, b'<title>Microsoft</title><div><div><div><input>')):
            with patch("urlscanx.analysis.dom." + target, limit):
                output = analyze({"task": {}, "page": {"title": "PayPal"}}, SCAN, dom)
            self.assertIsNone(output.dom_inventory)
            self.assertFalse(any(e.origin == "urlscan_dom" and e.state == "observed" for e in output.evidence))
            self.assertEqual({b["name"] for b in output.brand_candidates}, {"PayPal"})

    def test_label_and_element_id_budgets_also_withhold_partial_structure(self):
        for dom in (b'<label>A</label><label>B</label><label>C</label>', b'<input id="x"><div id="a"></div><div id="b"></div>'):
            with patch("urlscanx.analysis.dom.MAX_ENTRIES", 2):
                output = analyze({"task": {}}, SCAN, dom)
            self.assertIsNone(output.dom_inventory)
            self.assertEqual(output.brand_signals, [])
            self.assertEqual(output.evidence_coverage["dom"].inspection, "partial")


class SliceNetworkTrustTests(unittest.TestCase):
    def test_single_heartbeat_spelling_no_periodicity_claim(self):
        for path in ("/ping", "/messenger/web/ping", "/heartbeat"):
            output = analyze({"task": {}, "data": {"requests": [request("https://e.test" + path, method="POST")]}}, SCAN)
            self.assertEqual(output.network_patterns, [])
            self.assertEqual(output.heartbeat_requests[0]["request_count"], 1)
            self.assertEqual(output.heartbeat_requests[0]["cadence"], "unresolved")
            rendered = format_analysis(analysis_envelope({"task": {}}, SCAN, None, output))
            self.assertIn("Heartbeat-style endpoint observed", rendered)
            self.assertNotIn("polling", rendered)

    def test_partial_path_substrings_and_options_not_heartbeat(self):
        events = [request("https://e.test" + path) for path in ("/pingback", "/heartbeat-log", "/ping/extra", "/opaque")]
        events += [request("https://e.test/ping", method="OPTIONS")]
        output = analyze({"task": {}, "data": {"requests": events}}, SCAN)
        self.assertEqual(output.heartbeat_requests, [])

    def test_generic_repetition_is_not_polling_or_heartbeat(self):
        output = analyze({"task": {}, "data": {"requests": [request("https://e.test/opaque", method="POST")] * 2}}, SCAN)
        self.assertEqual(output.network_patterns[0].kind, "repeated_endpoint")
        self.assertEqual(output.heartbeat_requests, [])

    def test_form_and_request_structural_relations_no_ownership(self):
        source = {"task": {}, "page": {"url": "https://tenant.pages.dev/"}, "data": {"requests": [request("https://other.test/")]}}
        output = analyze(source, SCAN, b'<title>Microsoft</title><form action="https://other.test/post"></form>')
        self.assertTrue(all(h["provider_relationship"] == "unresolved" for h in output.trust_hints))
        self.assertEqual(next(h for h in output.trust_hints if h["kind"] == "form_markup_target")["structural_relation"], "cross_domain")
        self.assertEqual(output.brand_candidates[0]["provider_relationship"], "unresolved")


class SliceCorpusTests(unittest.TestCase):
    def test_all_primary_derived_fixtures_semantics_brands_refs_raw_equality(self):
        expected = {1: {"Microsoft", "OneDrive"}, 2: {"BAC Credomatic"}, 3: {"PayPal"}, 4: {"Microsoft"}, 5: {"Microsoft"},
                    6: {"Visa", "MasterCard"}, 7: {"Discord"}, 8: {"ShareGate"}, 9: {"Solana Beach"}, 10: {"Akamai"}, 11: {"Link"}}
        for number in range(1, 12):
            with self.subTest(fixture=number):
                source, scan, dom = fixture(number)
                # Supplement contains only sanitized presentation from primary DOM.
                dom += (FIXTURES / "presentation" / f"F{number:03}.html").read_bytes()
                before = copy.deepcopy(source)
                output = analyze(source, scan, dom)
                self.assertTrue(expected[number] <= {b["name"] for b in output.brand_candidates})
                self.assertEqual(output.findings, [])
                self.assertEqual(source, before)
                envelope = analysis_envelope(source, scan, dom, output)
                self.assertEqual(envelope["result"], before)
                self.assertEqual(envelope["schema_version"], "1.0")
                self.assertEqual(output.to_dict(), analyze(source, scan, dom).to_dict())
                ids = {e.id for e in output.evidence}
                objects = [*output.brand_signals, *output.brand_candidates, *output.heartbeat_requests, *output.trust_hints,
                           *output.dom_inventory["controls"], *output.dom_inventory["forms"]]
                for obj in objects:
                    self.assertTrue(obj["id"] and obj["state"] and set(obj["evidence_refs"]) <= ids)
                for verbose in (False, True):
                    rendered = format_analysis(envelope, verbose=verbose)
                    for phrase in (*FORBIDDEN, "MFA interception", "KYC success", "password submitted", "beaconing", "C2"):
                        if phrase == "C2":
                            self.assertNotRegex(rendered.lower(), r"\bc2\b")
                        else:
                            self.assertNotIn(phrase.lower(), rendered.lower())
                self.assertEqual(len(ids), len(output.evidence))

    def test_fixture_control_expectations(self):
        roles = {}
        for number in (1, 3, 4, 5, 6, 7, 9, 10, 11):
            source, scan, dom = fixture(number)
            controls = analyze(source, scan, dom).dom_inventory["controls"]
            roles[number] = {c["semantic_role"] for c in controls}
            self.assertTrue(all(c["visibility"] == "unresolved" and c["submission"] == "not_evaluated" for c in controls))
        self.assertTrue({"password", "username"} <= roles[1])
        self.assertTrue({"email", "password", "otp_candidate"} <= roles[3])
        self.assertIn("username", roles[4])
        self.assertTrue({"username", "password"} <= roles[5])
        self.assertTrue({"payment_pan", "payment_expiry", "payment_cvc"} <= roles[6])
        self.assertTrue({"email", "password"} <= roles[7])
        self.assertFalse(roles[9] & {"password", "username", "email", "otp_candidate"})
        self.assertTrue({"email", "phone", "person_name", "company"} <= roles[10])
        self.assertEqual(roles[11], set())

    def test_f001_f005_markup_and_f008_f009_f010_network_expectations(self):
        for n in (1, 5):
            source, scan, dom = fixture(n)
            forms = analyze(source, scan, dom).dom_inventory["forms"]
            self.assertEqual(forms[0]["markup_method"], "GET" if n == 1 else "POST")
            self.assertEqual(forms[0]["runtime_submission"], "not_established")
        for n in (8, 9, 10):
            source, scan, dom = fixture(n)
            output = analyze(source, scan, dom)
            if n == 8:
                ping = next(h for h in output.heartbeat_requests if "/messenger/web/ping" in h["family"])
                self.assertEqual(ping["request_count"], 1)
                self.assertEqual(ping["method_counts"], {"POST": 1})
            elif n == 9:
                pattern = next(p for p in output.network_patterns if p.kind == "socket_io_http_polling")
                self.assertEqual(pattern.request_count, 7)
                self.assertEqual(pattern.method_counts, {"GET": 4, "POST": 3})
                self.assertEqual([p["request_count"] for p in pattern.session_partitions], [1, 6])
                self.assertEqual(output.evidence_coverage["websockets"].count, 0)
            else:
                self.assertEqual(output.heartbeat_requests, [])
                self.assertTrue(all(p.kind == "repeated_endpoint" for p in output.network_patterns))

    def test_renderer_bounds_and_verbose_same_analysis(self):
        dom = '<form>' + '<input autocomplete="username">' * 12 + '</form>'
        output = inventory(dom)
        envelope = analysis_envelope({"task": {}}, SCAN, dom.encode(), output)
        normal, verbose = format_analysis(envelope), format_analysis(envelope, verbose=True)
        self.assertIn("Controls: username 12", normal)
        self.assertIn("Semantic controls", verbose)
        self.assertIn("markup form method GET", normal)
        self.assertIn("Runtime submission not established", normal)

    def test_new_extractors_passive_with_all_io_execution_blocked(self):
        source, scan, dom = fixture(8)
        dom += (FIXTURES / "presentation" / "F008.html").read_bytes()
        with patch("urllib.request.urlopen", side_effect=AssertionError("HTTP")), \
             patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("HTTP opener")), \
             patch("socket.socket", side_effect=AssertionError("socket")), \
             patch("socket.getaddrinfo", side_effect=AssertionError("DNS")), \
             patch("subprocess.run", side_effect=AssertionError("process")), \
             patch("builtins.open", side_effect=AssertionError("file")), \
             patch("builtins.eval", side_effect=AssertionError("eval")):
            output = analyze(source, scan, dom)
            self.assertTrue(output.heartbeat_requests)
            self.assertTrue(output.brand_candidates)
