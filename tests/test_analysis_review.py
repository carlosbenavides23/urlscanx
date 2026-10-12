"""Regression tests for the six MVP-a code review fixes; all inputs are offline."""

from collections import Counter
import copy
import json
import unittest
from unittest.mock import patch

from urlscanx.analysis import analyze, analysis_envelope
from urlscanx.analysis.adapters import label, safe_url
from urlscanx.analysis.dom import MarkupBudgetExceeded, MarkupInventory
from urlscanx.analysis.render import format_analysis
from urlscanx.display import display_url, mask_identifier
from test_analysis import fixture, request, SCAN


TOKENS = (
    "ghp_shortExampleToken",
    "sk-shortExampleToken",
    "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.c2ln",  # JWT-like, less than 48 chars.
    "OpaqueBareToken_" * 4,
)


class ReviewRedactionTests(unittest.TestCase):
    def test_shared_masking_covers_raw_and_encoded_query_keys_paths_and_names(self):
        for token in TOKENS:
            encoded = "".join(f"%{ord(char):02X}" for char in token)
            for value in (token, encoded):
                with self.subTest(token=token, encoded=value != token):
                    self.assertEqual(label(value), "[omitted]")
                    self.assertEqual(mask_identifier(value, fingerprint=False), "[omitted]")
                    for url in (f"https://example.test/?{value}", f"https://example.test/?{value}=x",
                                f"https://example.test/{value}"):
                        shown = safe_url(url)
                        self.assertNotIn(token, shown)
                        self.assertNotIn(encoded, shown)
                        self.assertIn("[omitted]", shown)
                        # Normal views use the same recognition policy with existing fingerprints.
                        self.assertNotIn(token, display_url(url))
                        self.assertNotIn(encoded, display_url(url))
                        self.assertIn("[REDACTED", display_url(url))
        for ordinary in ("session_cookie", "intercom-state", "loginfmt", "a" * 64 + ".js", "f" * 64):
            self.assertEqual(mask_identifier(ordinary, fingerprint=False), ordinary)
        self.assertEqual(display_url("https://example.test/api?item=42"), "https://example.test/api?item=42")

    def test_all_derived_outputs_and_verbose_omit_tokens_raw_envelope_preserves_them(self):
        for token in TOKENS:
            with self.subTest(token=token):
                url = f"https://example.test/{token}?{token}"
                result = {"task": {"url": "https://example.test/"}, "data": {
                    "requests": [request(url), request(url)],
                    "cookies": [{"name": token, "value": "cookie-value"}],
                    "storages": [{"origin": "https://example.test/", "key": token, "value": "storage-value", "isLocalStorage": True}],
                }}
                before = copy.deepcopy(result)
                dom = f'<input id="{token}" name="{token}">'.encode()
                output = analyze(result, SCAN, dom)
                envelope = analysis_envelope(result, SCAN, dom, output)
                self.assertEqual(result, before)
                self.assertEqual(envelope["result"], before)
                self.assertIn(token, json.dumps(envelope["result"]))
                self.assertNotIn(token, json.dumps(envelope["analysis"]))
                self.assertEqual(output.browser_state["cookies"][0]["name"], "[omitted]")
                self.assertEqual(output.browser_state["storages"][0]["key"], "[omitted]")
                for verbose in (False, True):
                    self.assertNotIn(token, format_analysis(envelope, verbose=verbose))


class ReviewIdentifierTests(unittest.TestCase):
    def test_pattern_ids_exclude_changed_otp_queries_and_artifact_digests(self):
        ids = []
        for otp in ("111111", "999999"):
            result = {"task": {}, "data": {"requests": [request(f"https://example.test/verify?otp={otp}")] * 2}}
            output = analyze(result, SCAN)
            pattern = output.network_patterns[0]
            self.assertNotIn(otp, pattern.family)
            ids.append(pattern.id)
        self.assertEqual(ids[0], ids[1])

    def test_pattern_ids_do_not_encode_masked_path_or_bare_key_tokens(self):
        for template in ("https://example.test/{token}", "https://example.test/?{token}",
                         "https://example.test/api/token/{token}?code={token}"):
            ids = []
            for token in ("ghp_firstSecretToken", "ghp_secondSecretToken"):
                result = {"task": {}, "data": {"requests": [request(template.format(token=token))] * 2}}
                ids.append(analyze(result, SCAN).network_patterns[0].id)
            self.assertEqual(ids[0], ids[1])

    def test_raw_grouping_keeps_different_queries_with_equal_display_separate(self):
        events = [request(f"https://example.test/verify?otp={otp}") for otp in ("111111", "111111", "222222", "222222")]
        output = analyze({"task": {}, "data": {"requests": events}}, SCAN)
        first, second = output.network_patterns
        self.assertEqual(first.family, second.family)
        self.assertNotEqual(first.id, second.id)
        self.assertEqual(first.request_refs, ["/data/requests/0", "/data/requests/1"])
        self.assertEqual(second.request_refs, ["/data/requests/2", "/data/requests/3"])

    def test_result_evidence_and_composed_network_objects_are_dom_independent(self):
        result, scan, dom = fixture(9)
        with_dom, without_dom = analyze(result, scan, dom), analyze(result, scan)
        result_records = lambda output: [e for e in output.evidence if e.origin == "urlscan_result"]
        self.assertEqual(result_records(with_dom), result_records(without_dom))
        self.assertEqual(with_dom.network_patterns, without_dom.network_patterns)
        self.assertEqual(with_dom.trust_boundaries, without_dom.trust_boundaries)

    def test_dom_evidence_depends_on_dom_but_not_on_unrelated_result_material(self):
        first = analyze({"task": {}}, SCAN, b'<input id="name">')
        changed_result = analyze({"task": {"extra": "changed"}}, SCAN, b'<input id="name">')
        changed_dom = analyze({"task": {}}, SCAN, b'<input id="name">\n')
        dom_records = lambda output: [e for e in output.evidence if e.origin == "urlscan_dom" and e.state == "observed"]
        self.assertEqual(dom_records(first), dom_records(changed_result))
        self.assertNotEqual([e.id for e in dom_records(first)], [e.id for e in dom_records(changed_dom)])


class ReviewNetworkIntegrityTests(unittest.TestCase):
    def test_corpus_pattern_counts_have_matching_request_and_response_evidence(self):
        for number in range(1, 12):
            with self.subTest(fixture=number):
                result, scan, dom = fixture(number)
                output = analyze(result, scan, dom)
                evidence = {e.id: e for e in output.evidence}
                events = {e["request_ref"]: e for e in output.network_requests}
                for pattern in output.network_patterns:
                    self.assertEqual(len(pattern.evidence_refs), len(set(pattern.evidence_refs)))
                    self.assertTrue(set(pattern.evidence_refs) <= evidence.keys())
                    refs = [evidence[ref] for ref in pattern.evidence_refs]
                    requests = [e for e in refs if e.layer == "network_request"]
                    responses = [e for e in refs if e.layer == "network_response"]
                    self.assertEqual({e.location["json_pointer"] for e in requests}, set(pattern.request_refs))
                    self.assertEqual(dict(Counter(e.details["method"] for e in requests)), pattern.method_counts)
                    counted_status = Counter(str(e.details["status"]) for e in responses)
                    unknown = sum(events[ref]["status"] is None for ref in pattern.request_refs)
                    if unknown:
                        counted_status["unknown"] = unknown
                    self.assertEqual(dict(counted_status), pattern.status_counts)
                    for ref in pattern.request_refs:
                        event = events[ref]
                        self.assertTrue(set(event["evidence_refs"]) <= set(pattern.evidence_refs))
                    self.assertEqual(sum(pattern.status_counts.values()), pattern.request_count)

    def test_unknown_status_uses_request_ref_without_fabricated_response(self):
        events = [request(), request()]
        events[0]["response"]["response"]["status"] = None
        output = analyze({"task": {}, "data": {"requests": events}}, SCAN)
        pattern = output.network_patterns[0]
        evidence = {e.id: e for e in output.evidence}
        refs = [evidence[ref] for ref in pattern.evidence_refs]
        self.assertEqual(pattern.status_counts, {"200": 1, "unknown": 1})
        self.assertEqual(sum(e.layer == "network_request" for e in refs), 2)
        self.assertEqual(sum(e.layer == "network_response" for e in refs), 1)

    def test_options_plus_single_application_request_is_not_repeated_activity(self):
        for method in ("GET", "POST"):
            for initiator in (None, {"type": "preflight"}):
                with self.subTest(method=method, initiator=initiator):
                    preflight = request(method="OPTIONS")
                    preflight["response"]["response"]["status"] = 204
                    if initiator is not None:
                        preflight["request"]["initiator"] = initiator
                    source = {"task": {}, "data": {"requests": [preflight, request(method=method)]}}
                    before = copy.deepcopy(source)
                    output = analyze(source, SCAN)
                    self.assertEqual(output.network_patterns, [])
                    self.assertEqual(len(output.network_requests), 2)
                    self.assertEqual(output.network_requests[0]["method"], "OPTIONS")
                    self.assertEqual(source, before)
                    self.assertNotIn("Repeated endpoint", format_analysis(analysis_envelope(source, SCAN, None, output)))

    def test_two_application_requests_still_repeat_without_preflight_inflation(self):
        events = [request(method="OPTIONS"), request(), request()]
        output = analyze({"task": {}, "data": {"requests": events}}, SCAN)
        pattern = output.network_patterns[0]
        self.assertEqual(pattern.request_count, 2)
        self.assertEqual(pattern.method_counts, {"GET": 2})
        self.assertEqual(pattern.request_refs, ["/data/requests/1", "/data/requests/2"])
        self.assertEqual(len(output.network_requests), 3)
        self.assertEqual(analyze({"task": {}, "data": {"requests": events[:1] * 2}}, SCAN).network_patterns, [])

    def test_f009_polling_remains_seven_application_events_with_response_support(self):
        result, scan, dom = fixture(9)
        # A same-family OPTIONS event cannot inflate this explicit protocol pattern.
        result["data"]["requests"].append(request(result["data"]["requests"][8]["request"]["request"]["url"], method="OPTIONS"))
        output = analyze(result, scan, dom)
        pattern = next(p for p in output.network_patterns if p.kind == "socket_io_http_polling")
        self.assertEqual(pattern.request_count, 7)
        self.assertEqual(pattern.method_counts, {"GET": 4, "POST": 3})
        self.assertEqual(pattern.status_counts, {"200": 7})
        self.assertEqual(len(pattern.evidence_refs), 14)


class ReviewDOMBudgetTests(unittest.TestCase):
    def assert_withheld(self, markup, target, limit, reason):
        source = {"task": {}, "data": {"requests": [request()]}}
        before = copy.deepcopy(source)
        with patch(target, limit):
            output = analyze(source, SCAN, markup)
        self.assertIsNone(output.dom_inventory)
        coverage = output.evidence_coverage["dom"]
        self.assertEqual((coverage.availability, coverage.inspection, coverage.count), ("available", "partial", None))
        self.assertEqual(coverage.reason, reason)
        self.assertIsNone(coverage.details["forms_count"])
        self.assertFalse(any(e.layer == "dom_markup" and e.state == "observed" for e in output.evidence))
        self.assertTrue(any(e.layer == "dom_markup" and e.state == "unresolved" for e in output.evidence))
        self.assertEqual(len(output.network_requests), 1)
        self.assertEqual(source, before)

    def test_entry_limit_with_skipped_nested_form_and_future_label_discards_prefix(self):
        markup = b'<form id="outer"><input id="early" form="later"><form id="skipped"></form><input id="late"></form><form id="later"></form><label for="early">Verification code</label>'
        self.assert_withheld(markup, "urlscanx.analysis.dom.MAX_ENTRIES", 2, "entry budget exceeded")

    def test_depth_limit_with_nested_form_cannot_corrupt_form_or_label_stack(self):
        markup = b'<form id="outer"><input id="early"><div><form id="skipped"></form><input name="late"></div></form>'
        self.assert_withheld(markup, "urlscanx.analysis.dom.MAX_DEPTH", 2, "depth budget exceeded")

    def test_stopped_parser_cannot_resume_or_publish_mutated_structural_state(self):
        parser = MarkupInventory()
        with patch("urlscanx.analysis.dom.MAX_DEPTH", 2), self.assertRaises(MarkupBudgetExceeded):
            parser.feed('<form id="outer"><label>Email<input id="early"><form id="skipped">')
        snapshot = copy.deepcopy((parser.forms, parser.controls, parser.labels, parser.stack, parser.form_stack))
        parser.handle_data("Verification code")
        parser.handle_endtag("form")
        with self.assertRaises(MarkupBudgetExceeded):
            parser.handle_starttag("input", [("name", "late")])
        with self.assertRaises(MarkupBudgetExceeded):
            parser.inventory()
        self.assertEqual((parser.forms, parser.controls, parser.labels, parser.stack, parser.form_stack), snapshot)
        self.assertEqual(len(parser.forms), 1)  # Rejected nested form never mutated the stack.

    def test_exact_entry_budget_allows_balanced_nonentry_tags_and_late_labels(self):
        with patch("urlscanx.analysis.dom.MAX_ENTRIES", 2):
            output = analyze({"task": {}}, SCAN, b'<form id="f"><input id="field"></form><div><label for="field">Email</label></div>')
        self.assertEqual(output.evidence_coverage["dom"].inspection, "complete")
        self.assertEqual(output.dom_inventory["controls"][0]["semantic_type"], "email")
        self.assertEqual(output.dom_inventory["controls"][0]["form_association"], "ancestor")
