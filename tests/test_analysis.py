import contextlib
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from urlscanx.analysis import analyze, analysis_envelope
from urlscanx.analysis.adapters import adapt_requests, payload
from urlscanx.analysis.model import EVIDENCE_STATES, LAYERS
from urlscanx.analysis.render import format_analysis


FIXTURES = Path(__file__).parent / "fixtures" / "analysis"
SCAN = "01a0e84d-e186-775a-b6b8-ec96c96fccf0"
FORBIDDEN = ("same actor", "same campaign", "same operator", "safe", "clean", "phishing probability",
             "no phishing detected", "malicious", "compromised", "stolen session", "cookie theft", "card harvesting")


def fixture(number):
    result = json.loads((FIXTURES / f"F{number:03}.json").read_text(encoding="utf-8"))
    return result, result["task"]["uuid"], (FIXTURES / f"F{number:03}.html").read_bytes()


def request(url="https://example.test/endpoint", method="GET", timestamp=1, **fields):
    return {"request": {"requestId": "1", "frameId": "frame-1", "documentURL": "https://example.test/",
                        "timestamp": timestamp, "request": {"url": url, "method": method, **fields}},
            "response": {"response": {"status": 200}}}


class CoverageTests(unittest.TestCase):
    def test_missing_null_wrong_type_and_empty_are_distinct(self):
        for key in ("requests", "cookies", "storages", "redirects", "websockets", "console"):
            for value, availability, count in ((None, "unavailable", None), ("bad", "invalid", None),
                                               ({}, "invalid", None), ([], "available", 0)):
                with self.subTest(key=key, value=value):
                    output = analyze({"task": {}, "data": {key: value}}, SCAN)
                    coverage = output.evidence_coverage[key]
                    self.assertEqual((coverage.availability, coverage.count), (availability, count))
                    self.assertEqual(coverage.inspection, "complete" if value == [] else "not_run")
                    if key in {"cookies", "storages"}:
                        self.assertEqual(output.browser_state[key], [] if value == [] else None)
                    if key == "requests":
                        self.assertEqual(output.network_requests, [] if value == [] else None)
            self.assertEqual(analyze({"task": {}}, SCAN).evidence_coverage[key].count, None)
        for data in (None, [], "bad"):
            self.assertIsNone(analyze({"task": {}, "data": data}, SCAN).evidence_coverage["requests"].count)
        empty = analyze({"task": {}, "data": {"requests": []}}, SCAN)
        self.assertTrue(any(e.state == "not_observed" and e.location == {"json_pointer": "/data/requests"} for e in empty.evidence))

    def test_invalid_entries_do_not_invent_requests_and_limits_are_explicit(self):
        result = {"task": {}, "data": {"requests": [None, {"request": None}, request()]}}
        output = analyze(result, SCAN)
        self.assertEqual(output.evidence_coverage["requests"].inspection, "partial")
        self.assertEqual(output.network_requests[0]["request_ref"], "/data/requests/2")
        with patch("urlscanx.analysis.adapters.MAX_ENTRIES", 2):
            output = analyze(result, SCAN)
        self.assertEqual(output.evidence_coverage["requests"].skipped_count, 1)
        self.assertEqual(output.evidence_coverage["requests"].count, 3)
        self.assertEqual(output.network_requests, [])

    def test_dom_missing_invalid_not_requested_and_limits(self):
        for dom, requested, availability in ((None, True, "unavailable"), (None, False, "not_requested"),
                                               (b"\xff", True, "invalid"), ("html", True, "invalid")):
            output = analyze({"task": {}}, SCAN, dom, dom_requested=requested)
            self.assertEqual(output.evidence_coverage["dom"].availability, availability)
            self.assertIsNone(output.dom_inventory)
        with patch("urlscanx.analysis.MAX_DOM_BYTES", 4):
            output = analyze({"task": {}}, SCAN, b"<input>")
        self.assertEqual(output.evidence_coverage["dom"].inspection, "not_run")
        self.assertIn("limit", output.evidence_coverage["dom"].reason)
        with patch("urlscanx.analysis.dom.MAX_ENTRIES", 2):
            output = analyze({"task": {}}, SCAN, b"<input><input><input>")
        self.assertEqual(output.evidence_coverage["dom"].inspection, "partial")

    def test_invalid_result_and_unsupported_websocket_records(self):
        self.assertEqual(analyze(None, SCAN).status, "invalid")
        output = analyze({"task": {}, "data": {"websockets": [{"url": "wss://example.test"}]}}, SCAN)
        self.assertEqual(output.evidence_coverage["websockets"].inspection, "not_supported")
        self.assertFalse(any(e.state == "not_observed" and e.location.get("json_pointer") == "/data/websockets" for e in output.evidence))


class AdapterTests(unittest.TestCase):
    def test_full_request_adapter_preserves_source_metadata_without_get_default(self):
        event = request(method=None, timestamp=2.5, hasPostData=True)
        event["request"].update(wallTime=123.5, initiator={"type": "script", "stack": {"callFrames": [{"lineNumber": 2}]}}, type="XHR")
        event["response"]["response"]["status"] = None
        event["requests"] = [{}]
        events, invalid = adapt_requests([event])
        normalized = events[0]
        self.assertEqual(invalid, 0)
        self.assertEqual(normalized.method, "unknown")
        self.assertIsNone(normalized.status)
        self.assertEqual(normalized.timestamp, 2.5)
        self.assertEqual(normalized.wall_time, 123.5)
        self.assertEqual(normalized.initiator, event["request"]["initiator"])
        self.assertEqual(normalized.frame_id, "frame-1")
        self.assertEqual(normalized.request_id, "1")
        self.assertEqual(normalized.request_pointer, "/data/requests/0/request/request")
        self.assertEqual(normalized.redirect_history_pointer, "/data/requests/0/requests")
        self.assertEqual(normalized.payload["state"], "not_recorded")

    def test_payload_states_do_not_confuse_hint_empty_or_encoded_bytes(self):
        cases = [({}, "not_recorded"), ({"hasPostData": True}, "not_recorded"),
                 ({"postData": ""}, "empty_preserved"), ({"postData": "secret"}, "available"),
                 ({"postData": None}, "unavailable"), ({"postData": []}, "invalid"),
                 ({"postDataEntries": [{"bytes": ""}]}, "unavailable"),
                 ({"postDataEntries": [{"bytes": "eA=="}]}, "encoded_unresolved"),
                 ({"postDataEntries": None}, "unavailable")]
        for source, expected in cases:
            with self.subTest(source=source):
                facts = payload(source, "/request")
                self.assertEqual(facts["state"], expected)
                self.assertNotIn("secret", json.dumps(facts))

    def test_no_global_query_normalization_and_nullable_timing(self):
        urls = ["https://example.test/ping?t=1", "https://example.test/ping?t=2"]
        events = [request(url, timestamp=None) for url in urls]
        output = analyze({"task": {}, "data": {"requests": events}}, SCAN)
        self.assertEqual(output.network_patterns, [])
        events += [request(urls[0], timestamp=None)]
        output = analyze({"task": {}, "data": {"requests": events}}, SCAN)
        self.assertEqual(output.network_patterns[0].kind, "repeated_endpoint")
        self.assertEqual(output.network_patterns[0].request_count, 2)
        self.assertIsNone(output.network_patterns[0].timing["span_seconds"])

    def test_protocol_selectors_and_session_partition_are_not_guessed(self):
        base = "https://example.test/socket.io/?EIO=4&transport=polling"
        events = [request(base + "&t=1"), request(base + "&sid=first-secret&t=2"),
                  request(base + "&sid=second-secret&t=3")]
        output = analyze({"task": {}, "data": {"requests": events}}, SCAN)
        pattern = output.network_patterns[0]
        self.assertEqual(pattern.kind, "socket_io_http_polling")
        self.assertEqual([p["request_count"] for p in pattern.session_partitions], [1, 1, 1])
        for secret in ("first-secret", "second-secret"):
            self.assertNotIn(secret, json.dumps(output.to_dict()))
        for suffix in ("?transport=polling", "?EIO=4&transport=websocket", "?EIO=4&transport=polling&transport=websocket"):
            output = analyze({"task": {}, "data": {"requests": [request("https://example.test/socket.io/" + suffix)] * 2}}, SCAN)
            self.assertEqual(output.network_patterns[0].kind, "repeated_endpoint")

    def test_malformed_fields_and_untrusted_terminal_text_are_bounded(self):
        result = {"task": {}, "data": {"cookies": [{"sameSite": {}, "name": "\x1b[31m", "value": "secret"}],
                  "storages": [{"key": "user@example.test", "value": "secret", "isLocalStorage": None}],
                  "requests": [request("http://[bad"), request("https://example.test/" + "x" * 17000),
                               request("https://example.test/\x1b[31m"), request("https://example.test/\u202e"),
                               request("https://example.test/\ud800") ]}}
        output = analyze(result, SCAN)
        serialized = json.dumps(output.to_dict())
        self.assertNotIn("secret", serialized)
        self.assertNotIn("user@example.test", serialized)
        self.assertNotIn("\\u001b", serialized)
        self.assertIsNone(output.browser_state["cookies"][0]["same_site"])
        self.assertEqual(output.browser_state["storages"][0]["storage_type"], "unknown")
        self.assertEqual(output.network_patterns, [])

    def test_structural_hints_use_exact_origins_and_never_infer_ownership(self):
        events = [request("https://EXAMPLE.test:443/a"), request("https://other.test/a"),
                  request("https://example.test:444/a"), request("data:text/plain,x")]
        output = analyze({"task": {}, "data": {"requests": events}}, SCAN)
        self.assertEqual([t.structural_relation for t in output.trust_boundaries],
                         ["same_origin", "cross_domain", "unresolved", "unresolved"])
        self.assertTrue(all(t.registrable_domain_relation == "unresolved" and t.provider_relationship == "unknown"
                            and t.service_role == "unknown" for t in output.trust_boundaries))

    def test_missing_group_timestamp_never_uses_wall_clock_as_substitute(self):
        events = [request(timestamp=3), request(timestamp=None)]
        events[1]["request"]["wallTime"] = 1000
        output = analyze({"task": {}, "data": {"requests": events}}, SCAN)
        self.assertEqual(output.network_patterns[0].timing["basis"], "unresolved")
        self.assertIsNone(output.network_patterns[0].timing["first_relative_seconds"])

    def test_unknown_method_and_status_are_counted_as_unknown(self):
        events = [request(method=None), request(method="POST")]
        events[0]["response"]["response"]["status"] = None
        output = analyze({"task": {}, "data": {"requests": events}}, SCAN)
        self.assertEqual(output.network_patterns[0].method_counts, {"POST": 1, "unknown": 1})
        self.assertEqual(output.network_patterns[0].status_counts, {"200": 1, "unknown": 1})

    def test_invalid_payload_coverage_and_flat_request_shape(self):
        source = {"task": {}, "data": {"requests": [{"request": {"url": "https://example.test/", "postData": {}},
                   "response": {"status": 201}}]}}
        output = analyze(source, SCAN)
        self.assertEqual(output.network_requests[0]["request_location"], "/data/requests/0/request")
        self.assertEqual(output.network_requests[0]["status"], 201)
        self.assertEqual(output.evidence_coverage["request_payloads"].availability, "invalid")


class DOMTests(unittest.TestCase):
    def test_associated_labels_aria_autocomplete_and_explicit_forms(self):
        dom = b'''<h1>Password OTP card number</h1><input id="generic"><label for="code">Verification code</label>
                  <input id="code"><label>Telephone <input name="local"></label><span id="person">Company</span>
                  <input aria-labelledby="person"><input autocomplete="cc-number" form="later">
                  <form id="later"><input type="hidden" value="secret"></form><textarea>secret</textarea><select></select>'''
        output = analyze({"task": {}}, SCAN, dom)
        controls = output.dom_inventory["controls"]
        self.assertEqual([c["semantic_type"] for c in controls], ["generic_text", "otp_candidate", "phone", "name_contact", "pan", "hidden", "textarea", "select"])
        self.assertEqual(controls[4]["form_association"], "explicit")
        self.assertEqual(controls[4]["form_index"], 0)
        self.assertEqual(controls[0]["form_association"], "none")
        self.assertNotIn("secret", json.dumps(output.to_dict()))
        self.assertEqual(controls[0]["location"], {"line": 1, "column": 33})

    def test_invalid_explicit_form_does_not_fall_back_to_ancestor(self):
        output = analyze({"task": {}}, SCAN, b'<form id="a"><input form="missing"></form>')
        self.assertEqual(output.dom_inventory["controls"][0]["form_association"], "unresolved")
        self.assertIsNone(output.dom_inventory["controls"][0]["form_index"])

    def test_password_autocomplete_and_markup_hidden_do_not_prove_visibility(self):
        output = analyze({"task": {}}, SCAN, b'<input autocomplete="current-password" hidden><input type="hidden" name="password">')
        controls = output.dom_inventory["controls"]
        self.assertEqual([c["semantic_type"] for c in controls], ["password", "hidden"])
        self.assertTrue(controls[0]["markup_hidden"])
        self.assertEqual(controls[0]["visibility"], "unresolved")


class CorpusTests(unittest.TestCase):
    def test_corpus_neutral_provenance_stable_ids_and_raw_deep_equality(self):
        for number in range(1, 12):
            with self.subTest(fixture=number):
                source, scan, dom = fixture(number)
                before = copy.deepcopy(source)
                output = analyze(source, scan, dom)
                envelope = analysis_envelope(source, scan, dom, output, analyzed_at="fixed")
                self.assertEqual(source, before)
                self.assertEqual(envelope["result"], before)
                envelope["result"]["task"]["url"] = "modified copy"
                self.assertEqual(source, before)
                self.assertEqual(output.to_dict(), analyze(source, scan, dom).to_dict())
                self.assertEqual(output.findings, [])
                self.assertEqual(output.analyst_summary.inferred_records, 0)
                ids = {e.id for e in output.evidence}
                self.assertEqual(len(ids), len(output.evidence))
                for event in output.network_requests:
                    self.assertTrue(set(event["evidence_refs"]) <= ids)
                for record in output.evidence:
                    self.assertIn(record.state, EVIDENCE_STATES)
                    self.assertIn(record.layer, LAYERS)
                    self.assertEqual(record.scan_id, scan)
                    self.assertTrue(record.artifact_id.startswith(("result:sha256:", "dom:sha256:")))
                    pointer = record.location.get("json_pointer")
                    if pointer is not None:
                        value = source
                        for token in pointer.split("/")[1:]:
                            value = value[int(token)] if isinstance(value, list) else value[token]
                for verbose in (False, True):
                    rendered = format_analysis(analysis_envelope(source, scan, dom, output), verbose=verbose)
                    for phrase in FORBIDDEN:
                        self.assertNotIn(phrase, rendered.lower())
                    self.assertNotIn("fixture-private-value", rendered)
                    self.assertIn("not observed != does not exist", rendered)
                self.assertNotIn("fixture-private-value", json.dumps(output.to_dict()))
                self.assertNotIn("fixture-private-console", json.dumps(output.to_dict()))

    def test_f003_orphan_controls_and_no_runtime_sensitive_post(self):
        source, scan, dom = fixture(3)
        output = analyze(source, scan, dom)
        self.assertEqual(output.dom_inventory["forms_count"], 0)
        self.assertEqual([c["semantic_type"] for c in output.dom_inventory["controls"]], ["email", "password", "otp_candidate"])
        self.assertTrue(all(c["form_association"] == "none" for c in output.dom_inventory["controls"]))
        self.assertEqual({e["method"] for e in output.network_requests}, {"GET"})
        self.assertEqual(output.network_patterns, [])
        self.assertEqual(output.evidence_coverage["external_script_sources"].availability, "unavailable")

    def test_f004_f005_state_and_password_visibility(self):
        for number, cookies, storages in ((4, 23, 2), (5, 14, 1)):
            source, scan, dom = fixture(number)
            output = analyze(source, scan, dom)
            self.assertEqual(len(output.browser_state["cookies"]), cookies)
            self.assertEqual(len(output.browser_state["storages"]), storages)
            self.assertEqual(output.findings, [])
            if number == 5:
                password = next(c for c in output.dom_inventory["controls"] if c["semantic_type"] == "password")
                self.assertEqual(password["visibility"], "unresolved")
                self.assertEqual(password["submission"], "not_evaluated")
                self.assertTrue(password["aria_hidden"])

    def test_f006_payment_inventory_is_markup_not_transfer(self):
        source, scan, dom = fixture(6)
        output = analyze(source, scan, dom)
        self.assertTrue({"pan", "expiry", "cvc"} <= {c["semantic_type"] for c in output.dom_inventory["controls"]})
        self.assertTrue(all(c["submission"] == "not_evaluated" for c in output.dom_inventory["controls"]))

    def test_f008_single_ping_is_not_polling(self):
        source, scan, dom = fixture(8)
        output = analyze(source, scan, dom)
        self.assertEqual(len(output.browser_state["storages"]), 3)
        self.assertEqual(sum("/ping" in e["url"] for e in output.network_requests), 1)
        self.assertTrue(all(p.kind == "repeated_endpoint" for p in output.network_patterns))
        self.assertNotIn("HTTP polling", format_analysis(analysis_envelope(source, scan, dom, output)))

    def test_f009_protocol_frequency_sessions_timing_and_no_websocket(self):
        source, scan, dom = fixture(9)
        output = analyze(source, scan, dom)
        pattern = next(p for p in output.network_patterns if p.kind == "socket_io_http_polling")
        self.assertEqual(pattern.request_count, 7)
        self.assertEqual(pattern.method_counts, {"GET": 4, "POST": 3})
        self.assertEqual(pattern.status_counts, {"200": 7})
        self.assertEqual(pattern.request_refs, [f"/data/requests/{i}" for i in (8, 23, 24, 26, 27, 29, 30)])
        self.assertEqual([(p["sid_present"], p["request_count"]) for p in pattern.session_partitions], [(False, 1), (True, 6)])
        self.assertAlmostEqual(pattern.timing["span_seconds"], 0.242709, places=6)
        self.assertEqual(pattern.timing["cadence"], "unresolved")
        self.assertEqual(output.evidence_coverage["websockets"].count, 0)
        self.assertEqual(output.dom_inventory["forms_count"], 0)
        self.assertEqual([c["semantic_type"] for c in output.dom_inventory["controls"]], ["generic_text", "checkbox", "checkbox", "checkbox"])
        rendered = format_analysis(analysis_envelope(source, scan, dom, output))
        self.assertIn("WebSocket: not observed", rendered)
        self.assertNotIn("fixture-session", json.dumps(output.to_dict()))

    def test_f010_bot_state_and_opaque_posts_are_neutral(self):
        source, scan, dom = fixture(10)
        output = analyze(source, scan, dom)
        self.assertEqual(len(output.browser_state["cookies"]), 13)
        self.assertTrue({"email", "phone", "name_contact"} <= {c["semantic_type"] for c in output.dom_inventory["controls"]})
        self.assertTrue(all(p.kind == "repeated_endpoint" for p in output.network_patterns))
        self.assertEqual(output.findings, [])
        self.assertNotIn("exfiltration", json.dumps(output.to_dict()))

    def test_f011_verification_route_snapshot_no_kyc_claims(self):
        source, scan, dom = fixture(11)
        output = analyze(source, scan, dom)
        self.assertEqual((len(output.browser_state["storages"]), len(output.browser_state["cookies"])), (9, 5))
        self.assertEqual(output.dom_inventory["controls_count"], 0)
        self.assertEqual(output.dom_inventory["forms_count"], 0)
        self.assertTrue(any("secure-verification" in e["url"] for e in output.network_requests))
        rendered = format_analysis(analysis_envelope(source, scan, dom, output)).lower()
        for claim in ("selfie", "camera", "kyc", "document upload"):
            self.assertNotIn(claim, rendered)

    def test_verbose_removes_presentation_limit_not_redaction(self):
        source, scan, dom = fixture(11)
        output = analyze(source, scan, dom)
        envelope = analysis_envelope(source, scan, dom, output)
        normal, verbose = format_analysis(envelope), format_analysis(envelope, verbose=True)
        self.assertIn("body records with the same protected URL / format / field structure", normal)
        self.assertNotIn("body records with the same protected URL / format / field structure", verbose)
        self.assertIn("Refs: /data/requests/", verbose)
        self.assertNotIn("fixture-private-value", verbose)

    def test_engine_is_pure_and_never_uses_network_execution_or_files(self):
        source, scan, dom = fixture(3)
        with contextlib.ExitStack() as guards:
            for target in ("urllib.request.urlopen", "urllib.request.OpenerDirector.open", "socket.getaddrinfo",
                           "socket.socket", "subprocess.Popen", "builtins.eval", "builtins.open", "pathlib.Path.open"):
                guards.enter_context(patch(target, side_effect=AssertionError("analysis must be passive")))
            output = analyze(source, scan, dom + b'<a href="https://target.test/collector">x</a><form action="https://target.test/post"><script src="https://target.test/a.js"></script><script>fetch("https://target.test");</script>')
            rendered = format_analysis(analysis_envelope(source, scan, dom, output), verbose=True)
        self.assertIn("JavaScript not executed; local static flows do not establish submission or receipt.", rendered)
