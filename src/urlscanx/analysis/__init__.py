"""Passive analysis of already supplied Result, DOM and script artifacts."""

from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
import hashlib
from urllib.parse import parse_qsl, urlencode, urlsplit

from .. import __version__
from .adapters import (
    adapt_requests, array_field, endpoint_key, label, mapping, origin, origin_url,
    safe_url, text,
)
from .dom import MAX_DOM_BYTES, MarkupBudgetExceeded, MarkupInventory
from .presentation import inventory as presentation_inventory
from .javascript import inventory as javascript_inventory
from .payloads import inventory as payload_inventory
from .payload_correlation import correlate as payload_correlate
from .interaction import InteractionInventory
from .findings import build as findings_build
from .model import (
    AnalysisResult, EvidenceCoverage, NetworkPattern, Registry, RULESET_VERSION,
    SCHEMA_VERSION, TrustBoundary, digest,
)


def artifact_ids(result: object, dom: bytes | None) -> dict[str, str]:
    return {"result": "result:sha256:" + digest(result),
            "dom": "dom:sha256:" + hashlib.sha256(dom).hexdigest() if isinstance(dom, bytes) else "dom:unavailable"}


def analyze(result: object, scan_id: str, dom: bytes | None = None, *,
            dom_requested: bool = True, dom_error: str | None = None, archived_scripts: tuple = ()) -> AnalysisResult:
    """No I/O, mutation of input, execution, or consumption of analyst annotations."""
    output = AnalysisResult()
    registry = Registry(output, scan_id, artifact_ids(result, dom))
    page, task = mapping(mapping(result).get("page")), mapping(mapping(result).get("task"))
    document_url = text(page.get("url")) or text(task.get("url"))
    document_pointer = "/page/url" if text(page.get("url")) else "/task/url"
    document_ref = None
    if document_url is not None:
        document_ref = registry.add("result", "provider_metadata", "observed", {"json_pointer": document_pointer},
                                    "Document URL metadata preserved", details={"origin": origin_url(document_url)})
    parser = None
    valid_result = isinstance(result, dict) and isinstance(result.get("task"), dict)
    output.evidence_coverage["result"] = EvidenceCoverage(
        "available" if valid_result else "invalid", "complete" if valid_result else "not_run",
        reason=None if valid_result else "Result is not an object with task metadata",
    )
    registry.add("result", "provider_metadata", "observed" if valid_result else "artifact_unavailable",
                 {"json_pointer": ""}, "Result artifact available" if valid_result else "Result artifact invalid")

    arrays = {}
    for key in ("requests", "redirects", "cookies", "storages", "websockets", "console"):
        arrays[key], coverage = array_field(result, key)
        output.evidence_coverage[key] = coverage
        if arrays[key] is None:
            registry.add("result", "provider_metadata", "artifact_unavailable", {"json_pointer": "/data/" + key},
                         key + " cannot be inventoried", details={"reason": coverage.reason})
        elif coverage.count == 0:
            registry.add("result", "provider_metadata", "not_observed", {"json_pointer": "/data/" + key},
                         "0 captured " + key + " entries in this artifact")

    events, invalid = adapt_requests(arrays["requests"])
    requests_cov = output.evidence_coverage["requests"]
    incomplete = sum(e.method == "unknown" or e.raw_url is None or
                     safe_url(e.raw_url) in {"[invalid URL omitted]", "[oversized URL omitted]"} for e in events)
    if arrays["requests"] is not None and (invalid or incomplete):
        requests_cov.inspection = "partial"
        requests_cov.reason = "invalid request entries or unresolved URL/method metadata"
    requests_cov.details.update(normalized_events=len(events), invalid_entries=invalid, incomplete_events=incomplete)
    for event in events:
        event.evidence_refs.append(registry.add(
            "result", "network_request", "observed", {"json_pointer": event.pointer},
            "Request metadata captured", frame_id=label(event.frame_id),
            details={"method": event.method, "url": safe_url(event.raw_url), "request_location": event.request_pointer},
        ))
        if event.status is not None:
            event.evidence_refs.append(registry.add(
                "result", "network_response", "observed", {"json_pointer": event.response_pointer + "/status"},
                "Response status captured", frame_id=label(event.frame_id), details={"status": event.status},
            ))
        state = event.payload["state"]
        registry.add("result", "request_payload", "observed" if state in {"available", "empty_preserved"} else "unresolved",
                     {"json_pointer": event.payload["location"] or event.request_pointer},
                     "Request payload visibility inventoried; contents not interpreted",
                     frame_id=label(event.frame_id), details=event.payload.copy())
    output.network_requests = [event.public() for event in events] if arrays["requests"] is not None else None
    payload_counts = dict(sorted(Counter(event.payload["state"] for event in events).items()))
    captured = sum(payload_counts.get(key, 0) for key in ("available", "empty_preserved", "encoded_unresolved"))
    if arrays["requests"] is None:
        payload_cov = EvidenceCoverage(requests_cov.availability, "not_run", reason="request inventory unavailable")
    elif requests_cov.count == 0:
        payload_cov = EvidenceCoverage("available", "complete", 0, details={"state_counts": {}})
    else:
        availability = "available" if captured else "invalid" if payload_counts.get("invalid") else "unavailable"
        payload_cov = EvidenceCoverage(availability, "partial", captured if captured else None,
                                       "body visibility varies; contents and encoded entries are not interpreted",
                                       details={"state_counts": payload_counts})
    output.evidence_coverage["request_payloads"] = payload_cov

    for key in ("cookies", "storages"):
        if arrays[key] is not None:
            output.browser_state[key] = []
        for i, entry in enumerate(arrays[key] if arrays[key] is not None else []):
            if not isinstance(entry, dict):
                continue
            pointer = f"/data/{key}/{i}"
            if key == "cookies":
                facts = {"name": label(entry.get("name")), "domain": label(entry.get("domain")),
                         "path": safe_url(entry.get("path")),
                         "flags": {k: entry[k] if isinstance(entry.get(k), bool) else None
                                   for k in ("httpOnly", "secure", "session", "sameParty")},
                         "same_site": text(entry.get("sameSite")) if text(entry.get("sameSite")) in {"Strict", "Lax", "None"} else None}
            else:
                local = entry.get("isLocalStorage")
                facts = {"origin": origin_url(entry.get("origin")), "key": label(entry.get("key")),
                         "storage_type": ("local" if local else "nonlocal") if isinstance(local, bool) else "unknown"}
            facts.update(value_present="value" in entry, value_omitted=True, location=pointer)
            facts["evidence_ref"] = registry.add("result", "browser_state", "observed", {"json_pointer": pointer},
                                                  "Cookie snapshot entry" if key == "cookies" else "Storage snapshot entry",
                                                  details=facts.copy())
            output.browser_state[key].append(facts)

    for i, entry in enumerate(arrays["redirects"] if arrays["redirects"] is not None else []):
        if isinstance(entry, dict):
            registry.add("result", "network_request", "observed", {"json_pointer": f"/data/redirects/{i}"},
                         "Redirect metadata record captured; mechanism not inferred",
                         details={"from": safe_url(entry.get("from")), "to": safe_url(entry.get("to"))})
    for i, entry in enumerate(arrays["console"] if arrays["console"] is not None else []):
        if isinstance(entry, dict):
            registry.add("result", "console", "observed", {"json_pointer": f"/data/console/{i}"},
                         "Console entry captured; message content omitted")
    ws_cov = output.evidence_coverage["websockets"]
    if ws_cov.count:
        ws_cov.inspection = "not_supported"
        ws_cov.reason = "nonempty WebSocket records are counted but not interpreted"

    frame_ids = sorted({event.frame_id for event in events if event.frame_id is not None})
    frame_cov = EvidenceCoverage("available" if frame_ids else "unavailable", "partial" if arrays["requests"] is not None else "not_run",
                                 len(frame_ids) if frame_ids else None,
                                 "request frame IDs only; no complete frame tree or frame document contents",
                                 details={"frame_ids": [label(v) for v in frame_ids]})
    output.evidence_coverage["frames"] = frame_cov

    dom_cov = EvidenceCoverage("not_requested" if not dom_requested else "unavailable", "not_run",
                                reason="DOM not requested" if not dom_requested else "DOM artifact unavailable")
    if dom_requested and dom is not None:
        if not isinstance(dom, bytes):
            dom_cov = EvidenceCoverage("invalid", "not_run", reason="DOM is not bytes")
        elif len(dom) > MAX_DOM_BYTES:
            dom_cov = EvidenceCoverage("available", "not_run", reason="DOM exceeds 8 MiB analysis limit")
        else:
            try:
                markup = dom.decode("utf-8")
            except UnicodeDecodeError:
                dom_cov = EvidenceCoverage("invalid", "not_run", reason="DOM is not valid UTF-8")
            else:
                parser = MarkupInventory()
                try:
                    parser.feed(markup)
                    parser.close()
                    output.dom_inventory = parser.inventory(document_url)
                except MarkupBudgetExceeded:
                    dom_cov = EvidenceCoverage("available", "partial", reason=parser.budget_reason,
                                               details={"scope": "markup inventory withheld", "forms_count": None})
                    registry.add("dom", "dom_markup", "unresolved", {},
                                 "DOM structural inventory withheld after parser budget breach",
                                 details={"reason": parser.budget_reason})
                    parser = None
                except (AssertionError, ValueError):
                    # HTMLParser may reject malformed declarations. Withhold the
                    # complete structural inventory; exception text can contain values.
                    output.dom_inventory = None
                    parser = None
                    dom_cov = EvidenceCoverage("invalid", "not_run", reason="DOM markup parsing failed; structural inventory withheld")
                else:
                    dom_cov = EvidenceCoverage("available", "complete", output.dom_inventory["controls_count"],
                                               details={"scope": "markup inventory only", "forms_count": output.dom_inventory["forms_count"]})
                    for control in output.dom_inventory["controls"]:
                        control["evidence_ref"] = registry.add("dom", "dom_markup", "observed", control["location"],
                                                               "Control present in markup; visibility and submission not established",
                                                               details={"semantic_type": control["semantic_type"],
                                                                        "semantic_role": control["semantic_role"],
                                                                        "semantic_support": control["semantic_support"],
                                                                        "form_association": control["form_association"]})
                        control.update(id=registry.identifier("control", [control["evidence_ref"]]), state="observed",
                                       evidence_refs=[control["evidence_ref"]], limitations=["Visibility and runtime submission not established."])
                    for form in output.dom_inventory["forms"]:
                        # DOM evidence describes attributes; URL resolution is a composed fact.
                        ref = registry.add("dom", "dom_markup", "observed", form["location"], "HTML form markup preserved",
                                           details={"markup_method": form["markup_method"], "markup_action": form["markup_action"]})
                        refs = [ref] + ([document_ref] if document_ref and form["target_resolution"] == "resolved" else [])
                        form.update(id=registry.identifier("form", refs), state="observed", evidence_refs=refs,
                                    control_refs=[output.dom_inventory["controls"][i]["id"] for i in form["control_indices"]],
                                    limitations=["Client-side handlers may override or cancel markup behavior."])
                        for submit in form["submit_controls"]:
                            submit_ref = registry.add("dom", "dom_markup", "observed", submit["location"], "Submit control markup preserved")
                            submit.update(id=registry.identifier("submit", [submit_ref]), state="observed", evidence_refs=[submit_ref],
                                          limitations=["Markup association and overrides only; activation and runtime behavior unresolved."])
                        _form_trust(form, document_url, registry)
    if dom_error:
        dom_cov.reason = "optional DOM retrieval failed"  # No exception text or extracted URLs echoed.
    output.evidence_coverage["dom"] = dom_cov
    if dom_cov.inspection == "not_run":
        registry.add("dom", "dom_markup", "artifact_unavailable", {}, "DOM inventory cannot be evaluated",
                     details={"reason": dom_cov.reason})

    script_requests = sum(event.resource_type == "Script" for event in events) if arrays["requests"] is not None else None
    script_markup = output.dom_inventory["external_script_references"] if output.dom_inventory is not None else None
    output.evidence_coverage["external_script_sources"] = EvidenceCoverage(
        "unavailable" if script_requests or script_markup else "not_requested", "not_supported",
        reason="external script source bytes are not supplied; URLs and response hashes are not source code",
        details={"script_requests": script_requests, "markup_references": script_markup},
    )

    _network(events, registry)
    _trust(events, registry)
    presentation_inventory(result, parser, document_url, registry, document_ref)
    interaction = InteractionInventory(parser, registry, document_url)
    javascript_inventory(result, dom if dom_requested else None, parser, events, document_url, registry, archived_scripts, interaction)
    payload_inventory(result, events, registry)
    payload_correlate(output, registry)
    interaction.finalize()
    preserved_scripts = sum(s['kind'] == 'external_preserved' for s in output.javascript['scripts'])
    if preserved_scripts:
        missing = any(s['parser_status'] == 'unavailable' for s in output.javascript['scripts'])
        output.evidence_coverage['external_script_sources'] = EvidenceCoverage(
            'available', 'partial' if missing else 'complete', preserved_scripts,
            reason='Only explicit preserved response.body strings inspected; other references unavailable',
            details={'script_requests': script_requests, 'markup_references': script_markup})
    if document_ref:
        output.trust_hints.insert(0, {"id": registry.identifier("origin", [document_ref]), "kind": "page_origin",
                                      "page_origin": origin_url(document_url), "state": "observed", "evidence_refs": [document_ref],
                                      "provider_relationship": "unresolved"})
    registry.limit("MARKUP_ONLY", "dom", "Markup does not establish visibility, submission, or frame/shadow document contents.")
    registry.limit("MARKUP_HANDLERS", "forms", "Client-side handlers may override or cancel markup behavior; runtime submission not established.")
    registry.limit("PRESENTATION_ONLY", "brand", "Presentation vocabulary is limited; logos/text do not establish intent, provider ownership or impersonation.")
    registry.limit("METADATA_ONLY", "network", "Request-body structure only; values, response payloads, redirect-history expansion and WebSocket messages are not inspected.")
    registry.limit("LIMITED_STATIC_CODE", "scripts", "Bounded local AST and helper dependencies only; JavaScript not executed, imports and general interprocedural flows unsupported.")
    registry.limit("NO_OWNERSHIP", "trust", "Origin and hostname relations do not establish ownership; PSL/provider registry unavailable.")
    for key, coverage in output.evidence_coverage.items():
        if coverage.availability != "available" or coverage.inspection != "complete":
            registry.limit("COVERAGE_" + key.upper(), key, coverage.reason or "Category inspection is incomplete.")
    counts = Counter(record.state for record in output.evidence)
    output.analyst_summary.state_counts = dict(sorted(counts.items()))
    output.analyst_summary.observed_records = counts["observed"]
    output.analyst_summary.inferred_records = counts["inferred"] + len(output.javascript["flows"])
    output.status = "partial" if valid_result else "invalid"
    findings_build(output, registry)
    return output


def _network(events: list, registry: Registry) -> None:
    groups = defaultdict(list)
    for event in events:
        # OPTIONS may be CORS preflight. Keep every event in the raw/normalized
        # inventory, but conservatively exclude OPTIONS from application repetition.
        if event.method == "OPTIONS":
            continue
        key = endpoint_key(event)
        if key is not None:
            groups[key].append(event)
    # Relative monotonic time only; wallTime never substitutes for missing timestamps.
    times = [event.timestamp for event in events if event.timestamp is not None]
    baseline = min(times) if times else None
    # Explicit protocol evidence remains visible in compact output ahead of generic repetition.
    for key, members in sorted(groups.items(), key=lambda item: not item[0][3]):
        canonical, path, query, socket = key
        if not socket and path.rsplit("/", 1)[-1] in {"ping", "heartbeat"}:
            refs = [ref for event in members for ref in event.evidence_refs]
            request_refs = [event.pointer for event in members]
            family = safe_url(members[0].raw_url)
            registry.analysis.heartbeat_requests.append({
                "id": registry.identifier("heartbeat", [family, request_refs]), "kind": "heartbeat_style_endpoint",
                "family": family, "state": "observed", "request_count": len(members), "request_refs": request_refs,
                "evidence_refs": refs, "method_counts": dict(sorted(Counter(e.method for e in members).items())),
                "cadence": "unresolved", "role": "unknown",
                "support": {"source": "request_url_path", "terminal_segment": path.rsplit("/", 1)[-1]},
                "limitations": ["Endpoint spelling does not establish purpose or periodic activity."],
            })
        if len(members) < 2:
            continue
        first_url = members[0].raw_url
        timing = {"first_relative_seconds": None, "last_relative_seconds": None,
                  "span_seconds": None, "basis": "unresolved", "cadence": "unresolved"}
        if baseline is not None and all(event.timestamp is not None for event in members):
            first, last = min(event.timestamp for event in members), max(event.timestamp for event in members)
            timing.update(first_relative_seconds=round(first - baseline, 6), last_relative_seconds=round(last - baseline, 6),
                          span_seconds=round(last - first, 6), basis="captured_monotonic_timestamps")
        partitions, protocol = [], {}
        if socket:
            sessions = defaultdict(list)
            for event in members:
                params = parse_qsl(urlsplit(event.raw_url).query, keep_blank_values=True)
                sid = tuple(v for k, v in params if k == "sid")
                sessions[(sid, event.frame_id)].append(event)
            for (sid, frame), session_events in sessions.items():
                # Scan-local opaque identifier, not a hash of low-entropy secret values.
                session_number = 1 + sum(p["sid_present"] for p in partitions)
                resolved_sid = len(sid) == 1 and bool(sid[0])
                partitions.append({"session_id": "session-" + str(session_number) if resolved_sid else None,
                                   "sid_present": bool(sid), "request_count": len(session_events),
                                   "session_state": "present" if resolved_sid else "unresolved" if sid else "absent",
                                   "frame_id": label(frame), "request_refs": [e.pointer for e in session_events]})
            params = parse_qsl(urlsplit(first_url).query, keep_blank_values=True)
            protocol = {"EIO": next(v for k, v in params if k == "EIO"), "transport": "polling", "volatile_parameters": ["t"]}
            family = safe_url(canonical + path + "?" + urlencode(query))
        else:
            family = safe_url(first_url)
        kind = "socket_io_http_polling" if socket else "repeated_endpoint"
        request_refs = [event.pointer for event in members]
        registry.analysis.network_patterns.append(NetworkPattern(
            # Neither raw grouping keys, artifact digests nor evidence IDs enter
            # this published ID: they can encode redacted low-entropy query values.
            registry.identifier("n", [kind, family, request_refs]), kind, family,
            len(members), request_refs, [ref for event in members for ref in event.evidence_refs],
            dict(sorted(Counter(e.method for e in members).items())),
            dict(sorted(Counter(str(e.status) if e.status is not None else "unknown" for e in members).items())),
            sorted({label(e.frame_id) for e in members if e.frame_id is not None}), timing, partitions, protocol,
        ))


def _trust(events: list, registry: Registry) -> None:
    groups = defaultdict(list)
    for event in events:
        source, destination = origin(event.document_url), origin(event.raw_url)
        if source is not None and destination is not None:
            relation = "same_origin" if source == destination else "cross_domain" if source[1] != destination[1] else "unresolved"
        else:
            relation = "unresolved"
        groups[(relation, origin_url(event.document_url), origin_url(event.raw_url))].append(event)
    for key, members in groups.items():
        relation, source, destination = key
        registry.analysis.trust_boundaries.append(TrustBoundary(
            registry.identifier("t", [key, [event.evidence_refs[0] for event in members]]), relation, source, destination,
            [event.pointer for event in members], [event.evidence_refs[0] for event in members],
        ))
        boundary = registry.analysis.trust_boundaries[-1]
        registry.analysis.trust_hints.append({"id": registry.identifier("hint", [boundary.id]),
                                              "kind": "request_destination", "structural_relation": relation,
                                              "source_origin": source, "destination_origin": destination,
                                              "request_refs": boundary.request_refs, "evidence_refs": boundary.evidence_refs,
                                              "provider_relationship": "unresolved", "state": "observed",
                                              "limitations": ["Different hostname only; registrable domain and ownership unresolved."]})


def _form_trust(form: dict, document_url: str | None, registry: Registry) -> None:
    source, destination = origin(document_url), origin(form["target_origin"])
    relation = ("same_origin" if source == destination else "cross_domain" if source[1] != destination[1] else "unresolved") if source and destination else "unresolved"
    registry.analysis.trust_hints.append({"id": registry.identifier("formtrust", [form["id"]]),
                                          "kind": "form_markup_target", "structural_relation": relation,
                                          "source_origin": origin_url(document_url), "destination_origin": form["target_origin"],
                                          "form_ref": form["id"], "evidence_refs": form["evidence_refs"], "state": "observed",
                                          "provider_relationship": "unresolved",
                                          "limitations": ["Markup target only; handlers and provider ownership unresolved."]})


def analysis_envelope(result: dict, scan_id: str, dom: bytes | None, analysis: AnalysisResult,
                      *, analyzed_at: str | None = None) -> dict:
    """The original Result is deep-copied; derived output is separately serialized."""
    task, page = mapping(result.get("task")), mapping(result.get("page"))
    return {"schema_version": SCHEMA_VERSION,
            "metadata": {"analyzer_version": __version__, "ruleset_version": RULESET_VERSION,
                         "mode": "passive_mvp_a", "scan_id": scan_id, "scan_time": text(task.get("time")),
                         "origin": origin_url(page.get("url")) or origin_url(task.get("url")),
                         "analyzed_at": analyzed_at,
                         "artifact_ids": artifact_ids(result, dom), "result_digest_basis": "canonical_json",
                         "derived_values": "masked; raw result is preserved and may contain sensitive data"},
            "result": deepcopy(result), "analysis": analysis.to_dict()}
