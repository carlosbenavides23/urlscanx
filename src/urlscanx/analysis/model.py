"""Versioned, neutral analysis records. None of these models is a verdict."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json

SCHEMA_VERSION = "1.0"
RULESET_VERSION = "mvp-b.7"
EVIDENCE_STATES = frozenset({
    "observed", "inferred", "declared", "referenced", "not_observed",
    "unresolved", "artifact_unavailable",
    "static_flow_inferred", "runtime_observed",
})
LAYERS = frozenset({
    "dom_markup", "network_request", "network_response", "request_payload",
    "browser_state", "console", "provider_metadata", "static_code",
    "response_payload", "screenshot_review", "external_context",
})


def digest(value: object) -> str:
    material = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(material.encode()).hexdigest()


@dataclass
class EvidenceCoverage:
    availability: str
    inspection: str
    count: int | None = None
    reason: str | None = None
    skipped_count: int = 0
    details: dict = field(default_factory=dict)


@dataclass
class EvidenceRecord:
    id: str
    artifact_id: str
    scan_id: str
    layer: str
    state: str
    origin: str
    location: dict
    frame_id: str | None
    scope_id: str
    claim: str
    redaction: dict
    details: dict = field(default_factory=dict)


@dataclass
class Finding:
    id: str
    rule_id: str
    title: str
    evidence_refs: list[str]
    severity: str = "info"


@dataclass
class NetworkPattern:
    id: str
    kind: str
    family: str
    request_count: int
    request_refs: list[str]
    evidence_refs: list[str]
    method_counts: dict[str, int]
    status_counts: dict[str, int]
    frame_ids: list[str]
    timing: dict
    session_partitions: list[dict] = field(default_factory=list)
    protocol: dict = field(default_factory=dict)
    evidence_state: str = "observed"
    role: str = "unknown"


@dataclass
class TrustBoundary:
    id: str
    structural_relation: str
    source_origin: str | None
    destination_origin: str | None
    request_refs: list[str]
    evidence_refs: list[str]
    service_role: str = "unknown"
    provider_relationship: str = "unknown"
    registrable_domain_relation: str = "unresolved"


@dataclass
class Limitation:
    id: str
    code: str
    scope: str
    explanation: str


@dataclass
class AnalystSummary:
    observed_records: int = 0
    inferred_records: int = 0
    state_counts: dict[str, int] = field(default_factory=dict)
    caveat: str = "not observed != does not exist"
    capabilities: list[str] = field(default_factory=lambda: [
        "coverage", "request_metadata", "browser_state_inventory", "dom_controls",
        "repeated_endpoints", "socket_io_http_polling", "structural_trust",
        "local_control_semantics", "markup_forms", "brand_presentation", "heartbeat_style_endpoints",
        "bounded_javascript_ast", "local_static_flows", "static_endpoint_joins",
        "bounded_interprocedural_flows", "ordered_inline_static_constants",
        "bounded_static_paths", "runtime_correlation_context",
        "bounded_request_body_structure", "static_runtime_payload_structure",
        "composed_analyst_findings", "bounded_interaction_stages", "static_prefill_provenance", "declared_retry_navigation",
    ])
    unsupported: list[str] = field(default_factory=lambda: [
        "javascript_execution", "general_interprocedural_dataflow", "runtime_payload_equality", "frame_document_contents",
        "provider_ownership", "screenshot_review", "phishing_detection", "scoring",
    ])


@dataclass
class AnalysisResult:
    status: str = "partial"
    evidence_coverage: dict[str, EvidenceCoverage] = field(default_factory=dict)
    evidence: list[EvidenceRecord] = field(default_factory=list)
    findings: list[Finding | dict] = field(default_factory=list)
    network_patterns: list[NetworkPattern] = field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = field(default_factory=list)
    limitations: list[Limitation] = field(default_factory=list)
    analyst_summary: AnalystSummary = field(default_factory=AnalystSummary)
    network_requests: list[dict] | None = None
    browser_state: dict = field(default_factory=lambda: {"cookies": None, "storages": None})
    dom_inventory: dict | None = None
    brand_signals: list[dict] = field(default_factory=list)
    brand_candidates: list[dict] = field(default_factory=list)
    heartbeat_requests: list[dict] = field(default_factory=list)
    trust_hints: list[dict] = field(default_factory=list)
    runtime_payloads: list[dict] = field(default_factory=list)
    interaction: dict = field(default_factory=lambda: {
        "stages": [], "transitions": [], "prefills": [], "retry_paths": [],
        "navigations": [], "mutations": [], "handlers": [], "attempt_counters": [],
        "coverage": {}, "runtime_execution": "not_established", "ordering": "unresolved",
    })
    javascript: dict = field(default_factory=lambda: {
        "artifacts": [], "scripts": [], "sources": [], "transforms": [],
        "sinks": [], "flows": [], "runtime_joins": [], "calls": [],
        "functions": [], "call_edges": [],
        "path_conditions": [], "runtime_correlations": [],
        "payload_correlations": [],
        "path_analysis": {"branches_inspected": 0, "conditions_true": 0, "conditions_false": 0,
                          "conditions_unresolved": 0, "truncated": False, "reasons": []},
        "interprocedural": {"resolved_invocations": 0, "parameter_propagations": 0,
                            "return_propagations": 0, "cycles_truncated": 0},
        "skipped_scripts": 0, "truncated": False, "execution": "not_performed", "limitations": [],
    })

    def to_dict(self) -> dict:
        return asdict(self)


class Registry:
    def __init__(self, analysis: AnalysisResult, scan_id: str, artifacts: dict) -> None:
        self.analysis, self.scan_id, self.artifacts = analysis, scan_id, artifacts

    def identifier(self, kind: str, material: object, *, artifact: str | None = None) -> str:
        # Artifact-backed evidence depends only on its supporting artifact. Composed
        # IDs must explicitly provide provenance; no global manifest is injected.
        provenance = [artifact, self.artifacts[artifact]] if artifact is not None else None
        return kind + "-" + digest([self.scan_id, RULESET_VERSION, provenance, material])[:20]

    def add(self, artifact: str, layer: str, state: str, location: dict, claim: str,
            *, frame_id: str | None = None, details: dict | None = None) -> str:
        if state not in EVIDENCE_STATES or layer not in LAYERS:
            raise ValueError("Unsupported evidence state or layer")
        record_id = self.identifier("e", [layer, state, location, claim], artifact=artifact)
        self.analysis.evidence.append(EvidenceRecord(
            record_id, self.artifacts[artifact], self.scan_id, layer, state,
            "urlscan_result" if artifact == "result" else "urlscan_dom" if artifact == "dom" else "supplied_js_archive",
            location, frame_id, self.scan_id + ":" + artifact, claim,
            {"policy": "derived-v1", "values_omitted": True}, details or {},
        ))
        return record_id

    def limit(self, code: str, scope: str, explanation: str) -> None:
        self.analysis.limitations.append(Limitation(
            self.identifier("l", [code, scope]), code, scope, explanation,
        ))
