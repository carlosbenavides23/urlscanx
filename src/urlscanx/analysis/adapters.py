"""Read preserved fields without coercing missing, null or invalid data to empty lists."""

from __future__ import annotations

from dataclasses import dataclass
import math
import re
import unicodedata
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

from ..display import display_text, display_url, mask_identifier
from .model import EvidenceCoverage

MAX_ENTRIES = 10_000
MAX_URL_CHARS = 16_384


def _unsafe_characters(value: str) -> bool:
    return any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value)


def mapping(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def number(value: object) -> float | None:
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) else None


def label(value: object) -> str | None:
    """Do not echo arbitrary browser text, identities or token-shaped identifiers."""
    if not isinstance(value, str):
        return None
    masked = mask_identifier(value, fingerprint=False)
    if masked != value:
        return masked
    if len(value) > 80 or re.search(r"@|[\x00-\x1f\x7f-\x9f]|(?:\d[ -]?){12,}", value):
        return "[omitted]"
    if not re.fullmatch(r"[\w .:/()\[\]-]*", value, re.UNICODE):
        return "[omitted]"
    return display_text(value, 80)


def safe_url(value: object) -> str | None:
    """Derived output omits all query values except validated protocol selectors."""
    if not isinstance(value, str):
        return None
    if len(value) > MAX_URL_CHARS:
        return "[oversized URL omitted]"
    if _unsafe_characters(value):
        return "[invalid URL omitted]"
    try:
        parsed = urlsplit(value)
        query = []
        protocol_path = parsed.path == "/socket.io/"
        for key, val in parse_qsl(parsed.query, keep_blank_values=True):
            visible = protocol_path and ((key == "EIO" and val.isdigit() and len(val) <= 2)
                                         or (key == "transport" and val in {"polling", "websocket"}))
            query.append((label(key) or "[omitted]", val if visible else "[omitted]"))
        # Fragments may carry prefilled identities or credentials.
        path = "/".join("[omitted]" if "@" in unquote(segment) or re.fullmatch(r"\+?\d[\d -]{10,}", unquote(segment))
                        else segment for segment in parsed.path.split("/"))
        rendered = urlunsplit((parsed.scheme, parsed.netloc, path, urlencode(query), ""))
        return display_url(rendered, fingerprint=False).replace("%5Bomitted%5D", "[omitted]")
    except ValueError:
        return "[invalid URL omitted]"


def origin(value: object) -> tuple[str, str, int] | None:
    if not isinstance(value, str) or len(value) > MAX_URL_CHARS:
        return None
    if _unsafe_characters(value) or any(char.isspace() for char in value):
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username is not None:
            return None
        port = parsed.port
        return parsed.scheme.lower(), parsed.hostname.lower(), port if port is not None else (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError:
        return None


def origin_url(value: object) -> str | None:
    parts = origin(value)
    if parts is None:
        return None
    scheme, host, port = parts
    host = f"[{host}]" if ":" in host else host
    suffix = "" if port == (443 if scheme == "https" else 80) else f":{port}"
    return f"{scheme}://{host}{suffix}"


def array_field(result: object, key: str) -> tuple[list | None, EvidenceCoverage]:
    data = result.get("data") if isinstance(result, dict) else None
    if data is None:
        return None, EvidenceCoverage("unavailable", "not_run", reason="data missing or null")
    if not isinstance(data, dict):
        return None, EvidenceCoverage("invalid", "not_run", reason="data is not an object")
    if key not in data or data[key] is None:
        return None, EvidenceCoverage("unavailable", "not_run", reason="field missing" if key not in data else "field is null")
    if not isinstance(data[key], list):
        return None, EvidenceCoverage("invalid", "not_run", reason="field is not an array")
    values = data[key]
    skipped = max(0, len(values) - MAX_ENTRIES)
    invalid = sum(not isinstance(item, dict) for item in values[:MAX_ENTRIES])
    coverage = EvidenceCoverage("available", "partial" if skipped or invalid else "complete", len(values),
                                "entry limit or invalid entries" if skipped or invalid else None,
                                skipped, {"invalid_entries": invalid})
    return values[:MAX_ENTRIES], coverage


def payload(request: dict, pointer: str) -> dict:
    """Inventory visibility only; never decode, print or interpret payload content."""
    hint = request.get("hasPostData")
    result = {"has_post_data": hint if isinstance(hint, bool) else None,
              "state": "not_recorded", "location": None, "length": None}
    if "postData" in request:
        body = request["postData"]
        result.update(location=pointer + "/postData")
        if isinstance(body, str):
            result.update(state="available" if body else "empty_preserved", length=len(body))
            return result
        result["state"] = "unavailable" if body is None else "invalid"
    if "postDataEntries" in request:
        entries = request["postDataEntries"]
        result["location"] = pointer + "/postDataEntries"
        if isinstance(entries, list):
            # Empty byte placeholders do not establish a recoverable empty body.
            result["state"] = "encoded_unresolved" if any(
                isinstance(e, dict) and isinstance(e.get("bytes"), str) and e["bytes"] for e in entries[:MAX_ENTRIES]
            ) else "unavailable"
        else:
            result["state"] = "unavailable" if entries is None else "invalid"
    return result


def request_body_source(result: object, event: RequestEvent) -> dict:
    """Private view of the observed Result schema; never serialize this object.

    postData is literal request text. Encoded postDataEntries remain opaque when
    no literal text is preserved. No response fields or invented body aliases.
    """
    entry = mapping(mapping(mapping(result).get("data")).get("requests")[event.index])
    outer = mapping(entry.get("request"))
    request = mapping(outer.get("request")) if "request" in outer else outer
    return {"body": request.get("postData"), "literal_present": "postData" in request,
            "entries": request.get("postDataEntries"),
            "entries_present": "postDataEntries" in request,
            "headers": mapping(request.get("headers")), "pointer": event.request_pointer}


@dataclass
class RequestEvent:
    index: int
    pointer: str
    request_pointer: str
    response_pointer: str
    raw_url: str | None
    document_url: str | None
    method: str
    status: int | float | None
    request_id: str | None
    frame_id: str | None
    timestamp: float | None
    wall_time: float | None
    initiator: dict | None
    resource_type: str | None
    payload: dict
    redirect_history_pointer: str | None
    evidence_refs: list[str]

    def public(self) -> dict:
        initiator = None
        if self.initiator is not None:
            initiator = {"type": label(self.initiator.get("type")),
                         "location": self.pointer + "/request/initiator"}
        return {
            "request_ref": self.pointer, "request_location": self.request_pointer,
            "response_location": self.response_pointer, "url": safe_url(self.raw_url),
            "document_url": safe_url(self.document_url), "method": self.method,
            "status": self.status, "request_id": label(self.request_id), "frame_id": label(self.frame_id),
            "timestamp": self.timestamp, "wall_time": self.wall_time,
            "initiator": initiator, "resource_type": label(self.resource_type),
            "payload": self.payload.copy(), "redirect_history_location": self.redirect_history_pointer,
            "evidence_refs": self.evidence_refs[:],
        }


def adapt_requests(values: list | None) -> tuple[list[RequestEvent], int]:
    events, invalid = [], 0
    for i, entry in enumerate(values if values is not None else []):
        if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict):
            invalid += 1
            continue
        pointer = f"/data/requests/{i}"
        outer = entry["request"]
        nested = "request" in outer
        if nested and not isinstance(outer["request"], dict):
            invalid += 1
            continue
        request = outer["request"] if nested else outer
        rp = pointer + ("/request/request" if nested else "/request")
        response = mapping(entry.get("response"))
        response_nested = isinstance(response.get("response"), dict)
        status = number((response["response"] if response_nested else response).get("status"))
        method = text(request.get("method"))
        # Do not promote arbitrary malformed text to an HTTP method or default GET.
        method = method.upper() if method and re.fullmatch(r"[A-Za-z]{1,20}", method) else "unknown"
        events.append(RequestEvent(
            i, pointer, rp, pointer + ("/response/response" if response_nested else "/response"),
            text(request.get("url")), text(outer.get("documentURL")), method, status,
            text(outer.get("requestId")), text(outer.get("frameId")) or text(entry.get("frameId")) or None,
            number(outer.get("timestamp")), number(outer.get("wallTime")),
            outer.get("initiator") if isinstance(outer.get("initiator"), dict) else None,
            text(outer.get("type")) or text(entry.get("type")), payload(request, rp),
            pointer + "/requests" if "requests" in entry else None, [],
        ))
    return events, invalid


def endpoint_key(event: RequestEvent) -> tuple | None:
    """Exact query semantics outside the single supported protocol rule."""
    canonical = origin_url(event.raw_url)
    if canonical is None:
        return None
    parsed = urlsplit(event.raw_url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    socket = (parsed.path == "/socket.io/" and
              [v for k, v in params if k == "transport"] == ["polling"] and
              len([v for k, v in params if k == "EIO"]) == 1 and
              all(v.isdigit() and 1 <= len(v) <= 2 for k, v in params if k == "EIO"))
    # sid stays in session partitions, t is volatile only in this protocol.
    query = tuple((k, v) for k, v in params if k not in {"sid", "t"}) if socket else parsed.query
    return canonical, parsed.path, query, socket
