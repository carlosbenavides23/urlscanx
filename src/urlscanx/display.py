"""Safe, compact rendering of untrusted URLs and browser text."""

from __future__ import annotations

import hashlib
import re
from urllib.parse import unquote_plus, urlsplit, urlunsplit

NETWORK_SCHEMES = {"http", "https", "ws", "wss"}
_SECRET_NAMES = {
    "accesskey", "accesstoken", "apikey", "auth", "authorization", "bearer",
    "clientsecret", "code", "idtoken", "jwt", "key", "password", "passwd",
    "refreshtoken", "secret", "session", "sessionid", "sig", "signature",
    "token", "xamzsignature", "xgoogsignature",
}
_URL_IN_TEXT = re.compile(r"(?:https?|wss?)://[^\s<>\"']+", re.IGNORECASE)
_NON_NETWORK_IN_TEXT = re.compile(r"\b(?:blob|data):[^\s<>\"']+", re.IGNORECASE)
_STATIC_SUFFIXES = (
    ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".webp", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".map",
)


def _name(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", unquote_plus(value).lower())


def _redacted(value: str) -> str:
    digest = hashlib.sha256(unquote_plus(value).encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"[REDACTED sha256:{digest}]"


def _opaque(value: str) -> bool:
    """Conservatively hide long token-shaped strings, but retain ordinary hashes."""
    decoded = unquote_plus(value)
    if len(decoded) < 48 or decoded.lower().endswith(_STATIC_SUFFIXES) or re.fullmatch(r"[a-fA-F0-9]{32,128}", decoded):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9_~.=-]+", decoded))


def _compact(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _query(value: str) -> str:
    rendered = []
    for part in value.split("&"):
        if not part:
            continue
        key, separator, raw_value = part.partition("=")
        if not separator:
            rendered.append(_redacted(key) if _opaque(key) or re.match(r"(?:gh[pousr]_|sk-)", key, re.IGNORECASE) else _compact(key, 50))
            continue
        decoded = unquote_plus(raw_value)
        if _name(key) in _SECRET_NAMES or _opaque(raw_value) or len(decoded) > 80 or re.search(
            r"(?:token|secret|password|api[_-]?key|signature)=", decoded, re.IGNORECASE
        ):
            shown = _redacted(raw_value) if raw_value else ""
        else:
            shown = _compact(raw_value, 48)
        rendered.append(f"{_compact(key, 50)}={shown}")
    return "&".join(rendered)


def display_url(value: str, limit: int = 240) -> str:
    """Preserve host, route shape, and parameter names without printing likely credentials."""
    try:
        parsed = urlsplit(value)
        parsed.hostname  # Validate bracketed hosts before rendering.
    except ValueError:
        return "[invalid URL omitted]"
    if parsed.scheme and parsed.scheme.lower() not in NETWORK_SCHEMES:
        return f"{parsed.scheme}:[omitted]"
    netloc = parsed.netloc
    if parsed.username is not None:
        # URL userinfo can itself be a reusable credential.
        netloc = f"{_redacted(parsed.netloc.split('@', 1)[0])}@{parsed.netloc.rsplit('@', 1)[-1]}"
    segments = parsed.path.split("/")
    for index, segment in enumerate(segments):
        if not segment:
            continue
        previous = _name(segments[index - 1]) if index else ""
        webhook_token = index >= 2 and _name(segments[index - 2]) == "webhooks"
        if webhook_token or previous in _SECRET_NAMES or _opaque(segment):
            segments[index] = _redacted(segment)
        else:
            segments[index] = _compact(segment, 72)
    path = "/".join(segments)
    query = _query(parsed.query)
    fragment = _query(parsed.fragment) if "=" in parsed.fragment else (_redacted(parsed.fragment) if _opaque(parsed.fragment) else _compact(parsed.fragment, 50))
    rendered = urlunsplit((parsed.scheme, netloc, path, query, fragment))
    if len(rendered) > limit and query:
        names = "&".join(f"{part.partition('=')[0]}=[…]" for part in query.split("&"))
        rendered = urlunsplit((parsed.scheme, netloc, path, names, fragment))
    return _compact(rendered, limit)


def display_text(value: str, limit: int | None = 220) -> str:
    """Sanitize URLs embedded in free text, then bound terminal line length."""
    flattened = " ".join(value.split())
    flattened = _NON_NETWORK_IN_TEXT.sub(lambda match: match.group(0).split(":", 1)[0] + ":[omitted]", flattened)
    rendered = _URL_IN_TEXT.sub(lambda match: display_url(match.group(0)), flattened)
    return _compact(rendered, limit) if limit is not None else rendered


def is_static_url(value: str) -> bool:
    try:
        return urlsplit(value).path.lower().endswith(_STATIC_SUFFIXES)
    except ValueError:
        return False
