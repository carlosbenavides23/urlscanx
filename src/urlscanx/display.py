"""Safe, compact rendering of untrusted URLs and browser text."""

from __future__ import annotations

import hashlib
import re
from urllib.parse import quote, unquote_plus, urlsplit, urlunsplit

NETWORK_SCHEMES = {"http", "https", "ws", "wss"}
MAX_URL_CHARS = 16_384
MAX_NESTED_DEPTH = 2
MAX_DECODE_PASSES = 2
_LOW_ENTROPY_SECRET_NAMES = {
    "password", "passwd", "otp", "passcode", "pin", "code",
    "verificationcode", "authenticationcode", "cvc", "cvv", "pan",
    "cardnumber", "securitycode",
}
_SECRET_NAMES = {
    "accesskey", "accesstoken", "apikey", "auth", "authorization", "bearer",
    "clientsecret", "code", "idtoken", "jwt", "key", "password", "passwd",
    "refreshtoken", "secret", "session", "sessionid", "sig", "signature",
    "token", "xamzsignature", "xgoogsignature",
} | _LOW_ENTROPY_SECRET_NAMES
_URL_IN_TEXT = re.compile(r"(?:https?|wss?)://[^\s<>\"']+", re.IGNORECASE)
_NON_NETWORK_IN_TEXT = re.compile(r"\b(?:blob|data):[^\s<>\"']+", re.IGNORECASE)
_STATIC_SUFFIXES = (
    ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".webp", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".map",
)


def _name(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", unquote_plus(value).lower())


def _redacted(value: str, *, fingerprint: bool = True, semantic_name: str | None = None) -> str:
    # Semantic secrets override token shape and the caller's fingerprint preference.
    # Hashing a password/OTP/PIN/card secret enables dictionary reconstruction.
    if not fingerprint or (semantic_name is not None and _name(semantic_name) in _LOW_ENTROPY_SECRET_NAMES):
        return "[omitted]"
    digest = hashlib.sha256(unquote_plus(value).encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"[REDACTED sha256:{digest}]"


def _opaque(value: str) -> bool:
    """Conservatively hide long token-shaped strings, but retain ordinary hashes."""
    decoded = unquote_plus(value)
    if len(decoded) < 48 or decoded.lower().endswith(_STATIC_SUFFIXES) or re.fullmatch(r"[a-fA-F0-9]{32,128}", decoded):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9_~.=-]+", decoded))


def is_token_like(value: str) -> bool:
    """Shared policy for token-shaped query names/values, paths and identifiers."""
    decoded = unquote_plus(value)
    return bool(re.match(r"(?:gh[pousr]_|sk-)", decoded, re.IGNORECASE)
                or re.fullmatch(r"eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", decoded)
                or _opaque(value))


def mask_identifier(value: str, *, fingerprint: bool = True) -> str:
    return _redacted(value, fingerprint=fingerprint) if is_token_like(value) else value


def is_sensitive_name(value: str) -> bool:
    """Shared semantic policy for literals in derived static-code facts."""
    return _name(value) in _SECRET_NAMES


def _compact(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _decode_component(value: str) -> str:
    for _ in range(MAX_DECODE_PASSES):
        decoded = unquote_plus(value)
        if decoded == value:
            break
        value = decoded
    return value


def _component_name(value: str) -> str:
    # Do not feed bounded-decoded material back into the one-pass _name decoder.
    return re.sub(r"[^a-z0-9]", "", _decode_component(value).lower())


def _omit_assignments(value: str, names: set[str]) -> str:
    """Already decoded component; this helper never decodes or hashes a secret."""
    def replace(match):
        name = re.sub(r"[^a-z0-9]", "", match.group(2).lower())
        return match.group(1) + match.group(2) + "=[omitted]" if name in names else match.group(0)
    return re.sub(r"(^|[?&;])([^=?&;]+)=([^&;]*)", replace, value)


def _nested_url(value: str) -> str | None:
    # At most two decoding passes; no arbitrary decoder or URL discovery in prose.
    for _ in range(MAX_DECODE_PASSES):
        value = unquote_plus(value)
        if re.match(r"(?:https?|wss?)://", value, re.IGNORECASE):
            return value
    return None


def _query(value: str, *, fingerprint: bool = True, depth: int = 0, seen: frozenset = frozenset(),
           fragment_components: bool = False) -> str:
    rendered = []
    for part in value.split("&"):
        if not part:
            continue
        if fragment_components:
            decoded_part = _decode_component(part)
            if _omit_assignments(decoded_part, _LOW_ENTROPY_SECRET_NAMES) != decoded_part:
                # A fragment query component may itself encode the assignment.
                # Never pass its bounded-decoded secrets to a fingerprint helper.
                rendered.append(_omit_assignments(decoded_part, _SECRET_NAMES))
                continue
        key, separator, raw_value = part.partition("=")
        shown_key = _compact(mask_identifier(key, fingerprint=fingerprint), 50)
        if not separator:
            rendered.append(shown_key)
            continue
        decoded = unquote_plus(raw_value)
        nested_low_secret = any(_name(match.group(1)) in _LOW_ENTROPY_SECRET_NAMES
                                for match in re.finditer(r"([A-Za-z][A-Za-z0-9_-]*)=", decoded))
        nested = _nested_url(raw_value)
        if _name(key) in _SECRET_NAMES or nested_low_secret:
            shown = _redacted(raw_value, fingerprint=fingerprint and not nested_low_secret and nested is None,
                              semantic_name=key) if raw_value or _name(key) in _LOW_ENTROPY_SECRET_NAMES else ""
        elif nested is not None:
            # Never fingerprint an enclosing URL: it may contain a low-entropy secret.
            if depth >= MAX_NESTED_DEPTH or nested in seen:
                shown = "[omitted]"
            else:
                clean = _display_url(nested, MAX_URL_CHARS, fingerprint=fingerprint, depth=depth + 1, seen=seen)
                shown = raw_value if clean == nested else quote(clean, safe="[]:")
        elif is_token_like(raw_value) or len(decoded) > 80 or re.search(
            r"(?:token|secret|password|api[_-]?key|signature)=", decoded, re.IGNORECASE
        ):
            shown = _redacted(raw_value, fingerprint=fingerprint) if raw_value else ""
        else:
            shown = _compact(raw_value, 48)
        rendered.append(f"{shown_key}={shown}")
    return "&".join(rendered)


def _path(value: str, *, fingerprint: bool, depth: int, seen: frozenset) -> str:
    raw_segments = value.split("/")
    segments = raw_segments.copy()
    for index, segment in enumerate(raw_segments):
        if not segment:
            continue
        previous = _component_name(raw_segments[index - 1]) if index else ""
        webhook_token = index >= 2 and _component_name(raw_segments[index - 2]) == "webhooks"
        decoded = _decode_component(segment)
        omitted = _omit_assignments(decoded, _LOW_ENTROPY_SECRET_NAMES)
        if previous in _LOW_ENTROPY_SECRET_NAMES:
            segments[index] = "[omitted]"
        elif omitted != decoded:
            segments[index] = omitted
        elif "=" in segment:
            segments[index] = _query(segment, fingerprint=fingerprint, depth=depth, seen=seen)
        elif "=" in decoded:
            # Keep benign encoded paths exact. Encoded credential assignments are
            # omitted without another decoder/fingerprint pass.
            encoded_omitted = _omit_assignments(decoded, _SECRET_NAMES)
            segments[index] = encoded_omitted if encoded_omitted != decoded else segment
        elif webhook_token or previous in _SECRET_NAMES or is_token_like(segment):
            segments[index] = _redacted(segment, fingerprint=fingerprint, semantic_name=previous)
        else:
            segments[index] = _compact(segment, 72)
    return "/".join(segments)


def _display_url(value: str, limit: int, *, fingerprint: bool, depth: int, seen: frozenset) -> str:
    if len(value) > MAX_URL_CHARS:
        return "[oversized URL omitted]"
    seen = seen | {value}
    try:
        parsed = urlsplit(value)
        parsed.hostname  # Validate bracketed hosts before rendering.
        parsed.port
        if parsed.scheme.lower() in NETWORK_SCHEMES and not parsed.hostname:
            return "[invalid URL omitted]"
    except ValueError:
        return "[invalid URL omitted]"
    if parsed.scheme and parsed.scheme.lower() not in NETWORK_SCHEMES:
        return f"{parsed.scheme}:[omitted]"
    netloc = parsed.netloc
    if parsed.username is not None:
        # Userinfo can contain a password even when it looks token-like. Never hash it.
        netloc = f"[omitted]@{parsed.netloc.rsplit('@', 1)[-1]}"
    path = _path(parsed.path, fingerprint=fingerprint, depth=depth, seen=seen)
    query = _query(parsed.query, fingerprint=fingerprint, depth=depth, seen=seen)
    route, separator, fragment_query = parsed.fragment.partition("?")
    fragment = _path(route, fingerprint=fingerprint, depth=depth, seen=seen)
    if separator:
        fragment += "?" + _query(fragment_query, fingerprint=fingerprint, depth=depth, seen=seen, fragment_components=True)
    rendered = urlunsplit((parsed.scheme, netloc, path, query, fragment))
    if len(rendered) > limit and query:
        names = "&".join(f"{part.partition('=')[0]}=[…]" for part in query.split("&"))
        rendered = urlunsplit((parsed.scheme, netloc, path, names, fragment))
    return _compact(rendered, limit)


def display_url(value: str, limit: int = 240, *, fingerprint: bool = True) -> str:
    """Bounded, passive URL sanitization; nested URL depth never exceeds two."""
    return _display_url(value, limit, fingerprint=fingerprint, depth=0, seen=frozenset())


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
