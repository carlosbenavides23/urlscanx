"""Small client for the documented urlscan Result, DOM, and screenshot endpoints."""

from __future__ import annotations

import gzip
import json
import os
import re
import socket
import zlib
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

from . import __version__

BASE = "https://urlscan.io"
UUID_PATTERN = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


class ScanError(Exception):
    """A short, user-facing input or API failure."""

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def parse_scan(value: str) -> str:
    """Accept a UUID or exact urlscan result URL; reject other destinations."""
    if UUID_PATTERN.fullmatch(value):
        return value.lower()
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "urlscan.io"
            or parsed.port is not None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError
    except ValueError as exc:
        raise ScanError("Expected a scan UUID or https://urlscan.io/result/<UUID>/.", 2) from exc
    match = re.fullmatch(r"/result/(" + UUID_PATTERN.pattern + r")/?", parsed.path)
    if not match:
        raise ScanError("Expected a scan UUID or https://urlscan.io/result/<UUID>/.", 2)
    return match.group(1).lower()


def api_key() -> str:
    key = os.environ.get("URLSCAN_API_KEY", "").strip()
    if not key:
        raise ScanError("URLSCAN_API_KEY is missing. Set it in your environment.", 2)
    return key


class _ArtifactRedirectHandler(HTTPRedirectHandler):
    """Analysis retrieval never follows a redirect to a target or another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            parsed = urlsplit(newurl)
            previous = urlsplit(req.full_url)
            allowed = (parsed.scheme == "https" and parsed.hostname == "urlscan.io"
                       and parsed.port in (None, 443) and parsed.username is None
                       and parsed.password is None and not parsed.query and not parsed.fragment
                       and parsed.path.rstrip("/") == previous.path.rstrip("/"))
        except ValueError:
            allowed = False
        if not allowed:
            raise ScanError("urlscan artifact redirect outside the permitted host was blocked.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _get(path: str, key: str, *, allow_not_found: bool = False, artifact_only: bool = False) -> bytes | None:
    request = Request(
        f"{BASE}{path}",
        headers={
            "api-key": key,
            "User-Agent": f"urlscanx/{__version__}",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
        },
    )
    opener = build_opener(_ArtifactRedirectHandler()).open if artifact_only else urlopen
    for attempt in range(3):
        try:
            with opener(request, timeout=20) as response:
                raw = response.read()
                encoding = response.headers.get("Content-Encoding", "").strip().lower()
                if encoding in ("", "identity"):
                    return raw
                if encoding == "gzip":
                    try:
                        return gzip.decompress(raw)
                    except OSError as exc:
                        raise ScanError("urlscan returned invalid gzip-compressed data.") from exc
                if encoding == "deflate":
                    try:
                        return zlib.decompress(raw)
                    except zlib.error as exc:
                        raise ScanError("urlscan returned invalid deflate-compressed data.") from exc
                raise ScanError(f"urlscan returned unsupported content encoding: {encoding}.")
        except HTTPError as exc:
            if exc.code == 404 and allow_not_found:
                return None
            if exc.code in (429, 500, 502, 503, 504) and attempt < 2:
                time.sleep(2**attempt)
                continue
            messages = {
                401: "Authentication failed (HTTP 401). Check URLSCAN_API_KEY.",
                403: "Access denied (HTTP 403). Check scan visibility and API key.",
                404: "Scan or asset unavailable (HTTP 404). The scan may still be processing.",
                410: "Scan has been deleted (HTTP 410).",
                429: "urlscan rate limit reached (HTTP 429). Try again later.",
            }
            raise ScanError(messages.get(exc.code, f"urlscan request failed (HTTP {exc.code}).")) from exc
        except (TimeoutError, socket.timeout) as exc:
            raise ScanError("urlscan request timed out. Try again.") from exc
        except URLError as exc:
            raise ScanError("Could not connect to urlscan.io. Check your connection.") from exc
    raise ScanError("urlscan request failed. Try again.")


def fetch_result(scan_id: str, key: str, *, artifact_only: bool = False) -> dict:
    raw = _get(f"/api/v1/result/{scan_id}/", key, artifact_only=artifact_only)
    assert raw is not None
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ScanError("urlscan returned invalid JSON.") from exc
    if not isinstance(data, dict) or not isinstance(data.get("task"), dict):
        raise ScanError("urlscan returned an unexpected result format.")
    return data


def fetch_asset(scan_id: str, kind: str, key: str, *, optional: bool = False, artifact_only: bool = False) -> bytes | None:
    if kind == "dom":
        return _get(f"/dom/{scan_id}/", key, allow_not_found=optional, artifact_only=artifact_only)
    if kind == "screenshot":
        return _get(f"/screenshots/{scan_id}.png", key, allow_not_found=optional, artifact_only=artifact_only)
    raise ValueError("Unknown asset kind")
