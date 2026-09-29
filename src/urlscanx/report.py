"""Compact views over the flexible urlscan Result API schema."""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urlsplit

from .display import NETWORK_SCHEMES, display_text, display_url


def obj(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def items(value: object) -> list:
    return value if isinstance(value, list) else []


def string(value: object) -> str:
    return str(value) if isinstance(value, (str, int, float)) else ""


def unique(values: object) -> list[str]:
    return sorted({string(value) for value in items(values) if string(value)})


def hostname(value: str) -> str:
    try:
        return urlsplit(value).hostname or ""
    except ValueError:
        return ""


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, object]] = []
        self._stack: list[dict[str, object]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "form":
            form: dict[str, object] = {
                "method": values.get("method", "get").upper(),
                "action": values.get("action", ""),
                "name": values.get("name", ""),
                "id": values.get("id", ""),
                "inputs": [],
            }
            self.forms.append(form)
            self._stack.append(form)
        elif tag.lower() in ("input", "textarea", "select", "button") and self._stack:
            field = {
                "tag": tag.lower(),
                "name": values.get("name", ""),
                "type": values.get("type", "") or ("textarea" if tag.lower() == "textarea" else ""),
                "id": values.get("id", ""),
                "autocomplete": values.get("autocomplete", ""),
                "hidden": "hidden" in values,
            }
            inputs = self._stack[-1]["inputs"]
            if isinstance(inputs, list):
                inputs.append(field)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._stack:
            self._stack.pop()


def parse_forms(dom: bytes | str | None) -> list[dict[str, object]]:
    if dom is None:
        return []
    try:
        text = dom.decode("utf-8", errors="replace") if isinstance(dom, bytes) else dom
        parser = _FormParser()
        parser.feed(text)
        return parser.forms
    except (UnicodeError, ValueError):
        return []


def observed_urls(result: dict) -> set[str]:
    lists = obj(result.get("lists"))
    task = obj(result.get("task"))
    page = obj(result.get("page"))
    request_entries = items(obj(result.get("data")).get("requests"))
    urls = set(unique(lists.get("urls")))
    for value in (task.get("url"), page.get("url")):
        if isinstance(value, str) and value:
            urls.add(value)
    for entry in request_entries:
        request = obj(obj(entry).get("request"))
        for value in (request.get("url"), obj(request.get("request")).get("url")):
            if isinstance(value, str) and value:
                urls.add(value)
    return urls


def _network_url(value: str) -> bool:
    try:
        return urlsplit(value).scheme.lower() in NETWORK_SCHEMES and bool(hostname(value))
    except ValueError:
        return False


def non_network_schemes(result: dict) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in observed_urls(result):
        try:
            scheme = urlsplit(value).scheme.lower()
        except ValueError:
            continue
        if scheme and scheme not in NETWORK_SCHEMES:
            counts[scheme] = counts.get(scheme, 0) + 1
    return counts


def iocs(result: dict) -> dict[str, list[str]]:
    lists = obj(result.get("lists"))
    page = obj(result.get("page"))
    request_entries = items(obj(result.get("data")).get("requests"))
    domains = set(unique(lists.get("domains")))
    ips = set(unique(lists.get("ips")))
    urls = {value for value in observed_urls(result) if _network_url(value)}
    hashes = set(unique(lists.get("hashes")))
    downloads = obj(obj(obj(result.get("meta")).get("processors")).get("download"))
    for download in items(downloads.get("data")):
        digest = string(obj(download).get("sha256"))
        if digest:
            hashes.add(digest)
    for entry in request_entries:
        request = obj(obj(entry).get("request"))
        response = obj(obj(entry).get("response"))
        ip = response.get("remoteIPAddress") or obj(response.get("response")).get("remoteIPAddress")
        if isinstance(ip, str) and ip:
            ips.add(ip)
        digest = string(response.get("hash"))
        if digest:
            hashes.add(digest)
    if isinstance(page.get("ip"), str) and page["ip"]:
        ips.add(page["ip"])
    for url in urls:
        host = hostname(url) if "://" in url else ""
        if host:
            domains.add(host)
    return {"domains": sorted(domains), "ips": sorted(ips), "urls": sorted(urls), "hashes": sorted(hashes)}


def requests(result: dict) -> list[dict[str, str]]:
    output = []
    for entry in items(obj(result.get("data")).get("requests")):
        entry = obj(entry)
        request = obj(entry.get("request"))
        nested = obj(request.get("request"))
        response = obj(entry.get("response"))
        response_data = obj(response.get("response"))
        url = string(request.get("url") or nested.get("url"))
        if not url:
            continue
        output.append({
            "method": string(request.get("method") or nested.get("method") or "GET"),
            "status": string(response.get("status") or response_data.get("status") or "-"),
            "type": string(entry.get("type") or request.get("type") or response.get("type") or "-"),
            "url": url,
            "frame_id": string(request.get("frameId") or nested.get("frameId") or entry.get("frameId")),
            "document_url": string(request.get("documentURL") or nested.get("documentURL")),
            "primary": "yes" if request.get("primaryRequest") or nested.get("primaryRequest") or entry.get("primaryRequest") else "",
        })
    return output


def frames(result: dict) -> list[dict[str, object]]:
    """Use explicit frame records when present, then request frame IDs as a fallback."""
    data = obj(result.get("data"))
    page_url = string(obj(result.get("page")).get("url"))
    records = items(data.get("frames")) or items(result.get("frames"))
    found: dict[str, dict[str, object]] = {}
    main_id = ""
    for record in records:
        record = obj(record)
        frame_id = string(record.get("id") or record.get("frameId"))
        if not frame_id:
            continue
        parent = string(record.get("parentId") or record.get("parentFrameId"))
        explicit_main = record.get("isMainFrame") is True or record.get("main") is True
        if explicit_main or ("parentId" in record or "parentFrameId" in record) and not parent:
            main_id = frame_id
        found[frame_id] = {
            "id": frame_id,
            "url": string(record.get("url") or record.get("documentURL")),
            "parent": parent,
            "requests": 0,
        }
        if string(record.get("url") or record.get("documentURL")) == page_url and page_url:
            main_id = frame_id
    for entry in requests(result):
        frame_id = entry["frame_id"]
        if not frame_id:
            continue
        frame = found.setdefault(frame_id, {"id": frame_id, "url": "", "parent": "", "requests": 0})
        frame["requests"] = int(frame["requests"]) + 1
        if entry["primary"] or (entry["type"].lower() == "document" and entry["url"] == page_url):
            main_id = frame_id
        if entry["type"].lower() == "document":
            frame["url"] = entry["url"]
        elif not frame["url"] and entry["document_url"]:
            frame["url"] = entry["document_url"]
    if not found and page_url:
        return [{"id": "", "role": "main", "url": page_url, "requests": 0}]
    if not main_id and len(found) == 1:
        main_id = next(iter(found))
    ordered = sorted(found.values(), key=lambda frame: (frame["id"] != main_id, string(frame["url"]), string(frame["id"])))
    child_number = 0
    for frame in ordered:
        if frame["id"] == main_id:
            frame["role"] = "main"
        elif main_id or frame["parent"]:
            child_number += 1
            frame["role"] = f"child {child_number}"
        else:
            frame["role"] = "frame"
    return ordered


def technologies(result: dict) -> list[str]:
    data = obj(obj(obj(result.get("meta")).get("processors")).get("wappa")).get("data")
    names = []
    for entry in items(data):
        if isinstance(entry, str):
            names.append(entry)
        elif isinstance(entry, dict):
            names.append(string(entry.get("app") or entry.get("name")))
    return sorted({name for name in names if name})


def external_endpoints(result: dict) -> list[str]:
    page = obj(result.get("page"))
    main_host = hostname(string(page.get("url")))
    if not main_host:
        return []
    return sorted({
        entry["url"] for entry in requests(result)
        if hostname(entry["url"])
        and hostname(entry["url"]) != main_host
    })


def _section(title: str, values: list[str], limit: int | None = None) -> list[str]:
    shown = values[:limit] if limit is not None else values
    lines = [f"{title} ({len(values)}):"] + ([f"  {value}" for value in shown] if shown else ["  -"])
    if len(shown) < len(values):
        lines.append(f"  ... {len(values) - len(shown)} more")
    return lines


def format_iocs(result: dict) -> str:
    indicators = iocs(result)
    lines = []
    for key in ("domains", "ips", "urls", "hashes"):
        values = [display_url(value) for value in indicators[key]] if key == "urls" else indicators[key]
        lines.extend(_section(key.title(), values))
    return "\n".join(lines)


def format_requests(result: dict, limit: int | None = None) -> str:
    entries = requests(result)
    frame_roles = {string(frame["id"]): string(frame["role"]) for frame in frames(result) if frame["id"]}
    return "\n".join(_section("HTTP requests", [
        f"{entry['method']} {entry['status']} [{entry['type']}] {display_url(entry['url'])}"
        + (f" [frame: {frame_roles.get(entry['frame_id'], entry['frame_id'][:8])}]" if entry["frame_id"] else "")
        for entry in entries
    ], limit))


def _format_redirect(value: object) -> str:
    if isinstance(value, str):
        return display_text(value)
    entry = obj(value)
    source = string(entry.get("from") or entry.get("source") or entry.get("url"))
    target = string(entry.get("to") or entry.get("target") or entry.get("location"))
    status = string(entry.get("status") or entry.get("statusCode"))
    if source and target:
        return f"{display_url(source)} -> {display_url(target)}" + (f" ({status})" if status else "")
    return display_url(target or source) if target or source else display_text(string(value))


def _credential_field(field: dict) -> bool:
    kind = string(field.get("type")).lower()
    name = (string(field.get("name")) + " " + string(field.get("id")) + " " + string(field.get("autocomplete"))).lower()
    return kind in ("password", "email") or any(
        word in name for word in ("username", "user_name", "login", "email", "passwd", "password", "otp", "one-time-code", "verification")
    )


def format_report(result: dict, scan_id: str, dom: bytes | str | None = None, *, verbose: bool = False) -> str:
    task = obj(result.get("task"))
    page = obj(result.get("page"))
    data = obj(result.get("data"))
    verdicts = obj(result.get("verdicts"))
    verdict = obj(verdicts.get("overall")) or obj(verdicts.get("urlscan"))
    brands = []
    for value in items(verdict.get("brands") or obj(verdicts.get("urlscan")).get("brands")):
        name = string(obj(value).get("name") or obj(value).get("key")) if isinstance(value, dict) else string(value)
        if name:
            brands.append(name)
    indicators = iocs(result)
    lines = [
        "urlscanx report",
        f"Scan UUID: {scan_id}",
        f"Submitted URL: {display_url(string(task.get('url'))) or '-'}",
        f"Final URL: {display_url(string(page.get('url'))) or '-'}",
        f"Page title: {display_text(string(page.get('title'))) or '-'}",
        f"Submission time: {string(task.get('time')) or '-'}",
        f"Verdict: {('malicious' if verdict.get('malicious') else 'not flagged') if isinstance(verdict.get('malicious'), bool) else '-'}"
        + (f" (score {verdict['score']})" if isinstance(verdict.get('score'), (int, float)) else ""),
        f"Targeted brands: {display_text(', '.join(sorted(set(brands)))) or '-'}",
        f"Main IP: {string(page.get('ip')) or '-'}",
        f"ASN: {string(page.get('asn')) or '-'}",
        f"Country: {string(page.get('country')) or '-'}",
    ]
    lines.extend(_section("Technologies", [display_text(value) for value in technologies(result)], 30))
    for label, key in (("Contacted domains", "domains"), ("Contacted IPs", "ips"), ("URLs", "urls"), ("Hashes", "hashes")):
        values = [display_url(value) for value in indicators[key]] if key == "urls" else indicators[key]
        lines.extend(_section(label, values, 30))
    schemes = non_network_schemes(result)
    lines.extend(_section("Non-network URL schemes", [f"{scheme}: {count}" for scheme, count in sorted(schemes.items())], 10))
    links = sorted({string(obj(entry).get("href") or obj(entry).get("url")) for entry in items(data.get("links")) if string(obj(entry).get("href") or obj(entry).get("url"))})
    lines.extend(_section("Outgoing links", [display_url(value) for value in links], 30))
    known_frames = frames(result)
    frame_lines = [
        f"{frame['role']}: {display_url(string(frame['url'])) or '(URL unavailable)'}"
        + (f" ({frame['requests']} requests)" if frame["requests"] else "")
        for frame in known_frames
    ]
    lines.extend(_section("Frames", frame_lines, 20))
    if known_frames and not known_frames[0]["id"]:
        lines.append("  Child-frame detail unavailable in Result API data.")
    lines.extend(format_requests(result, 30).splitlines())
    xhr = [entry["url"] for entry in requests(result) if entry["type"].lower() in ("xhr", "fetch")]
    lines.extend(_section("XHR/fetch endpoints", [display_url(value) for value in sorted(set(xhr))], 30))

    globals_ = []
    for entry in items(data.get("globals")):
        if isinstance(entry, dict):
            prop = string(entry.get("prop") or entry.get("name"))
            kind = string(entry.get("type"))
            if prop:
                globals_.append(f"{kind}| {prop}" if kind else prop)
        elif isinstance(entry, str):
            globals_.append(entry)
    lines.extend(_section("JavaScript globals", [display_text(value) for value in sorted(set(globals_))], 30))

    redirects = [_format_redirect(value) for value in items(data.get("redirects"))]
    lines.extend(_section("Redirects", [value for value in redirects if value], 30))
    lines.extend(_section("Identifiers", [display_text(value) for value in unique(data.get("identifiers"))], 30))

    forms = parse_forms(dom)
    form_lines = []
    credential_lines = []
    other_field_lines = []
    for index, form in enumerate(forms, 1):
        method = string(form.get("method")) or "GET"
        action = display_url(string(form.get("action"))) or "(current URL)"
        name = string(form.get("name")) or string(form.get("id"))
        suffix = f" [{name}]" if name else ""
        form_lines.append(f"{index}. {method} {action}{suffix}")
        for field in items(form.get("inputs")):
            field = obj(field)
            kind = string(field.get("type")) or string(field.get("tag")) or "field"
            if kind.lower() in ("button", "submit", "reset", "image") or string(field.get("tag")) == "button":
                continue
            label = display_text(string(field.get("name")) or string(field.get("id"))) or "(unnamed)"
            extras = []
            if field.get("hidden") or kind.lower() == "hidden":
                extras.append("hidden")
            if string(field.get("id")) and string(field.get("id")) != label:
                extras.append(f"id={string(field.get('id'))}")
            if string(field.get("autocomplete")):
                extras.append(f"autocomplete={string(field.get('autocomplete'))}")
            rendered = f"form {index}: {label} ({kind})" + (f" [{', '.join(extras)}]" if extras else "")
            (credential_lines if _credential_field(field) else other_field_lines).append(rendered)
    lines.extend(_section("Forms", form_lines, 30))
    field_count = len(credential_lines) + len(other_field_lines)
    lines.append(f"Form input fields ({field_count}):")
    if credential_lines:
        lines.append("  Credentials:")
        lines.extend(f"    {value}" for value in credential_lines[:25])
    if other_field_lines:
        lines.append("  Other:")
        lines.extend(f"    {value}" for value in other_field_lines[:25])
    if not field_count:
        lines.append("  -")
    shown_fields = min(len(credential_lines), 25) + min(len(other_field_lines), 25)
    if field_count > shown_fields:
        lines.append(f"  ... {field_count - shown_fields} more")
    if dom is None:
        lines.append("Form analysis note: DOM snapshot unavailable or not requested.")

    cookies = []
    for cookie in items(data.get("cookies")):
        cookie = obj(cookie)
        value = obj(cookie.get("cookie")) or cookie
        name = string(value.get("name"))
        if name:
            cookies.append(f"{name} ({string(value.get('domain')) or 'unknown domain'})")
    lines.extend(_section("Cookies", cookies, 30))
    console: list[tuple[str, str, str]] = []
    for message in items(data.get("console")):
        message = obj(message)
        details = obj(message.get("message")) or message
        body = string(details.get("text"))
        if body:
            console.append((string(details.get("level")) or "log", body, string(details.get("url"))))
    if verbose:
        selected = console
    else:
        noise = ("webgpu", "canvas2d", "gpu process", "software webgl")
        selected = [
            entry for entry in console
            if entry[0].lower() in ("error", "warning", "warn")
            and not any(term in entry[1].lower() for term in noise)
        ]
        selected = list(dict.fromkeys(selected))
    rendered_console = [
        f"{level}: {display_text(body, None if verbose else 200)}"
        + (f" [{display_url(url)}]" if url else "")
        for level, body, url in selected
    ]
    lines.extend(_section("Console messages", rendered_console, None if verbose else 10))
    if not verbose and len(console) > len(selected):
        lines.append(f"  {len(console) - len(selected)} lower-priority or repeated messages hidden; use --verbose.")
    return "\n".join(lines)
