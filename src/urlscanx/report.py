"""Compact views over the flexible urlscan Result API schema."""

from __future__ import annotations

from urllib.parse import urlsplit


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


def iocs(result: dict) -> dict[str, list[str]]:
    lists = obj(result.get("lists"))
    task = obj(result.get("task"))
    page = obj(result.get("page"))
    requests = items(obj(result.get("data")).get("requests"))
    domains = set(unique(lists.get("domains")))
    ips = set(unique(lists.get("ips")))
    urls = set(unique(lists.get("urls")))
    hashes = set(unique(lists.get("hashes")))
    downloads = obj(obj(obj(result.get("meta")).get("processors")).get("download"))
    for download in items(downloads.get("data")):
        digest = string(obj(download).get("sha256"))
        if digest:
            hashes.add(digest)
    for value in (task.get("url"), page.get("url")):
        if isinstance(value, str) and value:
            urls.add(value)
    for entry in requests:
        request = obj(obj(entry).get("request"))
        response = obj(obj(entry).get("response"))
        for value in (request.get("url"), obj(request.get("request")).get("url")):
            if isinstance(value, str) and value:
                urls.add(value)
        ip = response.get("remoteIPAddress") or obj(response.get("response")).get("remoteIPAddress")
        if isinstance(ip, str) and ip:
            ips.add(ip)
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
            "type": string(entry.get("type") or request.get("type") or "-"),
            "url": url,
        })
    return output


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
        lines.extend(_section(key.title(), indicators[key]))
    return "\n".join(lines)


def format_requests(result: dict, limit: int | None = None) -> str:
    entries = requests(result)
    return "\n".join(_section("HTTP requests", [
        f"{entry['method']} {entry['status']} [{entry['type']}] {entry['url']}" for entry in entries
    ], limit))


def format_report(result: dict, scan_id: str) -> str:
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
        f"Submitted URL: {string(task.get('url')) or '-'}",
        f"Final URL: {string(page.get('url')) or '-'}",
        f"Page title: {string(page.get('title')) or '-'}",
        f"Submission time: {string(task.get('time')) or '-'}",
        f"Verdict: {('malicious' if verdict.get('malicious') else 'not flagged') if isinstance(verdict.get('malicious'), bool) else '-'}"
        + (f" (score {verdict['score']})" if isinstance(verdict.get('score'), (int, float)) else ""),
        f"Targeted brands: {', '.join(sorted(set(brands))) or '-'}",
        f"Main IP: {string(page.get('ip')) or '-'}",
        f"ASN: {string(page.get('asn')) or '-'}",
        f"Country: {string(page.get('country')) or '-'}",
    ]
    lines.extend(_section("Technologies", technologies(result), 30))
    for label, key in (("Contacted domains", "domains"), ("Contacted IPs", "ips"), ("URLs", "urls"), ("Hashes", "hashes")):
        lines.extend(_section(label, indicators[key], 30))
    links = sorted({string(obj(entry).get("href") or obj(entry).get("url")) for entry in items(data.get("links")) if string(obj(entry).get("href") or obj(entry).get("url"))})
    lines.extend(_section("Outgoing links", links, 30))
    lines.extend(format_requests(result, 30).splitlines())
    xhr = [entry["url"] for entry in requests(result) if entry["type"].lower() in ("xhr", "fetch")]
    lines.extend(_section("XHR/fetch endpoints", sorted(set(xhr)), 30))
    forms = items(data.get("forms"))
    lines.extend(_section("Forms", [string(obj(form).get("action") or obj(form).get("url")) or "(no action)" for form in forms], 30))
    fields = []
    for form in forms:
        for field in items(obj(form).get("inputs") or obj(form).get("fields")):
            field = obj(field)
            fields.append(" ".join(part for part in (string(field.get("name")), string(field.get("type"))) if part) or "(unnamed)")
    lines.extend(_section("Form input fields", fields, 30))
    cookies = []
    for cookie in items(data.get("cookies")):
        cookie = obj(cookie)
        value = obj(cookie.get("cookie")) or cookie
        name = string(value.get("name"))
        if name:
            cookies.append(f"{name} ({string(value.get('domain')) or 'unknown domain'})")
    lines.extend(_section("Cookies", cookies, 30))
    console = []
    for message in items(data.get("console")):
        message = obj(message)
        details = obj(message.get("message")) or message
        text = string(details.get("text"))
        if text:
            console.append(f"{string(details.get('level')) or 'log'}: {text}")
    lines.extend(_section("Console messages", console, 30))
    return "\n".join(lines)
