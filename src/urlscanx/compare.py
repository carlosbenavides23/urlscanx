"""Technical overlap and differences between scans."""

from __future__ import annotations

from collections import Counter
from urllib.parse import urljoin

from .display import display_text, display_url, is_static_url
from .report import _section, external_endpoints, hostname, iocs, items, obj, parse_forms, requests, string, technologies


def submission_endpoints(result: dict, dom: bytes | str | None = None) -> list[str]:
    """Observed write requests and POST form destinations; intent is not inferred."""
    endpoints = {
        entry["url"] for entry in requests(result)
        if entry["method"].upper() in ("POST", "PUT", "PATCH") and hostname(entry["url"])
    }
    base_url = string(obj(result.get("page")).get("url"))
    for form in parse_forms(dom):
        if string(form.get("method")).upper() != "POST":
            continue
        action = string(form.get("action"))
        try:
            destination = urljoin(base_url, action) if base_url else action
        except ValueError:
            continue
        if hostname(destination):
            endpoints.add(destination)
    return sorted(endpoints)


def _page_host(result: dict) -> str:
    page = obj(result.get("page"))
    return hostname(string(page.get("url"))) or string(page.get("domain"))


def _page_resource(url: str, first: dict, second: dict) -> bool:
    host = hostname(url)
    for result in (first, second):
        page = obj(result.get("page"))
        apex = string(page.get("apexDomain"))
        if host and (host == _page_host(result) or apex and (host == apex or host.endswith("." + apex))):
            return True
    return False


def _static_urls(result: dict) -> set[str]:
    static_types = {"script", "stylesheet", "image", "font", "media"}
    return {entry["url"] for entry in requests(result) if entry["type"].lower() in static_types}


def _hash_urls(result: dict) -> dict[str, set[str]]:
    mapping: dict[str, set[str]] = {}
    for entry in items(obj(result.get("data")).get("requests")):
        entry = obj(entry)
        digest = string(obj(entry.get("response")).get("hash"))
        request = obj(entry.get("request"))
        url = string(request.get("url") or obj(request.get("request")).get("url"))
        if digest and url:
            mapping.setdefault(digest, set()).add(url)
    return mapping


def compare_results(first: dict, second: dict, first_dom: bytes | str | None = None, second_dom: bytes | str | None = None) -> dict:
    left, right = iocs(first), iocs(second)
    first_page, second_page = obj(first.get("page")), obj(second.get("page"))
    title_a, title_b = string(first_page.get("title")), string(second_page.get("title"))
    ip_a, ip_b = string(first_page.get("ip")), string(second_page.get("ip"))
    overlap = {key: sorted(set(left[key]) & set(right[key])) for key in ("domains", "ips", "urls", "hashes")}
    deltas = {
        side: {key: sorted(set(source[key]) - set(other[key])) for key in ("domains", "urls", "hashes")}
        for side, source, other in (("a", left, right), ("b", right, left))
    }
    external_a, external_b = set(external_endpoints(first)), set(external_endpoints(second))
    deltas["a"]["external_endpoints"] = sorted(external_a - external_b)
    deltas["b"]["external_endpoints"] = sorted(external_b - external_a)
    submissions_a = set(submission_endpoints(first, first_dom))
    submissions_b = set(submission_endpoints(second, second_dom))
    submissions = submissions_a | submissions_b
    static_urls = _static_urls(first) | _static_urls(second)

    def category(url: str) -> str:
        if url in submissions:
            return "submission"
        if _page_resource(url, first, second):
            return "page"
        if url in static_urls or is_static_url(url):
            return "external_static"
        return "other"

    url_categories = {key: [] for key in ("submission", "page", "external_static", "other")}
    for url in overlap["urls"]:
        url_categories[category(url)].append(url)

    submission_hosts = {hostname(url) for url in submissions}
    static_hosts = {hostname(url) for url in url_categories["external_static"]}
    domain_categories = {key: [] for key in ("submission", "page", "external_static", "other")}
    for domain in overlap["domains"]:
        if domain in submission_hosts:
            group = "submission"
        elif _page_resource("https://" + domain + "/", first, second):
            group = "page"
        elif domain in static_hosts:
            group = "external_static"
        else:
            group = "other"
        domain_categories[group].append(domain)

    hash_map_a, hash_map_b = _hash_urls(first), _hash_urls(second)
    hash_categories = {key: [] for key in ("submission", "page", "external_static", "other", "unmapped")}
    hash_context: dict[str, list[str]] = {}
    for digest in overlap["hashes"]:
        linked = sorted(hash_map_a.get(digest, set()) | hash_map_b.get(digest, set()))
        hash_context[digest] = linked
        groups = {category(url) for url in linked}
        group = next((name for name in ("submission", "page", "external_static", "other") if name in groups), "unmapped")
        hash_categories[group].append(digest)

    return {
        "shared_domains": overlap["domains"],
        "shared_ips": overlap["ips"],
        "shared_urls": overlap["urls"],
        "shared_hashes": overlap["hashes"],
        "shared_technologies": sorted(set(technologies(first)) & set(technologies(second))),
        "page_title_matches": bool(title_a and title_a == title_b),
        "main_ip_matches": bool(ip_a and ip_a == ip_b),
        "request_counts": (len(requests(first)), len(requests(second))),
        "shared_external_endpoints": sorted(external_a & external_b),
        "only_in_a": deltas["a"],
        "only_in_b": deltas["b"],
        "submission_only_in_a": sorted(submissions_a - submissions_b),
        "submission_only_in_b": sorted(submissions_b - submissions_a),
        "shared_url_categories": url_categories,
        "shared_domain_categories": domain_categories,
        "shared_hash_categories": hash_categories,
        "shared_hash_context": hash_context,
    }


def format_comparison(
    first: dict, second: dict, first_id: str, second_id: str,
    first_dom: bytes | str | None = None, second_dom: bytes | str | None = None,
    *, verbose: bool = False,
) -> str:
    result = compare_results(first, second, first_dom, second_dom)
    limit = None if verbose else 15
    lines = [
        f"urlscanx comparison: {first_id} vs {second_id}",
        f"Page title matches: {'yes' if result['page_title_matches'] else 'no'}",
        f"Main IP matches: {'yes' if result['main_ip_matches'] else 'no'}",
        f"Request counts: {result['request_counts'][0]} vs {result['request_counts'][1]}",
    ]
    if first_dom is None or second_dom is None:
        missing = ", ".join(side for side, dom in (("A", first_dom), ("B", second_dom)) if dom is None)
        lines.append(f"Form actions unavailable for scan {missing}; submission endpoints use observed requests where possible.")
    for side, key in (("A", "submission_only_in_a"), ("B", "submission_only_in_b")):
        if result[key]:
            lines.extend(_section(f"Submission endpoints only in scan {side}", [display_url(url) for url in result[key]], limit))

    for key, label in (
        ("submission", "Shared submission endpoints"),
        ("page", "Shared scan-page resources"),
        ("external_static", "Shared external static assets"),
        ("other", "Other shared URLs"),
    ):
        values = result["shared_url_categories"][key]
        if values:
            lines.extend(_section(label, [display_url(url) for url in values], limit))
    for key, label in (
        ("submission", "Shared submission domains"),
        ("page", "Shared scan-page domains"),
        ("external_static", "Shared external asset domains"),
        ("other", "Other shared domains"),
    ):
        values = result["shared_domain_categories"][key]
        if values:
            lines.extend(_section(label, values, limit))
    for key, label in (
        ("submission", "Shared hashes linked to submission endpoints"),
        ("page", "Shared hashes linked to scan-page resources"),
        ("external_static", "Shared hashes linked to external static assets"),
        ("other", "Shared hashes with other request context"),
        ("unmapped", "Shared hashes without request URL context"),
    ):
        values = [
            digest + (" <- " + display_url(result["shared_hash_context"][digest][0]) if result["shared_hash_context"][digest] else "")
            for digest in result["shared_hash_categories"][key]
        ]
        if values:
            lines.extend(_section(label, values, limit))

    for label, key in (
        ("Shared domains", "shared_domains"), ("Shared IPs", "shared_ips"),
        ("Shared URLs", "shared_urls"), ("Shared hashes", "shared_hashes"),
        ("Shared technologies", "shared_technologies"),
        ("Shared external endpoints", "shared_external_endpoints"),
    ):
        values = [display_url(value) for value in result[key]] if key in ("shared_urls", "shared_external_endpoints") else result[key]
        lines.extend(_section(label, values, limit))
    for side, heading in (("a", "Only in scan A"), ("b", "Only in scan B")):
        lines.append(f"{heading}:")
        shown = False
        for key, label in (("domains", "domains"), ("urls", "URLs"), ("hashes", "hashes"), ("external_endpoints", "external endpoints")):
            values = [display_url(value) for value in result[f"only_in_{side}"][key]] if key in ("urls", "external_endpoints") else result[f"only_in_{side}"][key]
            if values:
                lines.extend("  " + line for line in _section(label, values, limit))
                shown = True
        if not shown:
            lines.append("  -")
    return "\n".join(lines)


ARTIFACT_LABELS = {
    "domains": "domains", "ips": "IPs", "urls": "URLs", "hashes": "hashes",
    "technologies": "technologies", "external_endpoints": "external endpoints",
    "submission_endpoints": "submission endpoints",
}


def compare_many(results: list[dict], doms: list[bytes | str | None] | None = None) -> dict:
    """Count exact source values once per scan, retaining subset membership."""
    if len(results) < 3:
        raise ValueError("Multi-scan comparison requires at least three scans")
    doms = [None] * len(results) if doms is None else doms
    if len(doms) != len(results):
        raise ValueError("Expected one DOM entry per scan")
    per_scan = []
    for result, dom in zip(results, doms):
        artifacts = iocs(result)
        artifacts.update(
            technologies=technologies(result), external_endpoints=external_endpoints(result),
            submission_endpoints=submission_endpoints(result, dom),
        )
        per_scan.append({key: set(values) for key, values in artifacts.items()})

    shared: dict[int, dict[str, list[str]]] = {}
    unique = [{} for _ in results]
    presence = {}
    for key in ARTIFACT_LABELS:
        counts: Counter[str] = Counter()
        for artifacts in per_scan:
            counts.update(artifacts[key])
        presence[key] = {
            value: [index + 1 for index, artifacts in enumerate(per_scan) if value in artifacts[key]]
            for value in sorted(counts)
        }
        for value, count in sorted(counts.items()):
            if count >= 2:
                shared.setdefault(count, {}).setdefault(key, []).append(value)
        for index, artifacts in enumerate(per_scan):
            unique[index][key] = sorted(value for value in artifacts[key] if counts[value] == 1)
    return {"shared": shared, "unique": unique, "presence": presence}


def format_multi_comparison(
    results: list[dict], scan_ids: list[str], doms: list[bytes | str | None] | None = None,
    *, min_shared: int = 2, verbose: bool = False,
) -> str:
    total = len(results)
    if len(scan_ids) != total:
        raise ValueError("Expected one ID per scan")
    if not 2 <= min_shared <= total:
        raise ValueError("min_shared must be between 2 and the number of scans")
    doms = [None] * total if doms is None else doms
    comparison = compare_many(results, doms)
    limit = None if verbose else 15
    lines = [f"urlscanx comparison: {total} scans"]
    lines.extend(f"Scan {index}: {scan_id}" for index, scan_id in enumerate(scan_ids, 1))
    missing = ", ".join(str(index) for index, dom in enumerate(doms, 1) if dom is None)
    if missing:
        lines.append(f"Form actions unavailable for scans {missing}; submission endpoints use observed requests where possible.")

    def sections(artifacts: dict[str, list[str]], *, subset: bool = False) -> list[str]:
        output = []
        for key, label in ARTIFACT_LABELS.items():
            values = []
            for value in artifacts.get(key, []):
                rendered = display_url(value) if key in ("urls", "external_endpoints", "submission_endpoints") else display_text(value)
                if subset:
                    members = ", ".join(map(str, comparison["presence"][key][value]))
                    rendered += f" [scans {members}]"
                values.append(rendered)
            if values:
                output.extend("  " + line for line in _section(label, values, limit))
        return output or ["  -"]

    lines.append(f"Shared by all scans ({total}/{total}):")
    lines.extend(sections(comparison["shared"].get(total, {})))
    for count in sorted(comparison["shared"], reverse=True):
        if min_shared <= count < total:
            lines.append(f"Present in {count}/{total} scans:")
            lines.extend(sections(comparison["shared"][count], subset=True))
    lines.append("Per-scan unique artifacts:")
    for index, (scan_id, artifacts) in enumerate(zip(scan_ids, comparison["unique"]), 1):
        lines.append(f"Scan {index} ({scan_id}):")
        lines.extend(sections(artifacts))
    return "\n".join(lines)
