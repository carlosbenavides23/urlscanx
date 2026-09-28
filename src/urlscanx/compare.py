"""Technical overlap between two scans."""

from __future__ import annotations

from .report import _section, external_endpoints, iocs, obj, requests, string, technologies


def compare_results(first: dict, second: dict) -> dict:
    left, right = iocs(first), iocs(second)
    first_page, second_page = obj(first.get("page")), obj(second.get("page"))
    title_a, title_b = string(first_page.get("title")), string(second_page.get("title"))
    ip_a, ip_b = string(first_page.get("ip")), string(second_page.get("ip"))
    return {
        "shared_domains": sorted(set(left["domains"]) & set(right["domains"])),
        "shared_ips": sorted(set(left["ips"]) & set(right["ips"])),
        "shared_urls": sorted(set(left["urls"]) & set(right["urls"])),
        "shared_hashes": sorted(set(left["hashes"]) & set(right["hashes"])),
        "shared_technologies": sorted(set(technologies(first)) & set(technologies(second))),
        "page_title_matches": bool(title_a and title_a == title_b),
        "main_ip_matches": bool(ip_a and ip_a == ip_b),
        "request_counts": (len(requests(first)), len(requests(second))),
        "shared_external_endpoints": sorted(set(external_endpoints(first)) & set(external_endpoints(second))),
    }


def format_comparison(first: dict, second: dict, first_id: str, second_id: str) -> str:
    result = compare_results(first, second)
    lines = [f"urlscanx comparison: {first_id} vs {second_id}"]
    for label, key in (
        ("Shared domains", "shared_domains"), ("Shared IPs", "shared_ips"),
        ("Shared URLs", "shared_urls"), ("Shared hashes", "shared_hashes"),
        ("Shared technologies", "shared_technologies"),
    ):
        lines.extend(_section(label, result[key]))
    lines.extend([
        f"Page title matches: {'yes' if result['page_title_matches'] else 'no'}",
        f"Main IP matches: {'yes' if result['main_ip_matches'] else 'no'}",
        f"Request counts: {result['request_counts'][0]} vs {result['request_counts'][1]}",
    ])
    lines.extend(_section("Shared external endpoints", result["shared_external_endpoints"]))
    return "\n".join(lines)
