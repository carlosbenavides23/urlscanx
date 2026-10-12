"""Bounded presentation signals, never provider ownership or impersonation."""

import re
from urllib.parse import urljoin, urlsplit

from .adapters import MAX_ENTRIES, label, mapping, origin_url, safe_url

# Recognition vocabulary only. No domains, ownership, trust or reputation mapping.
BRANDS = {
    "Microsoft": ("microsoft",), "OneDrive": ("onedrive",),
    "BAC Credomatic": ("bac credomatic", "baccredomatic"),
    "PayPal": ("paypal",), "Stripe": ("stripe",), "Discord": ("discord",),
    "Intercom": ("intercom",), "ShareGate": ("sharegate",), "Akamai": ("akamai",),
    "Solana Beach": ("solana beach",), "Visa": ("visa",), "MasterCard": ("mastercard",),
    "American Express": ("american express",), "UnionPay": ("unionpay",), "JCB": ("jcb",),
    "Link": ("link",),
}
AMBIGUOUS_BRANDS = frozenset({"Stripe", "Discord", "Intercom", "Visa", "MasterCard", "JCB", "Link"})


def candidates(value: str, *, title_or_logo: bool = False) -> list[str]:
    words = " ".join(value[:1000].lower().split())
    found = []
    for brand, aliases in BRANDS.items():
        if brand in AMBIGUOUS_BRANDS:
            matched = title_or_logo and words in aliases
        else:
            matched = any(re.search(r"(?<!\w)" + re.escape(alias) + r"(?!\w)", words) for alias in aliases)
        if matched:
            found.append(brand)
    return found


def inventory(result: object, parser: object | None, document_url: str | None, registry: object,
              document_ref: str | None = None) -> None:
    output = registry.analysis
    seen = set()
    evidence = {}
    budget_hit = False

    def add(artifact, kind, value, location, *, brands=None, source_host=None, logo=False, target=None,
            markup_target=None, composed=False):
        nonlocal budget_hit
        for brand in brands or [None]:
            key = (artifact, kind, brand, str(location))
            if key in seen:
                continue
            if len(output.brand_signals) >= MAX_ENTRIES:
                if not budget_hit:
                    registry.limit("BRAND_BUDGET", "brand", "Presentation entry limit reached; additional signals withheld.")
                    budget_hit = True
                return
            seen.add(key)
            details = {"kind": kind, "brand_candidate": brand, "value": label(value),
                       "source_host": source_host, "logo_candidate": logo, "target": safe_url(target)}
            evidence_key = (artifact, kind, str(location))
            if evidence_key not in evidence:
                support = {k: v for k, v in details.items() if k != "brand_candidate"} | {"brand_candidates": brands or []}
                if composed:
                    support["target"] = safe_url(markup_target)
                    support["source_host"] = urlsplit(origin_url(markup_target) or "").hostname
                evidence[evidence_key] = registry.add(artifact, "dom_markup" if artifact == "dom" else "provider_metadata", "observed",
                    location | {"presentation_kind": kind}, "Presentation signal preserved; intent and ownership not assessed",
                    details=support)
            ref = evidence[evidence_key]
            refs = [ref] + ([document_ref] if composed and document_ref else [])
            output.brand_signals.append({"id": registry.identifier("b", [refs, brand]), "state": "observed",
                                         "evidence_refs": refs, "location": location,
                                         "limitations": ["Presentation only; visibility, purpose and ownership unresolved."], **details})

    page = mapping(mapping(result).get("page"))
    if isinstance(page.get("title"), str):
        add("result", "page_title", page["title"], {"json_pointer": "/page/title"},
            brands=candidates(page["title"], title_or_logo=True))
    # Only explicit supported metadata; unknown processor formats remain unparsed.
    brand_metadata = mapping(result).get("brands")
    if isinstance(brand_metadata, list):
        for index, entry in enumerate(brand_metadata[:MAX_ENTRIES]):
            name = entry.get("name") if isinstance(entry, dict) else None
            if isinstance(name, str):
                add("result", "urlscan_brand_metadata", name, {"json_pointer": f"/brands/{index}/name"},
                    brands=candidates(name, title_or_logo=True) or ([label(name)] if label(name) not in {None, "[omitted]", ""} else []))
    if parser is not None:
        for entry in parser.presentation:
            if entry["inactive"]:
                continue
            tag, attrs, location = entry["tag"], entry["attrs"], entry["location"]
            if tag == "title":
                brands = candidates(entry["text"], title_or_logo=True)
                if not entry["svg_title"] or brands:
                    add("dom", "logo_title" if entry["svg_title"] else "document_title", entry["text"], location,
                        brands=brands, logo=entry["svg_title"])
            elif tag == "img":
                alt, title = attrs.get("alt", ""), attrs.get("title", "")
                brands = list(dict.fromkeys(candidates(alt, title_or_logo=True) + candidates(title, title_or_logo=True)))
                marker = " ".join(attrs.get(k, "") for k in ("class", "id", "src"))[:1000]
                logo = bool(re.search(r"(?:^|[^a-z])logo(?:[^a-z]|$)", marker, re.IGNORECASE))
                for key in ("alt", "title"):
                    if attrs.get(key) and (brands or logo):
                        add("dom", "logo_" + key if logo else "image_" + key, attrs[key], location | {"attribute": key},
                            brands=candidates(attrs[key], title_or_logo=True), logo=logo)
                if logo or brands:
                    try:
                        raw_source = attrs.get("src", "")
                        source = None if parser.base_href_present and not urlsplit(raw_source).scheme else urljoin(document_url or "", raw_source)
                        host = urlsplit(origin_url(source) or "").hostname
                    except ValueError:
                        source, host = None, None
                    add("dom", "image_source", None, location | {"attribute": "src"},
                        brands=brands or candidates(marker), source_host=host, logo=logo, target=source,
                        markup_target=attrs.get("src"), composed=True)
            else:
                brands = candidates(entry["text"])
                if brands:
                    # Preserve only recognized brand words, not arbitrary identity/secret copy.
                    add("dom", "local_brand_text", None, location, brands=brands)
                if tag == "a":
                    words = entry["text"].lower()
                    if re.search(r"\b(?:legal|privacy|terms|help|support)\b", words):
                        try:
                            raw_target = attrs.get("href", "")
                            target = None if parser.base_href_present and not urlsplit(raw_target).scheme else urljoin(document_url or "", raw_target)
                        except ValueError:
                            target = None
                        add("dom", "legal_help_link", None, location | {"attribute": "href"}, brands=brands, target=target,
                            markup_target=attrs.get("href"), composed=True)
    grouped = {}
    for signal in output.brand_signals:
        brand = signal["brand_candidate"]
        if brand is not None:
            grouped.setdefault(brand, []).append(signal)
    def presentation_order(item):
        # Direct titles/logo labels before peripheral image-brand references.
        ranks = {"page_title": 0, "document_title": 0, "urlscan_brand_metadata": 0,
                 "logo_title": 1, "logo_alt": 1, "local_brand_text": 2}
        return min(ranks.get(s["kind"], 3) for s in item[1]), item[0]

    for brand, signals in sorted(grouped.items(), key=presentation_order):
        refs = list(dict.fromkeys(ref for signal in signals for ref in signal["evidence_refs"]))
        if document_ref is not None and document_ref not in refs:
            refs.append(document_ref)
        output.brand_candidates.append({"id": registry.identifier("brand", [brand, refs]), "name": brand,
                                        "state": "observed", "signal_refs": [s["id"] for s in signals],
                                        "evidence_refs": refs, "provider_relationship": "unresolved",
                                        "page_origin": origin_url(document_url), "assessment": "presentation_only",
                                        "limitations": ["Presentation does not establish intent or ownership."]})
