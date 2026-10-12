"""Compact plain text presentation of the derived analysis model."""

from collections import Counter
import json
import textwrap

from .adapters import label
from .findings import display_key
from ..display import display_text, display_url, MAX_URL_CHARS


MAX_RENDERED_FINDINGS_DEFAULT = 8
OUTPUT_WIDTH = 110


def readable(value):
    """Presentation only: JSON keeps the original enums."""
    return str(value).replace('_', ' ')


def endpoint(value, *, verbose=False, limit=160):
    # display_text has its own embedded-URL cap even with limit=None. Preserve
    # the full protected URL in verbose instead of silently applying that cap.
    return display_url(value, MAX_URL_CHARS if verbose else limit, fingerprint=False)


def wrap_lines(lines):
    """Bound terminal width without deleting any provenance text."""
    out = []
    for line in lines:
        indent = len(line) - len(line.lstrip())
        out.extend(textwrap.wrap(line, OUTPUT_WIDTH, subsequent_indent=' ' * (indent + 2),
                                 break_long_words=True, break_on_hyphens=False) or [''])
    return out


def primary_findings(analysis):
    return sorted((f for f in analysis.get('findings', []) if f.get('kind')), key=display_key)


def excluded_finding(f):
    return f['evidence_state'] in {'contradictory', 'truncated'} or f['static_path_state'] == 'statically_unreachable'


def coverage_status(record):
    """Never turn an unavailable inventory into a zero or a completed analysis."""
    details = record.get('details', {})
    reason = record.get('reason') or ''
    if details.get('truncated') or details.get('budget_exceeded') or 'budget' in reason or 'exceeds' in reason:
        return 'truncated'
    if record['availability'] != 'available':
        return 'unavailable' + (' (invalid artifact)' if record['availability'] == 'invalid' else '')
    return {'not_supported': 'unsupported', 'not_run': 'unresolved'}.get(record['inspection'], record['inspection'])


def summary_lines(analysis):
    findings = primary_findings(analysis)
    visible = [f for f in findings if not excluded_finding(f)]
    coverage = analysis['evidence_coverage']
    interaction = analysis.get('interaction', {})
    js_status = coverage_status(coverage['javascript'])
    lines = ['', 'Analysis summary']
    count = str(len(visible)) if js_status == 'complete' else (
        'unavailable' if js_status.startswith('unavailable') and not visible else f"{len(visible)} supported; inspection {js_status}")
    lines.append('  Sensitive static request findings: ' + count)
    if coverage['requests']['availability'] != 'available':
        lines.append('  Runtime request support: unavailable')
    else:
        supported = sum(f['runtime_support'] in {'compatible_request_observed', 'initiator_supported_request_observed'} for f in visible)
        lines.append(f'  Runtime-supported findings: {supported} observed' +
                     ('; request coverage partial' if coverage['requests']['inspection'] != 'complete' else ''))
        states = Counter(f['runtime_support'] for f in findings)
        for state in ('unavailable', 'ambiguous', 'contradictory'):
            if states[state]: lines.append(f'    {states[state]} {state} finding relationships')
    bodies = coverage['request_bodies']
    if bodies['availability'] != 'available':
        lines.append('  Runtime payload structure support: unavailable')
    else:
        count = sum(f['payload_support'] == 'structurally_correlated' for f in visible)
        lines.append(f'  Runtime payload structure support: {count} structurally compatible' +
                     ('; body coverage ' + coverage_status(bodies) if bodies['inspection'] != 'complete' else ''))
    ic = interaction.get('coverage', {})
    stage_count = len(interaction.get('stages', []))
    lines.append('  Interaction stage candidates: ' + ('unavailable' if ic.get('stage_grouping') == 'unavailable' else str(stage_count)))
    unresolved = str(sum(f['sink'].get('target') is None for f in findings)) if js_status == 'complete' else (
        'unavailable' if js_status.startswith('unavailable') else
        f"{sum(f['sink'].get('target') is None for f in findings)} supported; inspection {js_status}")
    lines.append('  Unresolved targets: ' + unresolved)
    if excluded := sum(excluded_finding(f) for f in findings):
        lines.append(f'  Contradictory / unreachable / truncated findings: {excluded} (separate evidence section)')
    truncation = truncated_subsystems(analysis)
    if truncation: lines.append('  TRUNCATED: ' + ', '.join(truncation) + '; findings and counts may be incomplete')
    lines += ['  Execution of static flows is not established.',
              '  Structural payload correlation does not establish source value equality.']
    return lines


def truncated_subsystems(analysis):
    js = analysis.get('javascript', {})
    names = {name for name, c in analysis['evidence_coverage'].items() if coverage_status(c) == 'truncated'}
    if js.get('truncated'): names.add('javascript')
    for key in ('interprocedural', 'path_analysis'):
        if js.get(key, {}).get('truncated'): names.add(key)
    if any(c.get('requests_truncated') for c in js.get('runtime_correlations', [])):
        names.add('runtime request correlation')
    if analysis.get('interaction', {}).get('coverage', {}).get('truncated'): names.add('interaction')
    labels = {'javascript': 'JavaScript', 'interprocedural': 'JavaScript interprocedural',
              'path_analysis': 'JavaScript path analysis', 'runtime request correlation': 'runtime request correlation',
              'request_bodies': 'request bodies', 'interaction': 'interaction', 'findings': 'findings'}
    order = list(labels)
    return [labels.get(name, readable(name)) for name in sorted(names, key=lambda n: (order.index(n) if n in order else len(order), n))]


def interaction_display_groups(records, kind):
    """Group safe display identities only; hidden values and structured refs stay distinct."""
    groups = {}
    for record in records:
        if kind == 'prefills':
            identity = (record['source_kind'], display_text(record.get('key_name') or '', None))
        else:
            identity = (endpoint(record.get('target') or '(target unresolved)', verbose=True),
                        record['relation_to_submit'], record.get('target_state'), record.get('deferred'))
        identity += (record.get('path_state'), record.get('execution_context'))
        groups.setdefault(identity, []).append(record)
    return list(groups.values())


def coverage_lines(analysis, *, verbose=False):
    lines = ['', 'Coverage / limitations']
    for name, c in analysis['evidence_coverage'].items():
        if not verbose and name not in {'dom', 'javascript', 'requests', 'request_bodies', 'interaction', 'findings'}:
            if coverage_status(c) != 'truncated': continue
        status = coverage_status(c)
        if name == 'javascript' and analysis.get('javascript', {}).get('truncated'): status = 'truncated'
        unit = {'dom': 'markup controls', 'javascript': 'script records', 'interaction': 'stage candidates',
                'findings': 'composed findings', 'frames': 'request frame IDs',
                'external_script_sources': 'supplied scripts', 'request_bodies': 'preserved bodies'}.get(name, 'preserved records')
        count = f"; {c['count']} {unit}" if c['count'] is not None and c['availability'] == 'available' else ''
        lines.append(f"  {readable(name)}: {status}{count}")
        if name == 'findings' and status == 'partial' and not c.get('details', {}).get('truncated'):
            lines.append('    synthesis complete within its budget; lower-layer inspection partial')
        if c.get('reason') and (verbose or status in {'partial', 'truncated', 'unsupported'} or c['availability'] == 'invalid'):
            lines.append('    ' + c['reason'])
        if verbose:
            lines.append(f"    availability={c['availability']}; inspection={c['inspection']}; skipped={c['skipped_count']}")
            lines.append('    details: ' + json.dumps(c.get('details', {}), sort_keys=True, ensure_ascii=False))
    if verbose:
        lines += ['  Interaction coverage: ' + json.dumps(analysis.get('interaction', {}).get('coverage', {}), sort_keys=True),
                  '  JavaScript budgets: ' + json.dumps(analysis.get('javascript', {}).get('budgets', {}), sort_keys=True)]
        lines.extend('  ' + entry['explanation'] for entry in analysis['limitations'])
        lines += ['', 'Evidence index (derived facts only)']
        for evidence in analysis['evidence']:
            lines += [f"  {evidence['id']}: {evidence['layer']} / {evidence['state']}; {evidence['claim']}",
                      '    location: ' + json.dumps(evidence['location'], sort_keys=True)]
    lines += ['  not observed != does not exist',
              '  JavaScript not executed; local static flows do not establish submission or receipt.']
    return lines


def input_lines(analysis):
    lines = ['', 'Input / interaction overview']
    dom = analysis.get('dom_inventory')
    if dom is None:
        lines.append('  DOM inventory: unavailable; preserved Result evidence can still be inspected')
    else:
        lines.append(f"  DOM markup: {dom['forms_count']} forms; {dom['controls_count']} controls")
        roles = Counter(c.get('semantic_role', c['semantic_type']) for c in dom['controls'])
        lines.append('  Controls: ' + (', '.join(f'{readable(k)} {v}' for k, v in sorted(roles.items())) or 'no supported controls observed'))
        for form in dom['forms'][:3]:
            lines.append(f"  Form: markup form method {form['markup_method']} / target {display_text(form['resolved_markup_target'] or '(target unresolved)', 160)}")
        if len(dom['forms']) > 3: lines.append(f"  ... {len(dom['forms']) - 3} more forms (--verbose)")
        lines.append('  Runtime submission not established; markup handlers may override or cancel form behavior.')
    model = analysis.get('interaction', {})
    stages = model.get('stages', [])
    stage_count = 'unavailable' if model.get('coverage', {}).get('stage_grouping') == 'unavailable' else str(len(stages))
    lines.append(f'  Stage candidates: {stage_count}; ordering and runtime interaction not established.')
    if model.get('transitions'):
        lines.append(f"  Static transitions: {len(model['transitions'])} declarations (--verbose for supported relationships)")
    for stage in stages[:5]:
        lines.append('    Stage candidate: ' + ', '.join(readable(r) for r in stage['semantic_roles']))
        if stage['submission_handler_declared']: lines.append('      submit handler: declared only')
        if stage.get('runtime_support') == 'related_request_only': lines.append('      related request only; stage execution not established')
        if stage.get('runtime_support') == 'unresolved': lines.append('      runtime support: unresolved')
    if len(stages) > 5: lines.append(f'  ... {len(stages) - 5} more stage candidates (--verbose)')
    for key, title in (('prefills', 'Prefill'), ('retry_paths', 'Retry behavior'), ('navigations', 'Navigation')):
        records = model.get(key, [])
        if not records: continue
        groups = interaction_display_groups(records, key) if key != 'retry_paths' else [[r] for r in records]
        for members in groups[:2]:
            record = members[0]
            count = f'; {len(members)} records' if len(members) > 1 else ''
            if key == 'prefills':
                lines.append('  Prefill: ' + readable(record['source_kind']) +
                             ('; key: ' + display_text(record['key_name'], None) if record.get('key_name') else '') + count +
                             '; path: ' + readable(record.get('path_state', 'unresolved')) + '; final submitted values unresolved')
            elif key == 'retry_paths':
                lines.append('  Retry behavior: declared static path; execution not established')
            else:
                lines.append('  Navigation declared: ' + display_text(record.get('target') or '(target unresolved)', 160) +
                             '; ' + readable(record['relation_to_submit']) +
                             ('; deferred' if record.get('deferred') else '') +
                             '; path: ' + readable(record.get('path_state', 'unresolved')) +
                             (f'; {len(members)} static declarations with this protected target representation' if len(members) > 1 else '') +
                             '; runtime navigation not established')
        if len(groups) > 2:
            unit = 'records' if key == 'retry_paths' else 'display groups'
            lines.append(f'  ... {len(groups) - 2} more {title.lower()} {unit} (--verbose)')
    if any(h.get('retry_relationship') == 'unresolved' for h in model.get('handlers', [])):
        lines.append('  Retry behavior: unresolved')
    return lines


def request_summary_lines(analysis):
    coverage = analysis['evidence_coverage']['request_bodies']
    counts = coverage.get('details', {})
    lines = ['', 'Request / payload evidence summary']
    if analysis.get('network_requests') == []:
        lines.append('  Request bodies: no preserved requests to inspect')
    elif coverage['availability'] != 'available':
        lines.append('  Request bodies: unavailable; not preserved does not mean empty')
    else:
        lines.append('  Request bodies: ' + '; '.join(f"{counts.get(k, 0)} {title}" for k, title in
                     (('bodies_available', 'preserved'), ('parsed', 'parsed'), ('empty', 'empty'), ('unsupported', 'unsupported'),
                      ('malformed', 'malformed'), ('truncated', 'truncated'), ('bodies_unavailable', 'unavailable'))))
    # Only body structure is shown; complete payload inventories belong to verbose/JSON.
    payloads = [p for p in analysis.get('runtime_payloads', []) if p['body_availability'] != 'unavailable']
    requests = {r['request_ref']: r for r in analysis.get('network_requests') or []}
    groups = {}
    for payload in payloads:
        req = requests[payload['request_ref']]
        shape = tuple((f['path'], f['value_type'], f['semantic_role'], f['multiplicity']) for f in payload['fields'])
        key = (req['method'], req['url'], payload['body_format'], payload['parser_status'], shape)
        groups.setdefault(key, []).append(payload)
    for members in list(groups.values())[:3]:
        payload = members[0]
        req = requests[payload['request_ref']]
        lines.append(f"  {req['method']} {display_text(req['url'] or '(URL unresolved)', 160)}: {readable(payload['parser_status'])}")
        if len(members) > 1:
            lines.append(f'    {len(members)} body records with the same protected URL / format / field structure; distinct request refs in --verbose')
        fields = payload['fields']
        if fields: lines.append('    Fields (values omitted): ' + ', '.join(display_text(f['path'], 80) for f in fields[:4]))
        if len(fields) > 4: lines.append(f"    ... {len(fields) - 4} more fields (--verbose)")
    if len(groups) > 3: lines.append(f'  ... {len(groups) - 3} more body display groups (--verbose)')
    return lines


def static_summary_lines(analysis):
    js = analysis.get('javascript', {})
    lines = ['', 'Notable static JavaScript evidence']
    counts = Counter(s['parser_status'] for s in js.get('scripts', []))
    lines.append('  Scripts: ' + (', '.join(f'{v} {readable(k)}' for k, v in sorted(counts.items())) or 'unavailable'))
    # Composed flows already have a chain above. Do not repeat them here.
    covered = {ref for f in primary_findings(analysis) for ref in f['static_flow_refs']}
    flows = [f for f in js.get('flows', []) if f['id'] not in covered]
    lines.append(f"  {len(js.get('flows', []))} static flows; {len(flows)} outside primary findings (--verbose for provenance)")
    if js.get('scripts') and not js.get('flows'): lines.append('  No supported static flows observed in inspected code.')
    return lines


def runtime_lines(analysis):
    lines = ['', 'Runtime observations']
    requests = analysis.get('network_requests')
    if requests is None: lines.append('  Requests: unavailable')
    else:
        methods = Counter(r['method'] for r in requests)
        lines.append(f"  {len(requests)} preserved requests: " + ', '.join(f'{k} {v}' for k, v in sorted(methods.items())))
    patterns = analysis.get('network_patterns', [])
    for pattern in patterns[:5]:
        title = 'Socket.IO HTTP polling' if pattern['kind'] == 'socket_io_http_polling' else 'Repeated endpoint'
        lines.append(f"  {title}: {pattern['request_count']} requests; " + ', '.join(f'{k} {v}' for k, v in sorted(pattern['method_counts'].items())))
        lines.append('    ' + display_text(pattern['family'], 160))
        for partition in pattern['session_partitions']:
            lines.append(f"    {'with sid' if partition['sid_present'] else 'without sid'}: {partition['request_count']} requests (sid values omitted)")
    if len(patterns) > 5: lines.append(f'  ... {len(patterns) - 5} more patterns (--verbose)')
    heartbeats = analysis.get('heartbeat_requests', [])
    for hb in heartbeats[:3]:
        lines.append(f"  Heartbeat-style endpoint observed: {hb['request_count']} requests; purpose and cadence unresolved")
        lines.append('    ' + display_text(hb['family'], 160))
    if len(heartbeats) > 3: lines.append(f'  ... {len(heartbeats) - 3} more heartbeat endpoints (--verbose)')
    ws = analysis['evidence_coverage']['websockets']
    lines.append('  WebSocket: ' + ('not observed (0 preserved)' if ws['availability'] == 'available' and ws['count'] == 0 else coverage_status(ws)))
    for kind in ('cookies', 'storages'):
        cov = analysis['evidence_coverage'][kind]
        lines.append(f"  {kind}: " + (f"{cov['count']} snapshot entries; values omitted" if cov['availability'] == 'available' else 'unavailable'))
    return lines


def format_analysis(envelope: dict, *, verbose: bool = False) -> str:
    """Render once-computed facts; no IO, clocks, ANSI or additional analysis passes."""
    metadata, analysis = envelope['metadata'], envelope['analysis']
    lines = ['urlscanx analysis', 'Scan: ' + (label(metadata['scan_id']) or 'unknown'),
             'Time: ' + (label(metadata['scan_time']) or 'unknown'),
             'Origin: ' + (metadata['origin'] or 'unresolved')]
    lines += summary_lines(analysis) + finding_lines(analysis, verbose=verbose)
    if verbose:
        lines += detail_lines(analysis, verbose=True)
    else:
        lines += input_lines(analysis) + request_summary_lines(analysis) + static_summary_lines(analysis) + runtime_lines(analysis)
    lines += coverage_lines(analysis, verbose=verbose)
    if not verbose and any('…' in line for line in lines):
        lines.append('  Long display values shortened; use --verbose for full protected values.')
    return '\n'.join(wrap_lines(lines))


def detail_lines(analysis: dict, *, verbose: bool = False) -> list[str]:
    """Preserve the detailed lower-layer inventories for provenance inspection."""
    lines = []
    inventory = analysis["dom_inventory"]
    if inventory is not None:
        lines += ["", f"DOM markup: {inventory['forms_count']} forms; {inventory['controls_count']} controls",
                  "  Visibility and submission are not established."]
        lines += ["", "Semantic controls"]
        if not inventory["controls"]:
            lines.append("  0 captured controls")
        categories = {"Credentials / identifiers": [], "MFA candidates": [], "Payment": [], "Contact / other": []}
        for control in inventory["controls"]:
            role = control.get("semantic_role", control["semantic_type"])
            category = ("Credentials / identifiers" if role in {"password", "username"} else
                        "MFA candidates" if role == "otp_candidate" else "Payment" if role.startswith("payment_") else "Contact / other")
            categories[category].append(control)
        for category, controls in categories.items():
            if not controls:
                continue
            counts = Counter(c.get("semantic_role", c["semantic_type"]) for c in controls)
            lines.append(f"  {category}: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
            for control in controls if verbose else controls[:5]:
                lines.append(f"    {control.get('semantic_role', control['semantic_type'])}: {control['element_id'] or control['name'] or '(unnamed)'}; HTML {control.get('html_type') or control['tag']}; form={control['form_association']}")
                if verbose:
                    support = control.get("semantic_support", [])
                    lines.append("      Local support: " + (", ".join(s.get("attribute", s["source"]) for s in support) or "unresolved"))
                if control.get("markup_context") == "inert_markup":
                    lines.append("      Inert template/noscript markup; active control not established.")
            if not verbose and len(controls) > 5:
                lines.append(f"    ... {len(controls) - 5} more (--verbose)")
        lines += ["", "Forms (HTML markup only)"]
        forms = inventory.get("forms", [])
        if not forms:
            lines.append("  0 captured forms")
        for form in forms if verbose else forms[:5]:
            lines += [f"  {form['element_id'] or 'form-' + str(form['index'])}: markup form method {form['markup_method']} / target {form['resolved_markup_target'] or 'unresolved'}",
                      f"    Associated controls: {len(form['control_indices'])}; submit controls: {len(form['submit_controls'])}"]
            if form.get("markup_context") == "inert_markup":
                lines.append("    Inert template/noscript markup; activation unresolved.")
            if verbose:
                for submit in form["submit_controls"]:
                    if submit["formmethod"] is not None or submit["formaction"] is not None:
                        lines.append(f"    Submit override: {submit['formmethod'] or '(inherits method)'} / {submit['resolved_formaction'] or '(inherits target or unresolved)'}")
        if not verbose and len(forms) > 5:
            lines.append(f"  ... {len(forms) - 5} more (--verbose)")
        lines.append("  Runtime submission not established; client-side handlers may override/cancel markup behavior.")
    else:
        lines += ["", "Semantic controls / forms: unresolved (DOM inventory unavailable)"]
    lines += ["", "Network behavior"]
    methods = Counter(event["method"] for event in (analysis["network_requests"] or []))
    lines.append("  Methods: " + (", ".join(f"{k} {v}" for k, v in sorted(methods.items())) or "not evaluated / no normalized events"))
    patterns = analysis["network_patterns"]
    for pattern in patterns if verbose else patterns[:5]:
        title = "Socket.IO HTTP polling" if pattern["kind"] == "socket_io_http_polling" else "Repeated endpoint"
        methods = ", ".join(f"{k} {v}" for k, v in pattern["method_counts"].items())
        statuses = ", ".join(f"{k} {v}" for k, v in pattern["status_counts"].items())
        lines += [f"  [observed/network_request] {title}: {pattern['request_count']} requests",
                  "    " + pattern["family"], f"    {methods}; status {statuses}"]
        for partition in pattern["session_partitions"]:
            session = partition["session_id"] or ("unresolved sid" if partition["sid_present"] else "without sid")
            lines.append(f"    {session}: {partition['request_count']} requests (sid values omitted)")
        timing = pattern["timing"]
        if timing["span_seconds"] is not None:
            lines.append(f"    Captured span: {timing['span_seconds']:.3f} s; long-term cadence unresolved")
        if verbose:
            lines.append("    Refs: " + ", ".join(pattern["request_refs"]))
    if len(patterns) > 5 and not verbose:
        lines.append(f"  ... {len(patterns) - 5} more (--verbose)")
    heartbeats = analysis.get("heartbeat_requests", [])
    for heartbeat in heartbeats if verbose else heartbeats[:5]:
        heartbeat_methods = ", ".join(f"{k} {v}" for k, v in heartbeat["method_counts"].items())
        lines += [f"  [observed/network_request] Heartbeat-style endpoint observed: {heartbeat['request_count']} requests",
                  "    " + heartbeat["family"], "    " + heartbeat_methods + "; cadence unresolved; endpoint purpose unresolved."]
    if not verbose and len(heartbeats) > 5:
        lines.append(f"  ... {len(heartbeats) - 5} heartbeat-style endpoints (--verbose)")
    websocket = analysis["evidence_coverage"]["websockets"]
    if websocket["availability"] == "available" and websocket["count"] == 0:
        lines.append("  WebSocket: not observed in preserved websocket records (0 captured entries)")
    else:
        lines.append("  WebSocket: " + websocket["availability"] + " / " + websocket["inspection"])
    lines.extend(javascript_lines(analysis.get("javascript", {}), verbose=verbose))
    lines.extend(payload_lines(analysis, verbose=verbose))
    lines.extend(interaction_lines(analysis, verbose=verbose))
    lines += ["", "Browser state snapshot (values omitted)"]
    for kind, entries in analysis["browser_state"].items():
        coverage = analysis["evidence_coverage"][kind]
        if coverage["availability"] != "available":
            lines.append(f"  {kind}: {coverage['availability']}")
            continue
        lines.append(f"  {kind}: {coverage['count']} captured entries")
        shown = entries if verbose else entries[:5]
        for entry in shown:
            name = entry.get("name") or entry.get("key") or "(unnamed)"
            location = entry.get("domain") or entry.get("origin") or "unresolved"
            state = entry.get("storage_type") or "cookie"
            lines.append(f"    {name} @ {location} [{state}]")
        if len(entries) > len(shown):
            lines.append(f"    ... {len(entries) - len(shown)} more (--verbose)")
    lines += ["", "Brand presentation (neutral)"]
    brands = analysis.get("brand_candidates", [])
    signal_kinds = {s["id"]: s["kind"] for s in analysis.get("brand_signals", [])}
    if not brands:
        lines.append("  No recognized brand candidate in supported preserved signals; coverage limited.")
    for brand in brands if verbose else brands[:5]:
        kinds = sorted({signal_kinds[ref] for ref in brand["signal_refs"]})
        lines.append(f"  {brand['name']}: " + ", ".join(kinds) + "; provider relationship unresolved")
    if not verbose and len(brands) > 5:
        lines.append(f"  ... {len(brands) - 5} more (--verbose)")
    if verbose:
        for signal in analysis.get("brand_signals", []):
            lines.append(f"    {signal['kind']}: {signal['brand_candidate'] or '(unassigned)'}; source host={signal['source_host'] or 'unresolved'}; refs=" + ", ".join(signal["evidence_refs"]))
    lines += ["", "Structural trust hints"]
    relations = Counter(boundary["structural_relation"] for boundary in analysis["trust_boundaries"])
    lines.append("  " + (", ".join(f"{k} {v}" for k, v in sorted(relations.items())) or "not evaluated"))
    lines.append("  Different hostnames do not establish registrable-domain or provider ownership.")
    hints = [h for h in analysis.get("trust_hints", []) if h["kind"] == "form_markup_target" or verbose and h["kind"] == "request_destination"]
    for hint in hints if verbose else hints[:5]:
        if hint["kind"] == "form_markup_target":
            lines.append(f"  Form markup: {hint['structural_relation']} -> {hint['destination_origin'] or 'unresolved'}; provider relationship unresolved")
        elif verbose and hint["kind"] == "request_destination":
            lines.append(f"  Request origin: {hint['structural_relation']} -> {hint['destination_origin'] or 'unresolved'}; provider relationship unresolved")
    if not verbose and len(hints) > 5:
        lines.append(f"  ... {len(hints) - 5} more markup trust hints (--verbose)")
    return lines


def payload_lines(analysis: dict, *, verbose: bool = False) -> list[str]:
    coverage = analysis.get('evidence_coverage', {}).get('request_bodies', {}).get('details', {})
    lines = ['', 'Runtime request payloads',
             '  {requests_inspected} requests inspected; {bodies_available} bodies preserved; {bodies_unavailable} bodies unavailable; parsed {parsed}; unsupported {unsupported}; malformed {malformed}; truncated {truncated}'.format(
                 **{key:coverage.get(key,0) for key in ('requests_inspected','bodies_available','bodies_unavailable','parsed','unsupported','malformed','truncated')}),
             '  Not preserved != empty; field correspondence != source/value identity.']
    requests = {r['request_ref']:r for r in (analysis.get('network_requests') or [])}
    payloads = analysis.get('runtime_payloads', [])
    visible = payloads if verbose else [p for p in payloads if p['body_availability']!='unavailable' or requests[p['request_ref']]['method'] in {'POST','PUT','PATCH'}]
    if not verbose:
        priority = {'parsed':0, 'malformed':1, 'truncated':1, 'unsupported':2, 'not_run':3}
        visible = sorted(visible, key=lambda p:priority.get(p['parser_status'],3))
    for payload in visible if verbose else visible[:5]:
        request = requests[payload['request_ref']]
        lines.append(f"  {request['method']} {display_text(request['url'] or '(URL unresolved)', 200) if not verbose else request['url'] or '(URL unresolved)'}")
        lines.append('    request body: ' + ('not preserved' if payload['body_availability']=='unavailable' else
                     'preserved empty body' if payload['body_format']=='empty' else payload['body_availability']) +
                     '; format: ' + payload['body_format'] + '; parser: ' + payload['parser_status'])
        fields = payload['fields']
        for field in fields if verbose else fields[:6]:
            path = field['path'] if verbose else display_text(field['path'],160)
            lines.append(f"    {path}: {field['value_type']}; name semantics: {field['semantic_role']}; present, value omitted; multiplicity {field['multiplicity']}")
            if field['filename_present']:
                lines.append('      file metadata only; filename omitted; file contents not inspected')
        if not verbose and len(fields)>6:
            lines.append(f"    ... {len(fields)-6} more fields (--verbose)")
        if payload['reason']:
            lines.append('    ' + payload['reason'])
        if verbose:
            lines.append('    Request ref: ' + payload['request_ref'])
    if not verbose and len(visible)>5:
        lines.append(f"  ... {len(visible)-5} more request payload records (--verbose)")
    correlations = analysis.get('javascript', {}).get('payload_correlations', [])
    for record in correlations if verbose else correlations[:6]:
        candidate = ' candidate only' if record.get('static_producer_state') == 'candidate_only' else ''
        path = record['static_field_path'] if verbose else display_text(record['static_field_path'],160)
        title = 'Input object field' if record.get('static_field_path_basis') == 'input_object' else 'Static payload'
        lines.append(f"  {title}{candidate} {path} ({record['source_semantic_role'] or 'contextual'} source): {record['structural_relationship']}; {record['reason']}")
        if record.get('static_field_path_basis') == 'input_object':
            lines.append('    Serialized field identity: unresolved')
        if record['possible_static_producers']>1:
            lines.append(f"    Possible static producers: {record['possible_static_producers']}; producer identity not established")
        lines.append(f"    static path: {record['static_path_state']}; condition satisfaction not established; runtime execution not established; value relationship unresolved")
    if not verbose and len(correlations)>6:
        lines.append(f"  ... {len(correlations)-6} more payload relationships (--verbose)")
    return lines


def javascript_lines(js: dict, *, verbose: bool = False) -> list[str]:
    lines = ["", "JavaScript static analysis"]
    scripts = js.get("scripts", [])
    counts = Counter(s["parser_status"] for s in scripts)
    lines.append("  Scripts: " + (", ".join(f"{count} {state}" for state, count in sorted(counts.items())) or "unavailable"))
    edges = {e['id']: e for e in js.get('call_edges', [])}
    if 'functions' in js:
        resolved = sum(e['call_resolution'] == 'resolved' for e in edges.values())
        lines.append(f"  Helpers: {len(js['functions'])} indexed; calls: {resolved} resolved, {len(edges) - resolved} unresolved; depth limit: {js.get('budgets', {}).get('call_depth', 3)}")
    if js.get("truncated"):
        if js.get('interprocedural', {}).get('truncated'):
            lines.append('  Interprocedural propagation truncated; intraprocedural analysis continues.')
            lines.append('    Reasons: ' + ', '.join(js['interprocedural'].get('reasons', [])))
        if js.get('skipped_scripts') or any(s.get('truncated') for s in scripts):
            lines.append("  Script/parser or local-analysis budget exceeded; incomplete script facts withheld.")
        if js.get('path_analysis', {}).get('truncated'):
            lines.append('  Path analysis truncated; local static facts retained with incomplete viability.')
            lines.append('    Reasons: ' + ', '.join(js['path_analysis']['reasons']))
        if any(c.get('requests_truncated') for c in js.get('runtime_correlations', [])):
            lines.append('  Runtime request context budget exceeded; detailed correlation unresolved; endpoint joins retained.')
    sources = {s["id"]: s for s in js.get("sources", [])}
    sinks = {s["id"]: s for s in js.get("sinks", [])}
    transforms = {t["id"]: t for t in js.get("transforms", [])}
    flows = [f for f in js.get("flows", []) if verbose or f["sensitive"]]
    payloads_shown = set()
    groups = {'unconditional':'Supported static flows', 'conditional':'Conditional static flows',
              'unresolved':'Static flows with unresolved viability', 'truncated':'Static flows with truncated path analysis',
              'statically_unreachable':'Statically unreachable flows (declared syntax only)'}
    flows.sort(key=lambda f:list(groups).index(f.get('static_path_state','unresolved')))
    predicates = {p['id']:p for p in js.get('path_conditions', [])}
    correlations = {c['id']:c for c in js.get('runtime_correlations', [])}
    lines.append("  " + ("Static flows:" if verbose else "Sensitive static flows:"))
    if not flows:
        lines.append("    None in supported code; check artifact/parser coverage.")
    previous_group = None
    for flow in flows if verbose else flows[:8]:
        path_state = flow.get('static_path_state','unresolved')
        if path_state != previous_group:
            lines.append('    ' + groups[path_state] + ':')
            previous_group = path_state
        source, sink = sources[flow["source_id"]], sinks[flow["sink_id"]]
        title = source.get("semantic_role") or source["source_kind"]
        support = "DOM control " + (source.get("control_label") or "(identifier omitted)") if source["source_kind"] == "dom_control" else source["source_kind"]
        fields = [t.get("field") for t in (transforms[i] for i in flow["transform_ids"]) if t.get("field") and t["kind"] in {"object_property", "property_assignment", "append", "set"}]
        chain = " -> ".join(("property " + t["field"] if t.get("field") else t["kind"]) for t in (transforms[i] for i in flow["transform_ids"])) if verbose else ", ".join(dict.fromkeys(fields))
        lines.append(f"    {title}: {support} -> {sink['sink_kind']} {sink['method'] or ''} {sink['target'] or '(target unresolved)'}".rstrip())
        if chain:
            title = ('Transforms: ' if verbose else 'Input object fields: ' if sink['payload'].get('serialization_shape') == 'unresolved' else 'Payload fields: ')
            lines.append("      " + title + chain)
        if sink['id'] not in payloads_shown and sink['payload'].get('fields'):
            paths = [f.get('path') or f['name'] for f in sink['payload']['fields']]
            paths = paths if verbose else paths[:6]
            summary = ', '.join(paths)
            lines.append('      Static payload structure: ' + sink['payload']['encoding'] + '; ' + (summary if verbose else display_text(summary,240)))
            if not verbose and len(sink['payload']['fields']) > 6:
                lines.append(f"      ... {len(sink['payload']['fields'])-6} more static fields (--verbose)")
            payloads_shown.add(sink['id'])
        if sink['id'] not in payloads_shown and sink['payload'].get('serialization_shape') == 'unresolved':
            lines.append('      JSON serialization shape: unresolved; ' + ', '.join(sink['payload'].get('serialization_shape_reasons', [])))
            lines.append('      Source participates in serialization input; serialized field identity not established.')
            payloads_shown.add(sink['id'])
        boundary = [transforms[i] for i in flow['transform_ids'] if transforms[i]['kind'] in {'call_argument', 'function_parameter', 'function_return', 'function_alias'}]
        if boundary:
            steps = []
            for transform in boundary:
                edge = edges.get(transform.get('call_edge_ref'), {})
                name = edge.get('callee_name') or '(anonymous helper)'
                step = (f"call {name} argument {transform.get('argument_index')}" if transform['kind'] == 'call_argument' else
                        f"parameter {transform.get('parameter_name') or '(unnamed)'}" if transform['kind'] == 'function_parameter' else
                        f"return {name}" if transform['kind'] == 'function_return' else 'function alias')
                if step not in steps:
                    steps.append(step)
            lines.append('      Static helper path: ' + ' -> '.join(steps))
        if sink['target_resolution'] == 'unresolved' and sink.get('target_expression', {}).get('references'):
            lines.append("      Target references (unresolved): " + ", ".join(sink['target_expression']['references']))
        lines.append(f"      state: static_flow_inferred; runtime endpoint: {sink['runtime_endpoint']}; payload relationship unresolved")
        lines.append('      static path: ' + path_state.replace('_',' '))
        conditions = [predicates[i] for i in flow.get('path_condition_refs',[]) if i in predicates]
        for condition in conditions if verbose else conditions[:3]:
            subject = predicate_text(condition.get('expression', {}))
            if not verbose:
                subject = display_text(subject,200)
            lines.append(f"      condition: {subject} == {str(condition['polarity']).lower()} ({condition['resolution']}); literals omitted")
        if not verbose and len(conditions) > 3:
            lines.append(f'      ... {len(conditions)-3} more conditions (--verbose)')
        if flow.get('loop_context'):
            lines.append('      loop context: conditional; iteration count unresolved')
        correlation = correlations.get(sink.get('runtime_correlation_ref'))
        if correlation and correlation['compatible_request_count']:
            lines.append(f"      runtime correlation: {correlation['state']}; {correlation['compatible_request_count']} compatible requests; condition satisfaction not established")
            rejected_count = correlation.get('context_mismatch_request_count',len(correlation.get('context_mismatch_request_refs',[])))
            if rejected_count:
                lines.append(f"      Rejected {rejected_count} candidate requests: document/frame context mismatch")
            if correlation['relationship'] == 'contradictory_evidence':
                lines.append('      relationship: contradictory evidence; static path remains unreachable under supported model')
            if verbose:
                for match in correlation['requests']:
                    lines.append(f"      Request {match['request_ref']}: {match['target_relationship']}; query {match['query_relationship']}; initiator {match['initiator_relationship']}")
        context = ('statically reachable from call' if sink.get('execution_context') == 'statically_reachable_from_call' else
                   'handler declared only' if sink.get('execution_context') == 'handler_declared' else
                   'function declared only' if ':function:' in sink.get('scope_ref', '') else 'top-level static code')
        if sink.get('execution_context') == 'statically_reachable_from_call':
            roots = [edges[i] for i in flow.get('call_edge_refs', []) if i in edges and edges[i]['execution_context'] != 'statically_reachable_from_call']
            if roots and roots[0]['execution_context'] == 'handler_declared':
                context = 'handler declared only -> ' + context
            elif roots and ':function:' in roots[0]['caller_scope']:
                context = 'function declared only -> ' + context
            if path_state == 'statically_unreachable':
                context = context.replace('statically reachable from call','static call context (path unreachable)')
        lines.append(f"      execution context: {context}; runtime execution: not established")
        if verbose:
            loc = flow["location"]
            lines.append(f"      Script {flow['script_ref']} at {loc['script_line']}:{loc['script_column']}; refs=" + ", ".join(flow["evidence_refs"]))
            for edge_id in dict.fromkeys(t.get('call_edge_ref') for t in boundary):
                edge = edges.get(edge_id)
                if edge:
                    lines.append(f"      Call {edge['id']}: {edge['call_resolution']}; caller {edge['caller_scope']} at {edge['call_location']}; callee {edge['callee_function_id']} at {edge['callee_definition_location']}")
    if not verbose and len(flows) > 8:
        lines.append(f"    ... {len(flows) - 8} more (--verbose)")
    flow_sinks = {f["sink_id"] for f in flows}
    others = [s for s in sinks.values() if s["id"] not in flow_sinks]
    if others:
        lines.append("  Other declared sinks:")
        for sink in others if verbose else others[:5]:
            lines.append(f"    {sink['sink_kind']} {sink['method'] or ''} {sink['target'] or '(target unresolved)'}; static path: {sink.get('static_path_state','unresolved').replace('_',' ')}; runtime endpoint: {sink['runtime_endpoint']}")
            correlation = correlations.get(sink.get('runtime_correlation_ref'))
            if correlation and correlation.get('context_mismatch_request_count'):
                lines.append(f"      runtime correlation: {correlation['state']}; document/frame context mismatch; conflicting candidates rejected")
        if not verbose and len(others) > 5:
            lines.append(f"    ... {len(others) - 5} more (--verbose)")
    if verbose:
        for edge in edges.values():
            if edge.get('reason'):
                lines.append(f"  Call {edge['id']}: {edge['call_resolution']} / {edge['propagation']}; {edge['reason']}")
        for script in scripts:
            lines.append(f"  Script {script['id']}: {script['parser_status']}; analyzed={script['code_analyzed']}; execution not performed")
            if script['parse_error']:
                lines.append("    " + script['parse_error'])
            if script.get('budget_reason'):
                lines.append("    Budget: " + script['budget_reason'])
    lines += ["  JS not executed; external unavailable scripts not fetched; only bounded explicit helpers supported."]
    return lines


def predicate_text(expression):
    kind = expression.get('kind')
    if kind == 'identifier':
        return expression.get('binding') or '[omitted]'
    if kind == 'literal':
        value = expression['value']
        return str(value).lower() if isinstance(value,bool) else '[omitted]'
    if kind == 'not':
        return '!(' + predicate_text(expression['operand']) + ')'
    if kind == 'binary':
        return '(' + predicate_text(expression['left']) + ' ' + expression['operator'] + ' ' + predicate_text(expression['right']) + ')'
    return kind or 'bounded expression'


def interaction_lines(analysis, *, verbose=False):
    """Neutral stage candidates; display labels never imply temporal ordering."""
    model = analysis.get('interaction') or {}
    coverage = model.get('coverage') or {}
    if not coverage:
        return []
    lines = ['', 'Interaction stages',
             '  Static candidates; ordering unresolved globally; runtime interaction not established.',
             f"  {coverage['stage_candidates']} stages; {coverage['transitions_inferred']} transitions; "
             f"{coverage['prefills']} prefills; {coverage['retry_paths']} retry paths; {coverage['navigations']} navigations"]
    if coverage['stage_grouping'] == 'unavailable': lines.append('  DOM grouping unavailable; missing markup does not establish a single stage.')
    if coverage['transition_analysis'] == 'unavailable': lines.append('  Transition analysis unavailable; missing JavaScript does not establish no transitions.')
    if coverage['truncated']: lines.append('  Interaction analysis truncated: '+', '.join(coverage['reasons'])+'; lower-level evidence preserved.')
    controls = {c['id']: c for c in (analysis.get('dom_inventory') or {}).get('controls', [])}
    sinks = {s['id']: s for s in analysis.get('javascript', {}).get('sinks', [])}
    labels = {s['id']: 'Stage candidate '+chr(65+i) if i < 26 else 'Stage candidate '+str(i+1)
              for i,s in enumerate(model.get('stages', []))}

    def shown(records, count=5): return records if verbose else records[:count]
    def details(record):
        if verbose:
            lines.append('      ref: '+record['id']+'; evidence: '+', '.join(record.get('evidence_refs', [])))
            if record.get('path_condition_refs'): lines.append('      predicates: '+', '.join(record['path_condition_refs']))
    for stage in shown(model.get('stages', [])):
        lines.append('  '+labels[stage['id']]+': '+', '.join(stage['semantic_roles']))
        names = [controls[ref]['element_id'] or controls[ref]['name'] or '(unnamed)' for ref in stage['control_refs'] if ref in controls]
        lines.append('    controls: '+', '.join(shown(names))+'; static visibility: '+stage['static_visibility'])
        if stage['submission_handler_declared']: lines.append('    submit handler: declared; activation not established')
        for sink_ref in shown(stage['sink_refs'], 3):
            sink = sinks.get(sink_ref)
            if sink: lines.append('    request declaration: '+(sink.get('method') or 'unknown')+' '+display_text(sink.get('target') or '(target unresolved)', 160 if not verbose else None))
        if stage['runtime_support'] == 'related_request_only': lines.append('    compatible runtime request evidence; stage execution not established')
        if stage['runtime_support'] == 'unresolved': lines.append('    runtime support: unresolved; '+stage.get('runtime_support_reason', 'lower-layer relationship unresolved'))
        if stage.get('repeated_submission_relationship') in {'unresolved', 'mutually_exclusive'}: lines.append('    repeated submission relationship: '+stage['repeated_submission_relationship'])
        if any(h.get('retry_relationship') == 'unresolved' and h['stage_ref'] == stage['id'] for h in model['handlers']): lines.append('    retry relationship: unresolved')
        for prefill in shown([p for p in model['prefills'] if p.get('stage_ref') == stage['id']], 3):
            key_name = '; key: '+prefill['key_name'] if prefill.get('key_name') else ''
            lines.append('    prefill: '+prefill['source_kind']+key_name+'; '+prefill['path_state']+'; final submitted value provenance unresolved')
            details(prefill)
        for retry in shown([r for r in model['retry_paths'] if r['stage_ref'] == stage['id']], 3):
            lines.append('    '+('Repeated submission possibility: static declaration' if retry.get('kind') == 'static_repeated_submission' else 'retry path: declared')+'; '+retry['path_state']+'; retry execution not established')
            details(retry)
        for mutation in shown([m for m in model['mutations'] if m['stage_ref'] == stage['id'] and (m['kind'] == 'field_reset' or m.get('error_ui_candidate'))], 3):
            label = ('field reset declared' if mutation['kind'] == 'field_reset' else
                     mutation.get('error_content_state') or ('error UI presentation candidate' if mutation.get('direction') == 'show' else 'error UI mutation declared'))
            lines.append('    '+label+'; '+mutation['path_state'])
            details(mutation)
        if verbose:
            lines.append('    containers: '+', '.join(stage['container_refs'])+'; controls: '+', '.join(stage['control_refs']))
            lines.append('    flow refs: '+(', '.join(stage['static_flow_refs']) or 'none')+'; runtime correlation refs: '+(', '.join(stage['runtime_correlation_refs']) or 'none'))
            lines.append('    payload refs: '+(', '.join(stage['runtime_payload_refs']) or 'none'))
            details(stage)
    for transition in shown(model.get('transitions', [])):
        lines.append('  '+labels.get(transition['from_stage_ref'], 'unresolved')+' -> '+labels.get(transition['to_stage_ref'], 'unresolved')+
                     ': static transition; '+transition['path_state']+'; trigger: '+transition['trigger'])
        lines.append('    execution context: '+transition['execution_context']+'; runtime execution: not established')
        details(transition)
    for navigation in shown(model.get('navigations', [])):
        lines.append('  '+('Deferred navigation declared: ' if navigation['deferred'] else 'Navigation declared: ')+
                     display_text(navigation['target'] or '(target unresolved)', 160 if not verbose else None))
        lines.append('    '+navigation['target_state']+'; '+navigation['path_state']+'; '+navigation['relation_to_submit']+
                     '; network completion unresolved; runtime navigation not established')
        details(navigation)
    for counter in shown(model.get('attempt_counters', [])):
        lines.append('  Attempt counter declared: '+counter['binding']+'; '+counter['path_state']+'; actual attempts unresolved')
        details(counter)
    if verbose:
        for mutation in model.get('mutations', []):
            lines.append('  Structural mutation: '+mutation['kind']+'; stage: '+labels.get(mutation['stage_ref'], 'unresolved')+'; '+mutation['path_state'])
            details(mutation)
    for category in ('stages', 'transitions', 'navigations', 'attempt_counters'):
        if not verbose and len(model.get(category, [])) > 5: lines.append(f"  ... {len(model[category])-5} more {category} (--verbose)")
    lines.append('  DOM snapshot timing, user actions, final values and response meaning unresolved.')
    return lines


def finding_lines(analysis, *, verbose=False):
    """Render composition only; all execution/value claims remain limited."""
    findings = primary_findings(analysis)
    coverage = analysis.get('evidence_coverage', {}).get('findings', {}).get('details', {})
    excluded = [f for f in findings if excluded_finding(f)]
    visible = [f for f in findings if not excluded_finding(f)]
    shown = visible if verbose else visible[:MAX_RENDERED_FINDINGS_DEFAULT]
    lines = ['', 'Analyst findings', '  Evidence synthesis; execution and source value identity not established.']
    if not shown: lines.append('  No supported primary composed findings.')
    if coverage.get('truncated'): lines.append('  Synthesis truncated: '+', '.join(coverage.get('reasons', [])))
    prefills = {p['id']: p for p in analysis.get('interaction', {}).get('prefills', [])}
    retries = {r['id']: r for r in analysis.get('interaction', {}).get('retry_paths', [])}
    navigations = {n['id']: n for n in analysis.get('interaction', {}).get('navigations', [])}
    sinks = {s['id']: s for s in analysis.get('javascript', {}).get('sinks', [])}
    flows = {v['id']: v for v in analysis.get('javascript', {}).get('flows', [])}
    edges = {v['id']: v for v in analysis.get('javascript', {}).get('call_edges', [])}
    role_names = {'password': 'password-semantic input', 'otp_candidate': 'OTP-candidate input',
                  'payment_pan': 'payment PAN-semantic input', 'payment_cvc': 'payment CVC-semantic input',
                  'payment_expiry': 'payment expiry-semantic input'}
    all_shown = shown + (excluded if verbose else excluded[:2])
    for ordinal, f in enumerate(all_shown, 1):
        if ordinal == len(shown) + 1:
            if len(visible) > len(shown):
                lines.append(f'  {len(shown)} of {len(visible)} primary findings shown. Use --verbose to inspect all primary findings.')
            lines += ['', 'Contradictory / unreachable / truncated evidence',
                      '  Separate static evidence; runtime relationship does not establish path execution.']
        roles = ', '.join(role_names.get(r, r+'-semantic input') for r in f['source_roles'])
        sink = f['sink']; fields = sorted({r['path'] for r in f['static_fields'] if r['path']})
        target = sink.get('target') or '(target unresolved)'
        marker = f'{ordinal}.' if ordinal <= len(shown) else '-'
        lines += [f'  {marker} {roles}: static request flow',
                  '    '+roles,
                  '      -> '+(sink.get('encoding') or 'encoding unresolved')+'; channel: '+sink['channel'],
                  '      -> '+(sink.get('method') or 'method unresolved')+' '+endpoint(target, verbose=verbose)]
        field_title = 'input object fields (serialization unresolved)' if any(r['path_basis'] == 'input_object' for r in f['static_fields']) else 'static serialized fields'
        if fields: lines.append('    '+field_title+': '+', '.join(display_text(p, None if verbose else 100) for p in (fields if verbose else fields[:4])))
        if field_title.startswith('input object'):
            lines += ['    JSON serialization shape: unresolved', '    Serialized field identity: unresolved']
        if not verbose and len(fields) > 4: lines.append(f'    ... {len(fields) - 4} more static fields (--verbose)')
        lines.append('    static path: '+readable(f['static_path_state'])+(' ('+f['static_path_state']+')' if verbose else ''))
        if verbose: lines.append('    evidence: '+f['evidence_state'])
        if sink.get('target') is None:
            references = sorted({ref for key in f['sink_refs'] for ref in sinks.get(key, {}).get('target_expression', {}).get('references', [])})
            if references: lines.append('    Target references (unresolved): ' + ', '.join(references))
            if 'import_not_followed' in f['limitations']: lines.append('    Imported code not followed; target relationship unresolved')
        contexts = set()
        for variant in f['path_variants']:
            context = variant['execution_context']
            original = sinks.get(flows.get(variant['flow_ref'], {}).get('sink_id'), {})
            if context == 'handler_declared': context = 'handler declared only'
            elif ':function:' in original.get('scope_ref', '') and context != 'statically_reachable_from_call': context = 'function declared only'
            elif context == 'declared': context = 'top-level static code'
            else: context = readable(context)
            if variant['execution_context'] == 'statically_reachable_from_call':
                roots = [edges[i] for i in variant['call_edge_refs'] if i in edges and edges[i]['execution_context'] != 'statically_reachable_from_call']
                if roots and roots[0]['execution_context'] == 'handler_declared': context = 'handler declared only -> ' + context
                elif roots and ':function:' in roots[0]['caller_scope']: context = 'function declared only -> ' + context
            contexts.add(context)
        lines.append('    execution context: '+', '.join(sorted(contexts))+'; flow execution: not established')
        runtime = {'compatible_request_observed': 'compatible request observed',
                   'initiator_supported_request_observed': 'compatible request observed; initiator supported',
                   'not_observed': 'not observed'}.get(f['runtime_support'], readable(f['runtime_support']))
        payload = {'structurally_correlated': 'structurally compatible', 'body_unavailable': 'unavailable',
                   'body_unsupported': 'unsupported encoding', 'runtime_field_observed': 'runtime field observed; source relationship unresolved'}.get(f['payload_support'], readable(f['payload_support']))
        lines.append('    runtime request: '+runtime)
        lines.append('    runtime payload structure: '+payload+'; value relationship: unresolved')
        if f['request_refs']: lines.append('    request: '+', '.join(f['request_refs']))
        if f['possible_static_producers'] > 1: lines.append(f"    possible static producers: {f['possible_static_producers']}; source identity unresolved")
        support = f['interaction_support']
        if support['stage_refs']: lines.append('    stage association: '+', '.join(support['stage_roles'])+'; stage execution not established')
        for ref in support['prefill_refs'] if verbose else support['prefill_refs'][:2]:
            p = prefills[ref]
            lines.append('    prefill relation: '+p['source_kind']+('; key: '+p['key_name'] if p.get('key_name') else '')+'; final submitted value provenance unresolved')
        for ref in support['retry_refs'] if verbose else support['retry_refs'][:2]:
            r = retries[ref]
            lines.append('    '+('multiple compatible static submission invocations declared' if r.get('kind') == 'static_repeated_submission' else 'static retry path declared')+'; retry execution not established')
        for ref in support['navigation_refs'] if verbose else support['navigation_refs'][:2]:
            n = navigations[ref]
            lines.append('    navigation declared after request logic: '+endpoint(n.get('target') or '(target unresolved)', verbose=verbose, limit=120)+'; '+n['path_state']+'; runtime navigation not established')
        if verbose:
            lines += ['    ID: '+f['id'], '    Kind: '+f['kind']]
            for key in ('source_refs', 'dom_control_refs', 'static_flow_refs', 'sink_refs', 'path_condition_refs',
                        'runtime_correlation_refs', 'request_refs', 'payload_correlation_refs', 'runtime_payload_refs', 'runtime_field_refs', 'evidence_refs'):
                lines.append('    '+key+': '+(', '.join(f[key]) or 'none'))
            for variant in f['path_variants']:
                lines.append('    path variant: '+variant['flow_ref']+'; '+variant['static_path_state']+'; predicates: '+(', '.join(variant['path_condition_refs']) or 'none')+'; calls: '+(', '.join(variant['call_edge_refs']) or 'none'))
                lines.append('      transforms: '+(', '.join(variant.get('transform_refs', [])) or 'none'))
            for key in ('stage_refs', 'prefill_refs', 'retry_refs', 'navigation_refs', 'handler_refs', 'mutation_refs'):
                lines.append('    '+key+': '+(', '.join(support[key]) or 'none'))
            lines.append('    limitations: '+', '.join(f['limitations']))
    if len(visible) > len(shown) and not excluded: lines.append(f'  {len(shown)} of {len(visible)} primary findings shown. Use --verbose to inspect all primary findings.')
    if not verbose and len(excluded) > 2: lines.append(f'  ... {len(excluded) - 2} more separate evidence records (--verbose)')
    return lines
