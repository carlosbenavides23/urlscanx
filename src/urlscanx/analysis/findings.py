"""Read-only composition of existing facts. No artifact parsing or network joins."""
from collections import Counter, defaultdict

from .adapters import safe_url
from .model import EvidenceCoverage, RULESET_VERSION, digest

MAX_FINDINGS = 64
MAX_SUPPORTING_REFS_PER_FINDING = 128
MAX_FLOW_VARIANTS_PER_FINDING = 16
MAX_LIMITATIONS_PER_FINDING = 16
MAX_STATIC_FIELDS_PER_FINDING = 32
REQUEST_KINDS = frozenset({'fetch', 'xmlhttprequest', 'send_beacon', 'form_submit', 'form_request_submit'})
# These are already assigned by DOM/source inventory, never inferred here.
ROLES = frozenset({'username', 'email', 'password', 'otp_candidate', 'payment_pan', 'payment_expiry',
                   'payment_cvc', 'phone', 'person_name', 'postal_code', 'contact_data', 'company'})
PATHS = ('statically_unreachable', 'truncated', 'unresolved', 'conditional', 'unconditional')


def index(records):
    return {r['id']: r for r in records if isinstance(r, dict) and r.get('id')}


def refs(record):
    return record.get('evidence_refs', [])


def runtime_state(correlation, requests):
    """The final correlation is authoritative; candidate arrays are not consulted."""
    if correlation is None: return 'unavailable', []
    if correlation.get('relationship') == 'contradictory_evidence': return 'contradictory', []
    if correlation.get('requests_truncated') or correlation.get('static_path_state') == 'truncated': return 'unavailable', []
    state = correlation.get('state')
    if state == 'none': return 'not_observed', []
    if correlation.get('static_path_state') == 'statically_unreachable': return 'unavailable', []
    selected = correlation.get('selected_request_refs', [])
    if state == 'ambiguous_multiple_requests' or len(selected) > 1: return 'ambiguous', []
    if state not in {'endpoint_method_match', 'endpoint_method_initiator_match'} or len(selected) != 1:
        return 'unavailable', []
    if correlation.get('relationship') in {'context_mismatch', 'ambiguous_multiple_requests'} or selected[0] not in requests:
        return 'unavailable', []
    return ('initiator_supported_request_observed' if state == 'endpoint_method_initiator_match' else 'compatible_request_observed'), selected


def display_key(finding):
    states = {'static_with_runtime_and_interaction_context': 0, 'static_with_runtime_payload_structure': 0,
              'static_with_runtime_endpoint': 1, 'static_only': 2, 'unresolved': 3,
              'contradictory': 5, 'truncated': 6}
    roles = {'password': 0, 'otp_candidate': 1, 'payment_pan': 2, 'payment_cvc': 3, 'payment_expiry': 4, 'username': 5, 'email': 6}
    return (states.get(finding['evidence_state'], 4), min((roles.get(r, 7) for r in finding['source_roles']), default=8),
            finding['sink'].get('target') or '', finding['sink'].get('method') or '', finding['id'])


def build(output, registry):
    """Only append findings/coverage; every referenced lower-layer object is unchanged."""
    js = output.javascript
    sources, sinks, flows = (index(js.get(k, [])) for k in ('sources', 'sinks', 'flows'))
    predicates, transforms, edges = (index(js.get(k, [])) for k in ('path_conditions', 'transforms', 'call_edges'))
    correlations = index(js.get('runtime_correlations', []))
    payload_correlations = index(js.get('payload_correlations', []))
    payloads = index(output.runtime_payloads)
    fields = index([f for p in payloads.values() for f in p.get('fields', [])])
    controls = index((output.dom_inventory or {}).get('controls', []))
    requests = {r['request_ref']: r for r in output.network_requests or []}
    evidence = {e.id for e in output.evidence}
    interaction = output.interaction
    stages = index(interaction.get('stages', []))
    prefills, retries, navigations, handlers, mutations = (index(interaction.get(k, [])) for k in ('prefills', 'retry_paths', 'navigations', 'handlers', 'mutations'))
    reasons, groups, invalid = [], defaultdict(list), 0

    def valid(record):
        return (bool(refs(record)) and all(r in evidence for r in refs(record))
                and all(r in predicates for r in record.get('path_condition_refs', []))
                and all(r in edges for r in record.get('call_edge_refs', [])))

    def limit(reason):
        if reason not in reasons: reasons.append(reason)

    # Group a request code site, preserving every producer and invocation variant.
    # IDs use only static refs/site material; runtime enrichment never enters them.
    for flow in sorted(flows.values(), key=lambda f: f['id']):
        source, sink = sources.get(flow.get('source_id')), sinks.get(flow.get('sink_id'))
        if source is None or sink is None:
            invalid += 1; continue
        if source.get('semantic_role') not in ROLES or sink.get('sink_kind') not in REQUEST_KINDS:
            continue
        core = [flow, source, sink]
        if source.get('control_id') and source['control_id'] not in controls:
            invalid += 1; continue
        if any(not valid(r) for r in core) or any(r not in predicates for r in flow.get('path_condition_refs', [])) or any(r not in transforms for r in flow.get('transform_ids', [])) or any(r not in edges for r in flow.get('call_edge_refs', [])):
            invalid += 1; continue
        location = sink.get('location', {})
        key = (sink.get('script_ref'), location.get('script_line'), location.get('script_column'),
               sink.get('sink_kind'), sink.get('method'), sink.get('target'), flow.get('channel'))
        groups[key].append(flow)

    candidates = []
    for site, members in sorted(groups.items(), key=lambda pair: repr(pair[0])):
        if len(members) > MAX_FLOW_VARIANTS_PER_FINDING:
            limit('flow_variant_budget'); continue
        flow_ids = sorted(f['id'] for f in members)
        sink_ids = sorted({f['sink_id'] for f in members})
        source_ids = sorted({f['source_id'] for f in members})
        static_sources = [sources[s] for s in source_ids]
        records = members + static_sources + [sinks[s] for s in sink_ids]
        paths = {f.get('static_path_state', 'unresolved') for f in members}
        path_state = next((s for s in PATHS if s in paths), 'unresolved')
        if 'statically_unreachable' in paths and len(paths) > 1:
            path_state = 'truncated' if 'truncated' in paths else 'unresolved'
        kind = 'unresolved_sensitive_flow_target' if any(sinks[s].get('target_resolution') != 'resolved' for s in sink_ids) else 'sensitive_input_to_request'
        identity = [site, sorted({s.get('control_id') or s['id'] for s in static_sources})]
        f = {'id': 'finding-' + digest([registry.scan_id, RULESET_VERSION, kind, identity])[:20],
             'kind': kind, 'title': 'Static input-to-request flow' if kind == 'sensitive_input_to_request' else 'Static input flow with unresolved request target',
             'source_roles': sorted({s['semantic_role'] for s in static_sources}),
             'source_refs': source_ids, 'dom_control_refs': sorted({s['control_id'] for s in static_sources if s.get('control_id')}),
             'static_flow_refs': flow_ids, 'sink_refs': sink_ids,
             'sink': {'kind': site[3], 'method': site[4], 'target': safe_url(site[5]) if site[5] else None,
                      'encoding': sinks[sink_ids[0]].get('payload', {}).get('encoding', 'unresolved'), 'channel': site[6]},
             'static_fields': [], 'static_path_state': path_state,
             'path_variants': [{'flow_ref': m['id'], 'static_path_state': m.get('static_path_state', 'unresolved'),
                                'path_condition_refs': m.get('path_condition_refs', [])[:], 'execution_context': sinks[m['sink_id']].get('execution_context', 'declared'),
                                'call_edge_refs': m.get('call_edge_refs', [])[:], 'transform_refs': m.get('transform_ids', [])[:]} for m in members],
             'path_condition_refs': sorted({p for m in members for p in m.get('path_condition_refs', [])}),
             'runtime_support': 'unavailable', 'runtime_correlation_refs': [], 'request_refs': [],
             'payload_support': 'unresolved', 'payload_correlation_refs': [], 'runtime_payload_refs': [], 'runtime_field_refs': [],
             'possible_static_producers': 1,
             'source_identity': 'unresolved', 'flow_execution': 'not_established', 'value_relationship': 'unresolved',
             'interaction_support': {'stage_refs': [], 'stage_roles': [], 'prefill_refs': [], 'retry_refs': [], 'navigation_refs': [],
                                     'handler_refs': [], 'mutation_refs': [], 'stage_execution': 'not_established', 'retry_execution': 'not_established',
                                     'runtime_navigation': 'not_established', 'submitted_value_origin': 'unresolved'},
             'limitations': ['flow_execution_not_established', 'payload_value_relationship_unresolved']}
        field_keys = set()
        for sink_id in sink_ids:
            payload = sinks[sink_id].get('payload', {})
            # Reuse explicitly preserved input fields if serialization is unresolved.
            static_fields = payload.get('object_fields', []) if payload.get('encoding') == 'json' and payload.get('serialization_shape') != 'exact' else payload.get('fields', [])
            for field in static_fields:
                producer_refs = sorted(set(field.get('possible_source_refs', field.get('source_refs', []))))
                if not set(source_ids).intersection(field.get('source_refs', [])) or field.get('container'): continue
                known = [s for s in producer_refs if s in sources and valid(sources[s])]
                if len(known) != len(producer_refs): f['limitations'].append('optional_reference_unavailable')
                item = {'path': field.get('path'), 'source_refs': known, 'sink_ref': sink_id,
                        'path_basis': 'input_object' if static_fields is payload.get('object_fields') else 'serialized_field',
                        'serialization_shape': payload.get('serialization_shape'), 'producer_candidate': bool(field.get('producer_candidate'))}
                marker = (item['path'], sink_id, tuple(known))
                if marker not in field_keys:
                    field_keys.add(marker); f['static_fields'].append(item)
                    if item['path_basis'] == 'input_object': f['limitations'].append('serialization_shape_unresolved')
                    f['possible_static_producers'] = max(f['possible_static_producers'], len(producer_refs))
        if len(f['static_fields']) > MAX_STATIC_FIELDS_PER_FINDING:
            limit('static_fields_budget'); continue
        corr_states = []
        accepted = {}
        for sink_id in sink_ids:
            corr = correlations.get(sinks[sink_id].get('runtime_correlation_ref'))
            if corr and valid(corr) and corr.get('sink_id') == sink_id:
                f['runtime_correlation_refs'].append(corr['id']); records.append(corr)
                state, selected = runtime_state(corr, requests)
                if selected and not valid(requests[selected[0]]): state, selected = 'unavailable', []
                corr_states.append(state)
                if selected: accepted[corr['id']] = selected[0]; f['request_refs'].extend(selected)
            else:
                corr_states.append('unavailable')
                if sinks[sink_id].get('runtime_correlation_ref'): f['limitations'].append('optional_reference_unavailable')
        # Aggregate conservatively: one unresolved/ambiguous variant is never hidden.
        f['runtime_support'] = next((s for s in ('contradictory', 'ambiguous', 'unavailable', 'not_observed',
                                                 'compatible_request_observed', 'initiator_supported_request_observed') if s in corr_states), 'unavailable')
        if f['runtime_support'] in {'ambiguous', 'unavailable', 'contradictory'}:
            f['limitations'].append('runtime_request_' + f['runtime_support'])
        if path_state in {'conditional', 'unresolved', 'truncated', 'statically_unreachable'}: f['limitations'].append('path_' + path_state)
        if kind == 'unresolved_sensitive_flow_target':
            f['limitations'].append('target_unresolved')
            imports = [c for c in js.get('calls', []) if c.get('kind') == 'import_unfollowed' and c.get('script_ref') == site[0] and valid(c)]
            if imports: f['limitations'].append('import_not_followed'); records.extend(imports)
        pcs = [p for p in payload_correlations.values() if p.get('static_flow_id') in flow_ids and p.get('static_sink_id') in sink_ids and p.get('static_source_id') in source_ids and flows[p['static_flow_id']]['source_id'] == p.get('static_source_id') and flows[p['static_flow_id']]['sink_id'] == p.get('static_sink_id') and valid(p)]
        payload_states = []
        for pc in sorted(pcs, key=lambda p: p['id']):
            f['payload_correlation_refs'].append(pc['id']); records.append(pc)
            f['possible_static_producers'] = max(f['possible_static_producers'], pc.get('possible_static_producers', 0))
            selected = accepted.get(pc.get('runtime_correlation_id')) if sinks[pc['static_sink_id']].get('runtime_correlation_ref') == pc.get('runtime_correlation_id') else None
            payload = payloads.get(pc.get('runtime_payload_id'))
            runtime_fields = [fields[r] for r in pc.get('runtime_field_refs', []) if r in fields]
            if not selected or selected != pc.get('runtime_request_ref') or not payload or payload.get('request_ref') != selected or not valid(payload):
                payload_states.append('body_unavailable'); continue
            f['runtime_payload_refs'].append(payload['id']); records.append(payload)
            if payload.get('parser_status') != 'parsed' or payload.get('truncation', {}).get('truncated'):
                payload_states.append('body_unavailable' if payload.get('body_availability') == 'unavailable' else 'body_unsupported'); continue
            if len(runtime_fields) != len(pc.get('runtime_field_refs', [])) or any(not valid(r) for r in runtime_fields):
                f['limitations'].append('optional_reference_unavailable'); payload_states.append('unresolved'); continue
            # A field ref must belong to this payload, not merely exist globally.
            if any(r['id'] not in {x['id'] for x in payload.get('fields', [])} for r in runtime_fields):
                payload_states.append('unresolved'); continue
            f['runtime_field_refs'].extend(r['id'] for r in runtime_fields); records.extend(runtime_fields)
            if pc.get('structural_relationship') == 'field_structure_match' and pc.get('encoding_relationship') == 'compatible' and pc.get('static_producer_state') == 'static_flow_inferred' and pc.get('static_path_state') in {'unconditional', 'conditional'} and runtime_fields and path_state in {'unconditional', 'conditional'} and f['runtime_support'] in {'compatible_request_observed', 'initiator_supported_request_observed'} and pc.get('possible_static_producers') == 1:
                payload_states.append('structurally_correlated')
            elif pc.get('possible_static_producers', 0) > 1 or pc.get('reason') == 'multiplicity_unresolved': payload_states.append('ambiguous')
            elif runtime_fields: payload_states.append('runtime_field_observed')
            else: payload_states.append('unresolved')
        if set(flow_ids) - {p['static_flow_id'] for p in pcs}: payload_states.append('unresolved')
        if not payload_states: payload_states = ['body_unavailable']
        f['payload_support'] = next(s for s in ('body_unavailable', 'body_unsupported', 'ambiguous', 'unresolved', 'runtime_field_observed', 'structurally_correlated') if s in payload_states)
        if f['possible_static_producers'] > 1: f['limitations'].append('multiple_static_producers')
        if f['payload_support'] == 'body_unavailable': f['limitations'].append('runtime_body_unavailable')
        linked_stages = [s for s in stages.values() if valid(s) and any(m['id'] in s.get('static_flow_refs', []) and m['sink_id'] in s.get('sink_refs', []) for m in members)]
        support = f['interaction_support']
        for stage in sorted(linked_stages, key=lambda s: s['id']):
            support['stage_refs'].append(stage['id']); support['stage_roles'].extend(stage.get('semantic_roles', [])); records.append(stage)
            for retry in sorted(retries.values(), key=lambda r: r['id']):
                if retry.get('stage_ref') != stage['id'] or not valid(retry): continue
                if retry.get('kind') == 'static_repeated_submission':
                    if retry.get('state') != 'repeated_submission_declared' or stage.get('repeated_submission_relationship') != 'declared': continue
                    if not set(retry.get('sink_refs', [])).intersection(sink_ids): continue
                else:
                    h = handlers.get(retry.get('handler_ref'))
                    if not h or not valid(h) or h.get('retry_relationship') != 'declared' or retry.get('state') != 'retry_path_declared': continue
                    dependent = retry.get('error_mutation_refs', []) + retry.get('field_reset_refs', [])
                    if any(r not in mutations or not valid(mutations[r]) for r in dependent): continue
                    support['handler_refs'].append(h['id']); support['mutation_refs'].extend(dependent); records.extend([h] + [mutations[r] for r in dependent])
                support['retry_refs'].append(retry['id']); records.append(retry)
        for prefill in sorted(prefills.values(), key=lambda p: p['id']):
            if prefill.get('target_control_ref') not in f['dom_control_refs'] or not valid(prefill): continue
            if prefill.get('source_kind') not in {'url_query', 'url_fragment', 'localStorage', 'sessionStorage', 'dom_control'} or prefill.get('path_state') in {'statically_unreachable', 'truncated'}: continue
            if prefill.get('source_control_ref') and prefill['source_control_ref'] not in controls: continue
            if prefill.get('source_ref') and prefill['source_ref'] not in sources and prefill['source_ref'] not in evidence: continue
            if prefill['id'] not in support['prefill_refs']: support['prefill_refs'].append(prefill['id']); records.append(prefill)
        for nav in sorted(navigations.values(), key=lambda n: n['id']):
            if nav.get('relation_to_submit') == 'static_after_request' and set(nav.get('request_sink_refs', [])).intersection(sink_ids) and nav.get('path_state') in {'conditional', 'unconditional'} and valid(nav) and all(s in sinks for s in nav.get('request_sink_refs', [])):
                if nav['id'] not in support['navigation_refs']: support['navigation_refs'].append(nav['id']); records.append(nav)
        if linked_stages: f['limitations'].append('stage_execution_not_established')
        for key in ('stage_refs', 'stage_roles', 'prefill_refs', 'retry_refs', 'navigation_refs', 'handler_refs', 'mutation_refs'):
            support[key] = sorted(set(support[key]))
        for key in ('runtime_correlation_refs', 'request_refs', 'payload_correlation_refs', 'runtime_payload_refs', 'runtime_field_refs'):
            f[key] = sorted(set(f[key]))
        if path_state == 'statically_unreachable' or f['runtime_support'] == 'contradictory': f['evidence_state'] = 'contradictory' if f['runtime_support'] == 'contradictory' else 'unresolved'
        elif path_state == 'truncated': f['evidence_state'] = 'truncated'
        elif path_state == 'unresolved' or kind == 'unresolved_sensitive_flow_target': f['evidence_state'] = 'unresolved'
        elif f['payload_support'] == 'structurally_correlated': f['evidence_state'] = 'static_with_runtime_and_interaction_context' if linked_stages else 'static_with_runtime_payload_structure'
        elif f['runtime_support'] in {'compatible_request_observed', 'initiator_supported_request_observed'}: f['evidence_state'] = 'static_with_runtime_endpoint'
        else: f['evidence_state'] = 'static_only'
        f['limitations'] = sorted(set(f['limitations']))
        f['evidence_refs'] = sorted({r for record in records for r in refs(record) if r in evidence})
        # Do not publish an incomplete positive composition if its reference budget
        # cannot preserve provenance. Full lower-layer inventories remain available.
        references = set(f['evidence_refs'] + source_ids + flow_ids + sink_ids + f['dom_control_refs'] + f['path_condition_refs'])
        for key in ('runtime_correlation_refs', 'request_refs', 'payload_correlation_refs', 'runtime_payload_refs', 'runtime_field_refs'):
            references.update(f[key])
        for key in ('stage_refs', 'prefill_refs', 'retry_refs', 'navigation_refs', 'handler_refs', 'mutation_refs'): references.update(support[key])
        for variant in f['path_variants']: references.update(variant['transform_refs'] + variant['call_edge_refs'])
        for field in f['static_fields']: references.update(field['source_refs'])
        if len(references) > MAX_SUPPORTING_REFS_PER_FINDING: limit('supporting_refs_budget'); continue
        if len(f['limitations']) > MAX_LIMITATIONS_PER_FINDING: limit('limitations_budget'); continue
        candidates.append(f)
    candidates.sort(key=display_key)
    if len(candidates) > MAX_FINDINGS: limit('findings_budget')
    output.findings = candidates[:MAX_FINDINGS]
    counts = Counter(f['evidence_state'] for f in output.findings)
    details = {'candidate_static_flows': sum(len(g) for g in groups.values()), 'findings_emitted': len(output.findings),
               'deduplicated_flows': sum(max(0, len(f['static_flow_refs']) - 1) for f in output.findings),
               'invalid_core_candidates': invalid, 'state_counts': dict(sorted(counts.items())),
               'runtime_enriched': sum(f['runtime_support'] in {'compatible_request_observed', 'initiator_supported_request_observed'} for f in output.findings),
               'payload_enriched': sum(f['payload_support'] == 'structurally_correlated' for f in output.findings),
               'interaction_enriched': sum(bool(f['interaction_support']['stage_refs']) for f in output.findings),
               'truncated': bool(reasons), 'reasons': reasons,
               'budgets': {'findings': MAX_FINDINGS, 'supporting_refs': MAX_SUPPORTING_REFS_PER_FINDING,
                           'flow_variants': MAX_FLOW_VARIANTS_PER_FINDING, 'limitations': MAX_LIMITATIONS_PER_FINDING,
                           'static_fields': MAX_STATIC_FIELDS_PER_FINDING}}
    lower_coverage = output.evidence_coverage.get('javascript')
    lower_partial = lower_coverage is not None and lower_coverage.inspection != 'complete'
    details['lower_static_coverage'] = {'availability': lower_coverage.availability, 'inspection': lower_coverage.inspection} if lower_coverage else None
    output.evidence_coverage['findings'] = EvidenceCoverage('available', 'partial' if reasons or invalid or lower_partial else 'complete', len(output.findings),
                                                          'Read-only bounded evidence synthesis; execution and value identity unresolved', details=details)
