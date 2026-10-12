"""Compatible captured requests, never flow execution or payload equality."""
from urllib.parse import urlsplit

from .adapters import label, number, safe_url
from .javascript import endpoint

NETWORK_SINKS = {'fetch', 'xmlhttprequest', 'send_beacon', 'navigation', 'form_submit', 'form_request_submit'}
MAX_INITIATOR_FRAMES = 1  # immediate callsite only; ancestors cannot identify this sink
MAX_REQUEST_CONTEXTS_PER_SINK = 64
MAX_REQUEST_CONTEXTS_TOTAL = 256


def exact_target(url):
    """Private comparison key; query values are never serialized or hashed."""
    target = endpoint(url)
    return (*target, urlsplit(url).query) if target else None


def context_relation(event, document_url, frame_id):
    source, captured = exact_target(document_url), exact_target(event.document_url)
    if source is not None and captured is not None and source != captured:
        return 'context_mismatch'
    if frame_id and event.frame_id and frame_id != event.frame_id:
        return 'context_mismatch'
    if source is not None and captured is not None or frame_id and event.frame_id:
        return 'matched'
    return 'unresolved'


def initiator_relation(event, sink, script_url, document_url, unique_script_url, frame_id):
    if context_relation(event,document_url,frame_id) == 'context_mismatch':
        return 'context_mismatch'
    initiator = event.initiator
    if not initiator:
        return 'unresolved'
    initiator_type = initiator.get('type')
    if initiator_type is not None and initiator_type != 'script':
        return 'unresolved'
    stack = initiator.get('stack')
    frames = stack.get('callFrames') if isinstance(stack,dict) else None
    frame = frames[0] if isinstance(frames,list) and frames and isinstance(frames[0],dict) else None
    url = frame.get('url') if frame else initiator.get('url') if initiator.get('type') == 'script' else None
    if not isinstance(url,str):
        return 'unresolved'
    expected = script_url or document_url
    expected_key, url_key = exact_target(expected), exact_target(url)
    if expected_key is None or url_key is None:
        return 'unresolved'
    if script_url and unique_script_url and expected_key == url_key:
        return 'exact_script_match'
    loc = sink['location']
    if (frame and not script_url and document_url and exact_target(document_url) == exact_target(url)
            and loc.get('dom_line') is not None and loc.get('dom_column') is not None
            and number(frame.get('lineNumber')) == loc['dom_line'] - 1
            and number(frame.get('columnNumber')) == loc['dom_column']):
        return 'exact_callsite_match'
    if expected_key != url_key:
        return 'script_mismatch'
    return 'unresolved'


def correlate(js, registry, sink, target, events, *, script_url=None, document_url=None,
              unique_script_url=False, frame_id=None):
    matches = []
    source = next(s for s in js['scripts'] if s['id'] == sink['script_ref'])
    load_ref = source.get('load_request_ref')
    compatible_count = exact_count = mismatch_count = 0
    slots = min(MAX_REQUEST_CONTEXTS_PER_SINK, MAX_REQUEST_CONTEXTS_TOTAL - sum(len(c['requests']) for c in js['runtime_correlations']))
    if target and sink['sink_kind'] in NETWORK_SINKS:
        for event in events:
            if endpoint(event.raw_url) != endpoint(target) or sink['method'] and event.method != sink['method']:
                continue
            compatible_count += 1
            is_exact = exact_target(target) == exact_target(event.raw_url)
            exact_count += bool(is_exact and sink['method'] and event.method == sink['method'])
            context = context_relation(event,document_url,frame_id)
            mismatch_count += context == 'context_mismatch'
            if len(matches) >= slots:
                continue
            ref = registry.add('result', 'network_request', 'runtime_observed', {'json_pointer':event.request_pointer},
                               'Compatible origin/path request captured; flow and body relationship unresolved')
            context_ref = registry.add('result','network_request','runtime_observed',{'json_pointer':event.pointer},
                                       'Preserved request context only; static flow execution not established')
            # Scoped uniqueness also needs the request's preserved context. A
            # missing frame cannot choose between identical URLs in two frames.
            load_candidates = [load for load in events if load.resource_type == 'Script'
                               and exact_target(load.raw_url) == exact_target(script_url)
                               and context_relation(load,event.document_url,event.frame_id) != 'context_mismatch'] if script_url else []
            request_unique = unique_script_url and len(load_candidates) == 1 and load_candidates[0].pointer == load_ref
            relation = initiator_relation(event, sink, script_url, document_url, request_unique, frame_id)
            matches.append({'request_ref':event.pointer, 'evidence_refs':[ref,context_ref],
                            'target_relationship':'exact_normalized_target' if is_exact else 'origin_path_only',
                            'query_relationship':'exact' if urlsplit(target).query == urlsplit(event.raw_url).query else 'unresolved',
                            'method_relationship':'exact' if sink['method'] and event.method == sink['method'] else 'unresolved',
                            'context_relationship':context,
                            'initiator_relationship':relation, 'document_url':safe_url(event.document_url),
                            'frame_id':label(event.frame_id), 'resource_type':label(event.resource_type),
                            'request_order':event.index, 'timestamp':event.timestamp,
                            'context_role':'supporting_metadata_only'})
    rejected = [m for m in matches if m['context_relationship'] == 'context_mismatch']
    exact = [m for m in matches if m['target_relationship'] == 'exact_normalized_target' and m['method_relationship'] == 'exact'
             and m['context_relationship'] != 'context_mismatch']
    identified = [m for m in exact if m['initiator_relationship'] in {'exact_script_match','exact_callsite_match'}]
    selected = identified if len(identified) == 1 else exact
    state = ('unresolved' if target is None or sink['method'] is None else 'none')
    if len(selected) > 1:
        state = 'ambiguous_multiple_requests'
    elif selected:
        state = 'endpoint_method_initiator_match' if len(identified) == 1 else 'endpoint_method_match'
    elif matches:
        state = 'unresolved'
    truncated = compatible_count > len(matches)
    if truncated:
        state, selected = 'unresolved', []
        js['truncated'] = True
    load_evidence = [registry.add('result','network_request','runtime_observed',{'json_pointer':load_ref},
                                 'Preserved script load context; body-to-load identity used only when deterministic')] if load_ref else []
    record = {'id':registry.identifier('js-correlation',[sink['id'],[m['request_ref'] for m in matches]]),
              'sink_id':sink['id'], 'script_ref':sink['script_ref'],
              'state':state, 'compatible_request_count':compatible_count, 'exact_request_count':exact_count,
              'requests_truncated':truncated, 'budget_reason':'runtime request context budget' if truncated else None,
              'reasons':['document_frame_context_mismatch'] if mismatch_count else [],
              'context_mismatch_request_count':mismatch_count,
              'context_mismatch_request_refs':[m['request_ref'] for m in rejected],
              'script_load_ref':load_ref,
              'selected_request_refs':[m['request_ref'] for m in selected], 'requests':matches,
              'evidence_refs':list(dict.fromkeys(sink['evidence_refs']+load_evidence+[r for m in matches for r in m['evidence_refs']])),
              'static_path_state':sink['static_path_state'],
              'relationship':'contradictory_evidence' if compatible_count and sink['static_path_state']=='statically_unreachable' else 'unresolved',
              'condition_satisfaction':'not_established', 'flow_execution':'not_established',
              'payload_relationship':'unresolved', 'limitations':['Compatible request only; timing does not prove causation.']}
    js['runtime_correlations'].append(record)
    sink['runtime_correlation_ref'] = record['id']
    return record
