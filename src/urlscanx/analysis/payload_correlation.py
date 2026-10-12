"""Exact payload-path correspondence, never source/value identity."""
from collections import defaultdict

MAX_PAYLOAD_CORRELATIONS = 512
ENCODINGS = {'json':'json', 'url_search_params':'form_urlencoded', 'form_data':'multipart'}


def input_fields(sink):
    """Unresolved serialization retains object input facts, not serialized paths."""
    payload=sink['payload']
    return payload.get('object_fields',[]) if payload['encoding']=='json' and payload.get('serialization_shape')!='exact' else payload['fields']


def correlate(output,registry):
    js=output.javascript
    payloads={p['request_ref']:p for p in output.runtime_payloads}
    sinks={s['id']:s for s in js['sinks']}
    runtime={c['id']:c for c in js['runtime_correlations']}
    sources={s['id']:s for s in js['sources']}
    transforms={t['id']:t for t in js['transforms']}
    flows=list(js['flows'])
    # Slice 3 intentionally invalidates bindings changed within branches. Keep
    # candidate shape facts separate; do not manufacture completed static flows.
    for sink in sinks.values():
        for field in input_fields(sink):
            if field.get('container'): continue
            if not field.get('producer_candidate'): continue
            producers=[transforms[t] for t in field['producer_transform_refs'] if t in transforms]
            states={p.get('static_path_state','unresolved') for p in producers}
            state=next((s for s in ('statically_unreachable','truncated','unresolved','conditional') if s in states),'unresolved')
            predicates=list(dict.fromkeys(p for t in producers for p in t.get('path_condition_refs',[])))
            for source in field['source_refs']:
                flows.append({'id':None,'source_id':source,'sink_id':sink['id'],'channel':'body',
                    'static_path_state':state,'path_condition_refs':predicates,
                    'semantic_role':sources[source].get('semantic_role'), '_candidate_path':field['path'],
                    'evidence_refs':list(dict.fromkeys(sources[source]['evidence_refs']+sink['evidence_refs']+[e for t in producers for e in t['evidence_refs']]))})
    producer_sets=defaultdict(set)
    proposals=[]
    def site(sink):
        return (sink['script_ref'],sink['location'].get('script_line'),sink['location'].get('script_column'))
    resolved_sites={site(s) for s in sinks.values() if s.get('execution_context')=='statically_reachable_from_call'}
    # Include constant/unknown field producers too, even without source flows.
    # A second builder can emit the same field without reading a DOM control.
    for sink in sinks.values():
        # A helper template and its resolved invocation describe the same code
        # site. The template's unknown parameters are not another builder.
        if site(sink) in resolved_sites and sink.get('execution_context')!='statically_reachable_from_call':
            continue
        corr=runtime.get(sink.get('runtime_correlation_ref'))
        if not corr or len(corr['selected_request_refs'])!=1 or corr['state'] not in {'endpoint_method_match','endpoint_method_initiator_match'}:
            continue
        request_ref=corr['selected_request_refs'][0]
        for field in input_fields(sink):
            if field.get('container'): continue
            refs=field.get('possible_source_refs',field['source_refs'])
            producer_sets[(request_ref,field['path'])].update((sink['id'],s) for s in refs or ['unknown_producer'])
    # Each flow retains its own helper and path provenance. No request/body merge.
    for flow in flows:
        if flow['channel']!='body': continue
        sink=sinks[flow['sink_id']]
        correlation=runtime.get(sink.get('runtime_correlation_ref'))
        if correlation is None: continue
        selected=correlation['selected_request_refs']
        request_ref=selected[0] if len(selected)==1 and correlation['state'] in {'endpoint_method_match','endpoint_method_initiator_match'} else None
        for field in input_fields(sink):
            if field.get('container'): continue
            if flow.get('_candidate_path') and flow['_candidate_path']!=field['path']: continue
            if flow['source_id'] not in field['source_refs']: continue
            if len(proposals)>=MAX_PAYLOAD_CORRELATIONS:
                registry.limit('PAYLOAD_CORRELATION_BUDGET','payloads','Payload structural correlation budget reached; remaining relationships unresolved.')
                js['payload_correlations_truncated']=True
                # Withhold positive relationships rather than select a producer
                # from a partially enumerated competitor set.
                for record in proposals: record['force_unresolved']=True
                break
            proposals.append({'flow':flow,'sink':sink,'correlation':correlation,'field':field,'request_ref':request_ref})
            if request_ref:
                producer_sets[(request_ref,field['path'])].update((sink['id'],s) for s in field.get('possible_source_refs',field['source_refs']))
        if js.get('payload_correlations_truncated'): break
    for ordinal,proposal in enumerate(proposals):
        flow,sink,corr,field,request_ref=(proposal[k] for k in ('flow','sink','correlation','field','request_ref'))
        payload=payloads.get(request_ref)
        shape_unresolved=sink['payload']['encoding']=='json' and sink['payload'].get('serialization_shape')!='exact'
        runtime_fields=[f for f in payload['fields'] if f['path']==field['path']] if payload and not shape_unresolved else []
        reason='runtime_request_not_uniquely_correlated';relationship='unresolved';encoding='unresolved'
        path_state=flow.get('static_path_state','unresolved')
        possible=len(producer_sets[(request_ref,field['path'])]) if request_ref else len(field.get('possible_source_refs',field['source_refs']))
        matches=[m for m in corr['requests'] if m['request_ref']==request_ref]
        if shape_unresolved:
            reason='serialization_shape_unresolved'
        elif payload:
            reason='body_not_parsed'
            expected=ENCODINGS.get(sink['payload']['encoding'])
            encoding='compatible' if expected and expected==payload['body_format'] else 'unresolved'
            if matches and matches[0]['initiator_relationship']=='script_mismatch': reason='initiator_mismatch'
            elif payload['parser_status']=='parsed':
                reason='field_not_present'
                if encoding!='compatible': reason='media_type_or_static_encoding_unresolved'
                elif runtime_fields:
                    reason='field_structure_consistent'
                    if proposal.get('force_unresolved'): reason='correlation_budget'
                    elif path_state=='statically_unreachable': reason='unreachable_static_producer'
                    elif path_state in {'unresolved','truncated'}: reason='static_path_unresolved'
                    elif possible>1: reason='competing_static_producers'
                    elif not field.get('structural_matchable') or any(not f['structural_matchable'] for f in runtime_fields): reason='field_identity_redacted_or_unresolved'
                    elif len(runtime_fields)>1 or field.get('multiplicity')!=1:
                        relationship='field_name_match';reason='multiplicity_unresolved'
                    else: relationship='field_structure_match'
        refs=list(dict.fromkeys(flow['evidence_refs']+corr['evidence_refs']+(payload['evidence_refs'] if payload else [])))
        js['payload_correlations'].append({
            'id':registry.identifier('payload-correlation',[sink['location'],sources[flow['source_id']]['location'],field['path'],request_ref,ordinal]),
            'static_flow_id':flow['id'],'static_sink_id':sink['id'],'runtime_correlation_id':corr['id'],
            'static_source_id':flow['source_id'],
            'static_producer_state':'candidate_only' if flow['id'] is None else 'static_flow_inferred',
            'runtime_request_ref':request_ref,'runtime_payload_id':payload['id'] if payload else None,
            'static_field_path':field['path'],'runtime_field_path':field['path'] if runtime_fields else None,
            'static_field_path_basis':'input_object' if shape_unresolved else 'serialized_json' if sink['payload']['encoding']=='json' else 'payload_field',
            'serialized_field_path':None if shape_unresolved else field['path'],
            'serialization_shape':sink['payload'].get('serialization_shape'),
            'runtime_field_refs':[f['id'] for f in runtime_fields], 'structural_relationship':relationship,
            'source_semantic_role':flow['semantic_role'], 'runtime_semantic_roles':sorted({f['semantic_role'] for f in runtime_fields}),
            'possible_static_producers':possible,'static_path_state':path_state,
            'path_condition_refs':flow.get('path_condition_refs',[]),'encoding_relationship':encoding,
            'condition_satisfaction':'not_established','static_producer_identity':'not_established',
            'value_relationship':'unresolved','flow_execution':'not_established','reason':reason,'evidence_refs':refs,
        })
