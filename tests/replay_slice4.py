"""Explicit F001-F011 offline replay and derived-only Slice 4 review artifacts.

Run: python tests/replay_slice4.py "C:/path/to/Fixtures for urlscanx"
Only archive ingestion and report writes run outside the passive guard.
"""
import contextlib
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import sys
import tarfile
from unittest.mock import patch

from urlscanx import __version__
from urlscanx.analysis import analyze, analysis_envelope
from urlscanx.analysis.model import RULESET_VERSION
from urlscanx.analysis.render import format_analysis, payload_lines
from test_static_paths import PathTests, runtime
from test_payloads import body_request, inspect_body, multipart, JSON_FLOW
from test_javascript import inspect, SCAN, READ


def integrity(output):
    PathTests().integrity(output)
    evidence={e.id for e in output.evidence}
    js=output.javascript
    flow_ids={f['id'] for f in js['flows']}
    sink_ids={s['id'] for s in js['sinks']}
    source_ids={s['id'] for s in js['sources']}
    runtime_ids={c['id'] for c in js['runtime_correlations']}
    request_refs={r['request_ref'] for r in output.network_requests or []}
    field_ids={f['id'] for p in output.runtime_payloads for f in p['fields']}
    for records in (output.runtime_payloads,js['payload_correlations']):
        assert len({r['id'] for r in records})==len(records)
        for r in records: assert set(r['evidence_refs'])<=evidence
    for p in output.runtime_payloads:
        assert p['request_ref'] in request_refs
        for f in p['fields']: assert set(f['evidence_refs'])<=evidence
    for c in js['payload_correlations']:
        assert c['static_flow_id'] is None or c['static_flow_id'] in flow_ids
        assert c['static_sink_id'] in sink_ids and c['static_source_id'] in source_ids
        assert c['runtime_correlation_id'] in runtime_ids
        assert set(c['runtime_field_refs'])<=field_ids
        assert c['value_relationship']=='unresolved' and c['flow_execution']=='not_established'


def main(root,out):
    out.mkdir(parents=True,exist_ok=True)
    results={}
    for n in range(1,12):
        with tarfile.open(root/f'fixture-{n:03}.tar.gz') as archive:
            members=archive.getmembers()
            result=json.load(archive.extractfile(next(m for m in members if m.name.endswith('result.json'))))
            dom=archive.extractfile(next(m for m in members if m.name.endswith('dom.html'))).read()
        before=deepcopy(result)
        with contextlib.ExitStack() as stack:
            for target in ('urllib.request.urlopen','urllib.request.OpenerDirector.open','socket.socket','socket.getaddrinfo',
                           'subprocess.Popen','subprocess.run','builtins.eval','builtins.exec','builtins.open','pathlib.Path.open'):
                stack.enter_context(patch(target,side_effect=AssertionError('passive boundary')))
            output=analyze(result,result['task']['uuid'],dom)
            envelope=analysis_envelope(result,result['task']['uuid'],dom,output)
            assert before==result==envelope['result']
            integrity(output)
        sensitive=[f for f in output.javascript['flows'] if f['sensitive']]
        sinks={s['id']:s for s in output.javascript['sinks']}
        body_cov=output.evidence_coverage['request_bodies']
        assert body_cov.count==body_cov.details['bodies_available']
        if n in (1,3):
            assert body_cov.availability=='unavailable' and body_cov.count==0
        if n==6:
            assert body_cov.count==18 and body_cov.details['parsed']==15 and body_cov.details['unsupported']==3
        if n==9:
            assert body_cov.count==4 and body_cov.details['unsupported']==4
        if n==1:
            assert {f['semantic_role'] for f in sensitive if (sinks[f['sink_id']]['target'] or '').endswith('/api/collect')}=={'username','password'}
            assert all(sinks[f['sink_id']]['runtime_endpoint']=='not_observed' for f in sensitive)
            assert all(c['structural_relationship']=='unresolved' for c in output.javascript['payload_correlations'])
        if n==3:
            assert {f['semantic_role'] for f in sensitive}>={'email','password','otp_candidate'}
            assert all(sinks[f['sink_id']]['target_resolution']=='unresolved' for f in sensitive if sinks[f['sink_id']]['sink_kind']=='fetch')
            assert output.evidence_coverage['request_bodies'].details['bodies_available']==0
        if n>=4: assert sensitive==[]
        if n==9:
            p=next(p for p in output.network_patterns if p.kind=='socket_io_http_polling')
            assert p.request_count==7 and p.method_counts=={'GET':4,'POST':3}
            assert sorted(p['request_count'] for p in p.session_partitions)==[1,6]
            assert output.evidence_coverage['websockets'].count==0
        assert output.findings==[]
        summary={'raw_result_deep_equal':True,'passive_guards':True,'references_valid':True,
                 'body_coverage':output.evidence_coverage['request_bodies'].__dict__,
                 'runtime_field_semantics':dict(Counter(f['semantic_role'] for p in output.runtime_payloads for f in p['fields'])),
                 'sensitive_static_roles':[f['semantic_role'] for f in sensitive],
                 'path_states':dict(Counter(f['static_path_state'] for f in output.javascript['flows'])),
                 'path_analysis':output.javascript['path_analysis'],
                 'javascript_coverage':output.evidence_coverage['javascript'].__dict__,
                 'payload_relationships':dict(Counter(c['structural_relationship'] for c in output.javascript['payload_correlations'])),
                 'network_patterns':[{'kind':p.kind,'request_count':p.request_count,'method_counts':p.method_counts} for p in output.network_patterns]}
        results[f'F{n:03}']=summary
        if n in (1,3,5,6,9,10): (out/f'F{n:03}.txt').write_text(format_analysis(envelope)+'\n',encoding='utf8')
    (out/'verification.json').write_text(json.dumps(results,indent=2)+'\n',encoding='utf8')
    examples={
        'json':inspect_body('{"email":"private","password":"hunter2"}',code=JSON_FLOW),
        'form-urlencoded':inspect_body('email=private&password=hunter2','application/x-www-form-urlencoded',
            f'const b=new URLSearchParams();b.set("password",{READ});fetch("/api",{{method:"POST",body:b}});'),
        'multipart':inspect_body(multipart([('password','hunter2',None),('upload','opaque file bytes','private.pdf')]),
            'multipart/form-data; boundary=bounded', f'const b=new FormData();b.append("password",{READ});fetch("/api",{{method:"POST",body:b}});'),
        'unavailable':inspect_body(code=JSON_FLOW),
        'malformed':inspect_body('{"password":"hunter2",',code=JSON_FLOW),
        'truncated':inspect_body('{"password":"hunter2","array":'+json.dumps(list(range(100)))+'}',code=JSON_FLOW),
        'renamed':inspect_body('{"secret":"hunter2"}',code=JSON_FLOW.replace('password:','secret:')),
        'context-mismatch':inspect_body('{"password":"hunter2"}',code=JSON_FLOW,document='https://other.test/'),
        'conditional':inspect_body('{"password":"hunter2"}',code='if(ready){'+JSON_FLOW+'}'),
        'conditional-assignment':inspect_body('{"password":"hunter2"}',code=f'const p={READ};const payload={{}};if(ready){{payload.password=p;}}fetch("/api",{{method:"POST",body:JSON.stringify(payload)}});'),
        'competing-producers':inspect_body('{"password":"hunter2"}',code=f'const a={READ};const b=document.getElementById("email").value;const payload={{}};if(ready){{payload.password=a;}}else{{payload.password=b;}}fetch("/api",{{method:"POST",body:JSON.stringify(payload)}});'),
        'unreachable':inspect_body('{"password":"hunter2"}',code='if(false){'+JSON_FLOW+'}'),
        'no-static-producer':inspect_body('{"password":"hunter2"}'),
        'ambiguous-requests':inspect(JSON_FLOW,result=runtime(body_request('{"password":"hunter2"}'),body_request('{"other":"private"}'))),
    }
    for name,output in examples.items():
        integrity(output)
        report={'schema_version':'1.0','package_version':__version__,'ruleset_version':RULESET_VERSION,'analysis':output.to_dict()}
        text=json.dumps(report,indent=2)
        assert all(secret not in text for secret in ('hunter2','opaque file bytes','private.pdf'))
        (out/(name+'.json')).write_text(text+'\n',encoding='utf8')
        (out/(name+'.txt')).write_text('\n'.join(payload_lines(output.to_dict()))+'\n',encoding='utf8')
    import test_slice4_corrections as corrections
    corrected = {
        'plain':corrections.inspect_serialization(),
        'null-replacer':corrections.inspect_serialization(arguments='payload,null'),
        'space':corrections.inspect_serialization(arguments='payload,null,2'),
        'array-replacer':corrections.inspect_serialization(arguments='payload,["other"]'),
        'toJSON':corrections.inspect_serialization('payload.toJSON=custom;'),
        'static-delete':corrections.inspect_serialization('delete payload.password;'),
        'dynamic-delete':corrections.inspect_serialization('delete payload[field];'),
        'conditional-delete':corrections.inspect_serialization('if(flag){delete payload.password;}'),
        'prototype-mutation':corrections.inspect_serialization('Object.setPrototypeOf(payload,custom);'),
        'zero-bodies':analyze(runtime(*[body_request() for _ in range(10)]),SCAN),
        'partial-bodies':analyze(runtime(*[body_request() for _ in range(9)],body_request('{}')),SCAN),
        'empty-body':inspect_body(''),
        'unsupported-body':inspect_body('opaque','text/plain'),
    }
    reports = {}
    text_reports = []
    for name,output in corrected.items():
        integrity(output)
        reports[name] = {'static_payloads':[s['payload'] for s in output.javascript['sinks'] if s['sink_kind']=='fetch'],
                         'source_count':len(output.javascript['sources']),
                         'static_flows':[{'state':f['state'],'semantic_role':f['semantic_role'],'transform_ids':f['transform_ids']} for f in output.javascript['flows']],
                         'payload_correlations':output.javascript['payload_correlations'],
                         'runtime_payloads':output.runtime_payloads,
                         'body_coverage':output.evidence_coverage['request_bodies'].__dict__}
        text_reports.append('=== '+name+' ===\n'+format_analysis(analysis_envelope({'task':{}},SCAN,None,output)))
    serialized = json.dumps({'schema_version':'1.0','package_version':__version__,'ruleset_version':RULESET_VERSION,'cases':reports},indent=2)
    assert all(secret not in serialized for secret in ('hunter2','unknown-body-value','4111111111111111'))
    (out/'corrections.json').write_text(serialized+'\n',encoding='utf8')
    (out/'corrections.txt').write_text('\n\n'.join(text_reports)+'\n',encoding='utf8')
    print(json.dumps({k:{'body_coverage':v['body_coverage']['details'],'field_semantics':v['runtime_field_semantics'],'relationships':v['payload_relationships']} for k,v in results.items()},indent=2))


if __name__=='__main__':
    main(Path(sys.argv[1]),Path('docs/examples/mvp-b-slice4'))
