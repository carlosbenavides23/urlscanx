"""Explicit original-archive replay and derived-only examples.

Run with PYTHONPATH=src and installed dependencies:
    python tests/replay_slice3.py "C:/path/to/Fixtures for urlscanx"
Archive ingestion and report writes occur outside the guarded analyzer boundary.
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
from urlscanx.analysis.render import format_analysis, javascript_lines
from test_static_paths import PathTests, FLOW, HELPER, observed, runtime
from test_javascript import inspect, READ, SCAN
from test_slice3_corrections import preserved, INITIATOR
from test_static_paths import script_load


def replay(root, out):
    out.mkdir(parents=True,exist_ok=True)
    records = {}
    for n in range(1,12):
        with tarfile.open(root/f'fixture-{n:03}.tar.gz') as archive:
            members = archive.getmembers()
            result = json.loads(archive.extractfile(next(m for m in members if m.name.endswith('result.json'))).read())
            dom = archive.extractfile(next(m for m in members if m.name.endswith('dom.html'))).read()
        before = deepcopy(result)
        with contextlib.ExitStack() as guards:
            for target in ('urllib.request.urlopen','urllib.request.OpenerDirector.open','socket.socket','socket.getaddrinfo',
                           'subprocess.Popen','subprocess.run','builtins.eval','builtins.exec','builtins.open','pathlib.Path.open'):
                guards.enter_context(patch(target,side_effect=AssertionError('passive boundary')))
            output = analyze(result,result['task']['uuid'],dom)
            envelope = analysis_envelope(result,result['task']['uuid'],dom,output)
        assert result == before and envelope['result'] == before
        PathTests().integrity(output)
        js = output.javascript
        for correlation in js['runtime_correlations']:
            assert not set(correlation['selected_request_refs']) & set(correlation['context_mismatch_request_refs'])
            selected = set(correlation['selected_request_refs'])
            assert all(m['context_relationship'] != 'context_mismatch' for m in correlation['requests'] if m['request_ref'] in selected)
        sensitive = [f for f in js['flows'] if f['sensitive']]
        sinks = {s['id']:s for s in js['sinks']}
        if n == 1:
            assert {f['semantic_role'] for f in sensitive if (sinks[f['sink_id']]['target'] or '').endswith('/api/collect')} == {'username','password'}
            assert all(sinks[f['sink_id']]['runtime_endpoint']=='not_observed' for f in sensitive)
        if n == 3:
            assert {f['semantic_role'] for f in sensitive} >= {'email','password','otp_candidate'}
            assert all(sinks[f['sink_id']]['target_resolution']=='unresolved' for f in sensitive if sinks[f['sink_id']]['sink_kind']=='fetch')
        if n >= 4:
            assert sensitive == []
        if n == 9:
            pattern = next(p for p in output.network_patterns if p.kind=='socket_io_http_polling')
            assert pattern.request_count==7 and pattern.method_counts=={'GET':4,'POST':3}
            assert sorted(p['request_count'] for p in pattern.session_partitions)==[1,6]
            assert output.evidence_coverage['websockets'].count==0
        assert output.findings == []
        records[f'F{n:03}'] = {'raw_result_deep_equal':True, 'passive_guards':True, 'references_valid':True,
            'javascript_coverage':output.evidence_coverage['javascript'].__dict__,
            'sensitive_roles':[f['semantic_role'] for f in sensitive],
            'path_states':dict(Counter(f['static_path_state'] for f in js['flows'])), 'path_analysis':js['path_analysis'],
            'runtime_correlation_states':dict(Counter(c['state'] for c in js['runtime_correlations'])),
            'context_mismatch_candidates':sum(c['context_mismatch_request_count'] for c in js['runtime_correlations']),
            'representative_correlations':[
                {'state':c['state'],'compatible_request_count':c['compatible_request_count'],
                 'selected_request_refs':c['selected_request_refs'],'reasons':c['reasons'],
                 'flow_execution':c['flow_execution'],'payload_relationship':c['payload_relationship']}
                for c in js['runtime_correlations'] if c['compatible_request_count']][:3]}
        if n in (1,3,5,6,10):
            (out/f'F{n:03}.txt').write_text(format_analysis(envelope)+'\n',encoding='utf8')
    (out/'verification.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf8')
    examples = {
        'unconditional':(FLOW,None),
        'conditional':('if(ready){'+FLOW+'}',None),
        'unreachable':('if(false){'+FLOW+'}',None),
        'truncated':('if(ready){'*11+FLOW+'}'*11,None),
        'caller-callee':('function send(x){if(enabled){fetch("/api",{method:"POST",body:x});}}'+f'if(ready){{send({READ});}}',None),
        'conditional-runtime':('if(ready){'+FLOW+'}',runtime(observed())),
        'ambiguous-runtime':(FLOW,runtime(observed(),observed(),observed())),
        'contradiction':('if(false){'+FLOW+'}',runtime(observed())),
    }
    for name,(code,result) in examples.items():
        output = inspect(code,result=result)
        PathTests().integrity(output)
        (out/(name+'.txt')).write_text('\n'.join(javascript_lines(output.javascript))+'\n',encoding='utf8')
        if name == 'conditional-runtime':
            js = output.javascript
            (out/(name+'.json')).write_text(json.dumps({'schema_version':'1.0','package_version':__version__,'ruleset_version':'mvp-b.3',
                'flow':js['flows'][0], 'path_conditions':js['path_conditions'], 'runtime_correlation':js['runtime_correlations'][0],
                'javascript_coverage':output.evidence_coverage['javascript'].__dict__},indent=2)+'\n',encoding='utf8')
    unknown = observed(); unknown['request'].pop('documentURL'); unknown['request'].pop('frameId')
    corrections = {
        'context-mismatch':inspect(FLOW,result=runtime(observed(document='https://other.test/page'))),
        'context-mixed':inspect(FLOW,result=runtime(observed(document='https://other.test/page'),unknown)),
        'duplicate-external':preserved([observed(initiator=INITIATOR)],[script_load(),script_load()],archive=True),
        'unique-external':preserved([observed(initiator=INITIATOR)]),
    }
    projections = {}
    for name,output in corrections.items():
        PathTests().integrity(output)
        (out/(name+'.txt')).write_text('\n'.join(javascript_lines(output.javascript,verbose=True))+'\n',encoding='utf8')
        projections[name] = output.javascript['runtime_correlations'][0]
    dom = ('\n'*9+'   <script\n  nonce="abc"\n  type="text/javascript">\n    fetch("/api");</script>').encode()
    output = analyze(runtime(),SCAN,dom)
    loc = output.javascript['sinks'][0]['location']
    event = observed(method='GET',initiator={'type':'script','stack':{'callFrames':[{
        'url':'https://e.test/page/index.html','lineNumber':loc['dom_line']-1,'columnNumber':loc['dom_column']}]}})
    output = analyze(runtime(event),SCAN,dom)
    projections['multiline-inline'] = {'body_location':output.javascript['scripts'][0]['body_location'],
                                      'sink_location':loc,'correlation':output.javascript['runtime_correlations'][0]}
    (out/'corrections.json').write_text(json.dumps(projections,indent=2)+'\n',encoding='utf8')
    print('F001-F011: offline replay, raw deep equality, passive guards and reference integrity OK.')
    print('F009: 7 requests, GET 4 / POST 3, partitions 1/6, preserved WebSocket entries 0.')
    print('F004-F011: no sensitive flows introduced. Derived-only examples written to',out)


if __name__ == '__main__':
    replay(Path(sys.argv[1]),Path(__file__).resolve().parents[1]/'docs/examples/mvp-b-slice3')
