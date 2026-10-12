"""Explicit offline Slice 5 replay. Archive ingestion/report writes precede/follow guards."""
import contextlib
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import sys
import tarfile
from unittest.mock import patch

from urlscanx import __version__
from urlscanx.analysis import analyze, analysis_envelope, interaction
from urlscanx.analysis.model import RULESET_VERSION, SCHEMA_VERSION
from urlscanx.analysis.paths import PathFlowEngine
from urlscanx.analysis.render import format_analysis, interaction_lines
import replay_slice4
import test_interaction as cases
from test_static_paths import runtime
from test_payloads import body_request


def baseline(*args, **kwargs):
    kwargs.pop('interaction', None)
    return PathFlowEngine(*args, **kwargs)


def guard(stack):
    for target in ('urllib.request.urlopen', 'urllib.request.OpenerDirector.open', 'socket.socket', 'socket.getaddrinfo',
                   'subprocess.Popen', 'subprocess.run', 'builtins.eval', 'builtins.exec', 'builtins.open', 'pathlib.Path.open'):
        stack.enter_context(patch(target, side_effect=AssertionError('passive boundary')))


def main(root, out):
    out.mkdir(parents=True, exist_ok=True)
    summaries = {}
    for number in range(1, 12):
        with tarfile.open(root / f'fixture-{number:03}.tar.gz') as archive:
            members = archive.getmembers()
            result = json.load(archive.extractfile(next(m for m in members if m.name.endswith('result.json'))))
            dom = archive.extractfile(next(m for m in members if m.name.endswith('dom.html'))).read()
        before = deepcopy(result)
        with contextlib.ExitStack() as stack:
            guard(stack)
            output = analyze(result, result['task']['uuid'], dom)
            envelope = analysis_envelope(result, result['task']['uuid'], dom, output)
            with patch.object(interaction, 'InteractionFlowEngine', side_effect=baseline):
                lower = analyze(result, result['task']['uuid'], dom)
            assert output.javascript == lower.javascript
            assert output.runtime_payloads == lower.runtime_payloads
            assert output.dom_inventory == lower.dom_inventory
            assert output.network_requests == lower.network_requests
            assert output.network_patterns == lower.network_patterns
            assert before == result == envelope['result']
            replay_slice4.integrity(output); cases.integrity(output)
        assert output.findings == []
        if number == 9:
            pattern = next(p for p in output.network_patterns if p.kind == 'socket_io_http_polling')
            assert pattern.request_count == 7 and pattern.method_counts == {'GET': 4, 'POST': 3}
            assert sorted(p['request_count'] for p in pattern.session_partitions) == [1, 6]
            assert output.evidence_coverage['websockets'].count == 0
            assert output.interaction['transitions'] == []
        if number in (4, 5, 6): assert not any(f['sensitive'] for f in output.javascript['flows'])
        if number == 1:
            sinks = {s['id']: s for s in output.javascript['sinks']}
            flows = [f for f in output.javascript['flows'] if f['sensitive']]
            assert {f['semantic_role'] for f in flows} == {'username', 'password'}
            assert all(sinks[f['sink_id']]['runtime_endpoint'] == 'not_observed' for f in flows)
        if number == 3:
            assert {'email', 'password', 'otp_candidate'} <= {f['semantic_role'] for f in output.javascript['flows'] if f['sensitive']}
        normal = format_analysis(envelope); verbose = format_analysis(envelope, verbose=True)
        structural = json.dumps(output.interaction) + '\n' + '\n'.join(interaction_lines(output.to_dict()))
        for word in cases.FORBIDDEN: assert word.lower() not in structural.lower(), (number, word)
        prefix = f'F{number:03}'
        (out / (prefix + '.txt')).write_text(normal + '\n', encoding='utf-8')
        (out / (prefix + '-verbose.txt')).write_text(verbose + '\n', encoding='utf-8')
        (out / (prefix + '.json')).write_text(json.dumps(output.interaction, indent=2) + '\n', encoding='utf-8')
        summary = {'raw_result_deep_equal': True, 'passive_guards': True, 'references_valid': True,
                   'lower_layers_equal_without_interaction': True, 'interaction_coverage': output.interaction['coverage'],
                   'stage_roles': [s['semantic_roles'] for s in output.interaction['stages']],
                   'mutation_kinds': dict(Counter(m['kind'] for m in output.interaction['mutations'])),
                   'prefill_kinds': dict(Counter(p['source_kind'] for p in output.interaction['prefills'])),
                   'navigation_relationships': dict(Counter(n['relation_to_submit'] for n in output.interaction['navigations'])),
                   'javascript_coverage': output.evidence_coverage['javascript'].__dict__,
                   'body_coverage': output.evidence_coverage['request_bodies'].__dict__,
                   'sensitive_static_roles': [f['semantic_role'] for f in output.javascript['flows'] if f['sensitive']],
                   'network_patterns': [{'kind': p.kind, 'request_count': p.request_count, 'method_counts': p.method_counts} for p in output.network_patterns]}
        summaries[prefix] = summary
    (out / 'verification.json').write_text(json.dumps(summaries, indent=2) + '\n', encoding='utf-8')

    examples = {
        'one-stage': cases.model(),
        'unordered': cases.model('', cases.MULTI),
        'multi-stage': cases.model(cases.MULTI_CODE, cases.MULTI, runtime(body_request('{"password":"hunter2"}'))),
        'url-prefill': cases.model(cases.PREFILL + 'email.value=new URLSearchParams(location.search).get("email");'),
        'storage-prefill': cases.model(cases.PREFILL + 'email.value=localStorage.getItem("email");'),
        'retry-counter-reset': cases.model('let attempts=0;document.getElementById("login").onsubmit=()=>{if(failed){document.getElementById("error").hidden=false;document.getElementById("password").value="";attempts++;}};'),
        'post-request-navigation': cases.model('fetch("/api");location.replace("/account");'),
        'conditional-navigation': cases.model('fetch("/api");if(response.ok){location.href="/home";}'),
        'deferred-navigation': cases.model('setTimeout(()=>location.href="/home",2000);'),
        'await-navigation': cases.model('async function submit(){await fetch("/api");location.href="/home";}'),
        'promise-unresolved': cases.model('fetch("/api").then(()=>location.href="/home");'),
        'stage-runtime-request': cases.model('fetch("/api",{method:"POST",body:document.getElementById("password").value});', result=runtime(body_request('{"password":"hunter2"}'))),
    }
    with patch.object(interaction, 'MAX_STAGES', 2):
        examples['budget-truncated'] = cases.model(cases.MULTI_CODE, cases.MULTI)
    for name, output in examples.items():
        replay_slice4.integrity(output); cases.integrity(output)
        report = {'package_version': __version__, 'schema_version': SCHEMA_VERSION, 'ruleset_version': RULESET_VERSION,
                  'analysis': output.to_dict()}
        raw = json.dumps(report, indent=2)
        assert 'hunter2' not in raw
        (out / (name + '.json')).write_text(raw + '\n', encoding='utf-8')
        (out / (name + '.txt')).write_text('\n'.join(interaction_lines(output.to_dict())) + '\n', encoding='utf-8')
        (out / (name + '-verbose.txt')).write_text('\n'.join(interaction_lines(output.to_dict(), verbose=True)) + '\n', encoding='utf-8')
    print(json.dumps({k: {'stages': v['stage_roles'], 'coverage': v['interaction_coverage'],
                         'mutations': v['mutation_kinds'], 'prefills': v['prefill_kinds']} for k, v in summaries.items()}, indent=2))


if __name__ == '__main__': main(Path(sys.argv[1]), Path('docs/examples/mvp-b-slice5'))
