"""Final offline replay; archive IO occurs outside passive analysis guards.

Usage: python tests/replay_final.py FIXTURE_DIRECTORY OUTPUT_DIRECTORY
Public samples contain rendered derived facts only, never raw Result/DOM.
"""
import contextlib
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
from time import perf_counter
import tracemalloc
from unittest.mock import patch

from urlscanx.analysis import analyze, analysis_envelope
from urlscanx.analysis.render import format_analysis
from urlscanx.cli import main
from urlscanx.report import format_iocs, format_report, format_requests
from replay_slice5 import guard
from replay_slice6 import FORBIDDEN, lower
from test_findings import integrity
from test_interaction import integrity as interaction_integrity


def invoke(result, scan, dom, args):
    out, err = io.StringIO(), io.StringIO()
    def asset(scan, kind, key, **kwargs):
        return dom if kind == 'dom' else b'\x89PNG\r\n\x1a\nfixture'
    with patch('urlscanx.cli.api_key', return_value='offline-mocked-retrieval'), \
         patch('urlscanx.cli.fetch_result', return_value=result), \
         patch('urlscanx.cli.fetch_asset', side_effect=asset), \
         contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        assert main([scan, *args]) == 0, err.getvalue()
    return out.getvalue()


def replay(root, out):
    out.mkdir(parents=True, exist_ok=True)
    summaries = {}
    for number in range(1, 12):
        with tarfile.open(root/f'fixture-{number:03}.tar.gz') as archive:
            members = archive.getmembers()
            result = json.load(archive.extractfile(next(m for m in members if m.name.endswith('result.json'))))
            dom = archive.extractfile(next(m for m in members if m.name.endswith('dom.html'))).read()
        scan = result['task']['uuid']; before = deepcopy(result)
        start = perf_counter()
        with contextlib.ExitStack() as stack:
            guard(stack)
            output = analyze(result, scan, dom)
        analysis_ms = round((perf_counter()-start)*1000, 2)
        document = analysis_envelope(result, scan, dom, output, analyzed_at='fixed-replay')
        start = perf_counter()
        with contextlib.ExitStack() as stack:
            guard(stack)
            normal = format_analysis(document)
            verbose = format_analysis(document, verbose=True)
            with patch('urlscanx.analysis.findings_build', return_value=None): base = analyze(result, scan, dom)
            assert lower(output.to_dict()) == lower(base.to_dict())
            again = analyze(result, scan, dom)
            assert output.to_dict() == again.to_dict()
            assert analysis_envelope(result, scan, dom, output) == analysis_envelope(result, scan, dom, again)
            assert normal == format_analysis(analysis_envelope(result, scan, dom, again, analyzed_at='fixed-replay'))
            integrity(output); interaction_integrity(output)
            cli = json.loads(invoke(result, scan, dom, ['--analyze', '--json']))
            assert cli['result'] == result and cli['analysis'] == document['analysis']
        verification_ms = round((perf_counter()-start)*1000, 2)
        assert result == before == document['result']
        for word in FORBIDDEN: assert word.lower() not in (normal+'\n'+verbose).lower(), (number, word)
        # Non-analyze views continue to use their existing report contracts.
        for args, expected in (([], format_report(result, scan, dom)),
                               (['--verbose'], format_report(result, scan, dom, verbose=True)),
                               (['--iocs'], format_iocs(result)), (['--requests'], format_requests(result)),
                               (['--json'], json.dumps(result, indent=2, ensure_ascii=False))):
            assert invoke(result, scan, dom, args) == expected+'\n'
        if number in (1, 3, 9):
            with tempfile.TemporaryDirectory() as directory:
                previous = os.getcwd(); os.chdir(directory)
                try:
                    invoke(result, scan, dom, ['--save', '--analyze', '--json'])
                    saved = Path('urlscanx-output')/scan
                    assert json.loads((saved/'result.json').read_text(encoding='utf-8')) == before
                    assert (saved/'dom.html').read_bytes() == dom
                    sidecar = json.loads((saved/'analysis.json').read_text(encoding='utf-8'))
                    assert 'result' not in sidecar and sidecar['analysis'] == output.to_dict()
                    assert (saved/'analysis.txt').read_text(encoding='utf-8') == normal+'\n'
                finally: os.chdir(previous)
        if number == 9:
            p = next(p for p in output.network_patterns if p.kind == 'socket_io_http_polling')
            assert p.request_count == 7 and p.method_counts == {'GET':4, 'POST':3}
            assert sorted(p['request_count'] for p in p.session_partitions) == [1,6]
            assert output.evidence_coverage['websockets'].count == 0
        # Rendering allocations only: no new raw copy, AST, analysis or body parsing.
        tracemalloc.start(); start = perf_counter()
        format_analysis(document); format_analysis(document, verbose=True)
        render_ms = round((perf_counter()-start)*1000, 2)
        _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
        name = f'F{number:03}'
        (out/(name+'.txt')).write_text(normal+'\n', encoding='utf-8')
        if number in (1, 3): (out/(name+'-verbose.txt')).write_text(verbose+'\n', encoding='utf-8')
        summaries[name] = {'findings': len(output.findings), 'roles': [f['source_roles'] for f in output.findings],
                           'runtime': [f['runtime_support'] for f in output.findings],
                           'payload': [f['payload_support'] for f in output.findings],
                           'normal_lines': len(normal.splitlines()), 'verbose_lines': len(verbose.splitlines()),
                           'analysis_ms': analysis_ms, 'verification_ms': verification_ms,
                           'render_ms_instrumented': render_ms, 'render_peak_kib': round(peak/1024, 2),
                           'raw_equal': True, 'passive_guards': True, 'lower_observer_equal': True,
                           'deterministic': True, 'non_analyze_compatible': True, 'json_cli_equal': True}
        print(name, summaries[name])
    (out/'verification.json').write_text(json.dumps(summaries, indent=2)+'\n', encoding='utf-8')
    print('F001-F011 replay, raw equality, lower layers, passive, deterministic, JSON, non-analyze, save OK')


if __name__ == '__main__': replay(Path(sys.argv[1]), Path(sys.argv[2]))
