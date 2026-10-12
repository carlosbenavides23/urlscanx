"""Generate offline correction examples; no runtime execution or external fetches."""
import contextlib
import json
from pathlib import Path
from test_interaction_corrections import model, retry, FETCH, HELPER, ERROR, PASSWORD, FORM, runtime, body_request
from test_interaction import integrity
from replay_slice5 import guard
from urlscanx.analysis.render import interaction_lines
from urlscanx import __version__


def main():
    with contextlib.ExitStack() as stack:
        guard(stack)
        cases = {
            'accepted-correlation': model(FETCH,result=runtime(body_request('{}'))),
            'contradictory-unreachable': model('if(false){'+FETCH+'}',result=runtime(body_request('{}'))),
            'context-mismatch': model(FETCH,result=runtime(body_request('{}',document='https://other.test/'))),
            'sequential-send': model(HELPER+'send();send();'),
            'if-else-send': model(HELPER+'const flag=unknown;if(flag)send();else send();'),
            'opposite-guards': model(HELPER+'const flag=unknown;if(flag)send();if(!flag)send();'),
            'unreachable-second-send': model(HELPER+'send();if(false)send();'),
            'unknown-path-compatibility': model(HELPER+'if(check())send();if(other())send();'),
            'retry-cancelled-retained': retry(ERROR+'.hidden=false;'+PASSWORD+'.value="";'),
            'retry-no-cancellation': retry(ERROR+'.hidden=false;',cancel=False),
            'error-empty': retry(ERROR+'.textContent="";'),
            'error-dynamic': retry(ERROR+'.textContent=message;'),
            'retry-navigation': retry(ERROR+'.hidden=false;location.href="/next";'),
            'retry-stage-hidden': retry(ERROR+'.hidden=false;'+FORM+'.hidden=true;'),
            'reset-alone': retry(PASSWORD+'.value="";'),
        }
        for output in cases.values(): integrity(output)
    report = ['# Slice 5 correction examples', '', f'Package {__version__}; schema 1.0; ruleset mvp-b.5. Offline static declarations.', '']
    data = {}
    for name, output in cases.items():
        report += ['## '+name, '', '```text', *interaction_lines(output.to_dict()), '```', '']
        data[name] = {'interaction':output.interaction, 'runtime_correlations':output.javascript['runtime_correlations']}
    root = Path('docs/examples/mvp-b-slice5')
    (root/'correction-report.md').write_text('\n'.join(report),encoding='utf-8')
    (root/'correction-examples.json').write_text(json.dumps(data,indent=2)+'\n',encoding='utf-8')
    print('15 correction examples verified with passive guards and reference integrity')


if __name__ == '__main__': main()
