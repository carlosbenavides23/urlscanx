"""Explicit archive ingestion outside analysis guards; Slice 6 offline replay."""
import contextlib
from copy import deepcopy
import json
from pathlib import Path
import sys
import tarfile
from unittest.mock import patch

from urlscanx import __version__
from urlscanx.analysis import analyze, analysis_envelope
from urlscanx.analysis.model import RULESET_VERSION, SCHEMA_VERSION
from urlscanx.analysis.render import finding_lines
from replay_slice5 import guard
from test_findings import integrity, example, FLOW, HELPER, READ, FORM, ERROR
from test_interaction import integrity as interaction_integrity

FORBIDDEN = ('phishing confirmed', 'malicious endpoint', 'fake login', 'fake error', 'victim', 'harvesting',
             'exfiltrates', 'steals', 'MFA bypass', 'same actor', 'same campaign', 'backend received data',
             'value_matched', 'password_sent', 'same_value')


def lower(data):
    data.pop('findings');data['evidence_coverage'].pop('findings',None)
    return data


def write_example(out, name, output, *, full=False):
    data=output.to_dict()
    report={'package_version':__version__,'schema_version':SCHEMA_VERSION,'ruleset_version':RULESET_VERSION,
            'findings':data['findings'],'coverage':data['evidence_coverage']['findings']}
    if full: report['analysis']=data
    normal='\n'.join(finding_lines(data));verbose='\n'.join(finding_lines(data,verbose=True))
    text=json.dumps(report['findings'])+'\n'+normal+'\n'+verbose
    for word in FORBIDDEN: assert word.lower() not in text.lower(),(name,word)
    (out/(name+'.json')).write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    (out/(name+'.txt')).write_text(normal+'\n',encoding='utf-8')
    (out/(name+'-verbose.txt')).write_text(verbose+'\n',encoding='utf-8')


def main(root):
    out=Path('docs/examples/mvp-b-slice6');out.mkdir(parents=True,exist_ok=True)
    summary={}
    for number in range(1,12):
        with tarfile.open(root/f'fixture-{number:03}.tar.gz') as archive:
            members=archive.getmembers()
            result=json.load(archive.extractfile(next(m for m in members if m.name.endswith('result.json'))))
            dom=archive.extractfile(next(m for m in members if m.name.endswith('dom.html'))).read()
        before=deepcopy(result)
        with contextlib.ExitStack() as stack:
            guard(stack)
            output=analyze(result,result['task']['uuid'],dom)
            envelope=analysis_envelope(result,result['task']['uuid'],dom,output)
            with patch('urlscanx.analysis.findings_build',return_value=None):
                base=analyze(result,result['task']['uuid'],dom)
            assert lower(output.to_dict())==lower(base.to_dict())
            assert result==before==envelope['result']
            integrity(output);interaction_integrity(output)
        if number==9:
            pattern=next(p for p in output.network_patterns if p.kind=='socket_io_http_polling')
            assert pattern.request_count==7 and pattern.method_counts=={'GET':4,'POST':3}
            assert sorted(p['request_count'] for p in pattern.session_partitions)==[1,6]
            assert output.evidence_coverage['websockets'].count==0
            assert output.findings==[]
        if number==1:
            assert {'username','password'} <= {r for f in output.findings for r in f['source_roles']}
            assert all(f['runtime_support']=='not_observed' for f in output.findings)
        if number==3:
            assert {'email','password','otp_candidate'} <= {r for f in output.findings for r in f['source_roles']}
            assert all(f['kind']=='unresolved_sensitive_flow_target' and f['sink']['target'] is None for f in output.findings)
        name=f'F{number:03}';write_example(out,name,output)
        summary[name]={'raw_result_deep_equal':True,'passive_guards':True,'references_valid':True,'lower_layers_equal_without_synthesis':True,
                       'findings':len(output.findings),'states':[f['evidence_state'] for f in output.findings],
                       'roles':[f['source_roles'] for f in output.findings],
                       'runtime_support':[f['runtime_support'] for f in output.findings],
                       'payload_support':[f['payload_support'] for f in output.findings],
                       'findings_coverage':output.evidence_coverage['findings'].details,
                       'interaction_coverage':output.interaction['coverage'],
                       'javascript_coverage':output.evidence_coverage['javascript'].__dict__,
                       'network_patterns':[{'kind':p.kind,'request_count':p.request_count,'method_counts':p.method_counts,
                                            'partitions':[p['request_count'] for p in p.session_partitions]} for p in output.network_patterns],
                       'websocket_count':output.evidence_coverage['websockets'].count}
    examples={
        'static-only':(FLOW,None),
        'runtime-endpoint':(FLOW,''),
        'runtime-payload':(FLOW,'{"secret":"hunter2"}'),
        'full-composition':(HELPER+'const flag=unknown;if(flag)send('+READ+');','{"secret":"hunter2"}'),
        'multiple-producers':(HELPER+'send('+READ+');send("constant");','{"secret":"hunter2"}'),
        'contradictory-unreachable':('if(false){'+FLOW+'}','{"secret":"hunter2"}'),
        'serialization-unresolved':('const payload={secret:'+READ+'};fetch("/api",{method:"POST",body:JSON.stringify(payload,["other"])});','{"secret":"hunter2"}'),
        'unresolved-target':('fetch(config.target,{method:"POST",body:'+READ+'});',None),
        'query-prefill':('document.getElementById("email").value=new URLSearchParams(location.search).get("email");fetch("/api",{method:"POST",body:document.getElementById("email").value});',None),
        'declared-retry':(FORM+'.addEventListener("submit",e=>{e.preventDefault();'+FLOW+ERROR+'.hidden=false;});',None),
        'unresolved-retry':(FORM+'.addEventListener("submit",()=>{'+FLOW+ERROR+'.hidden=false;});',None),
        'post-request-navigation':(FLOW+'if(response.ok){location.href="/account";}',None),
        'findings-budget':(''.join('fetch("/api'+str(i)+'",{method:"POST",body:'+READ+'});' for i in range(70)),None),
    }
    for name,(code,body) in examples.items():
        with contextlib.ExitStack() as stack:
            guard(stack);output=example(code=code,body=body);integrity(output)
        write_example(out,name,output,full=True)
    (out/'verification.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({name:{k:v[k] for k in ('findings','roles','states','runtime_support','payload_support')} for name,v in summary.items()},indent=2))
    print('F001-F011 offline replay, raw equality, references and lower-layer equality OK')


if __name__=='__main__': main(Path(sys.argv[1]))
