"""Conservative composition, authority, bounded refs, privacy and passive invariants."""
import contextlib
from copy import deepcopy
import hashlib
import json
import unittest
from unittest.mock import patch

from urlscanx.analysis import analyze, analysis_envelope, findings
from urlscanx.analysis.model import Registry
from urlscanx.analysis.render import finding_lines, format_analysis
from test_interaction import model, ONE, READ, SCAN, integrity as interaction_integrity
from test_static_paths import runtime
from test_payloads import body_request

FLOW = 'const p='+READ+';fetch("/api",{method:"POST",body:JSON.stringify({secret:p})});'
HELPER = 'function send(p){fetch("/api",{method:"POST",body:JSON.stringify({secret:p})});}'
FORM = 'document.getElementById("login")'
ERROR = 'document.getElementById("error")'


def example(code=FLOW, body=None, html=ONE):
    result=runtime(body_request(body)) if body is not None else runtime()
    return model(code,html,result=result)


def compose(output):
    output.findings=[];output.evidence_coverage.pop('findings',None)
    findings.build(output,Registry(output,SCAN,{}))
    return output


def integrity(output):
    data=output.to_dict();js=data['javascript'];ui=data['interaction']
    ids=lambda xs:{r['id'] for r in xs}
    evidence=ids(data['evidence'])
    maps={'source_refs':ids(js['sources']),'dom_control_refs':ids((data['dom_inventory'] or {}).get('controls',[])),
          'static_flow_refs':ids(js['flows']),'sink_refs':ids(js['sinks']),'path_condition_refs':ids(js['path_conditions']),
          'runtime_correlation_refs':ids(js['runtime_correlations']), 'request_refs':{r['request_ref'] for r in data['network_requests'] or []},
          'payload_correlation_refs':ids(js['payload_correlations']), 'runtime_payload_refs':ids(data['runtime_payloads']),
          'runtime_field_refs':ids([f for p in data['runtime_payloads'] for f in p['fields']]),'evidence_refs':evidence}
    for f in data['findings']:
        for k,valid in maps.items(): assert set(f[k])<=valid,(k,f[k])
        for v in f['path_variants']:
            assert v['flow_ref'] in maps['static_flow_refs']
            assert set(v['path_condition_refs'])<=maps['path_condition_refs']
            assert set(v['call_edge_refs'])<=ids(js['call_edges'])
            assert set(v['transform_refs'])<=ids(js['transforms'])
        for field in f['static_fields']:
            assert set(field['source_refs'])<=maps['source_refs']
            assert field['sink_ref'] in maps['sink_refs']
        for key,category in (('stage_refs','stages'),('prefill_refs','prefills'),('retry_refs','retry_paths'),('navigation_refs','navigations'),('handler_refs','handlers'),('mutation_refs','mutations')):
            assert set(f['interaction_support'][key])<=ids(ui[category]),key
        assert f['flow_execution']=='not_established' and f['value_relationship']=='unresolved'
        assert 'severity' not in f and 'confidence' not in f and 'score' not in f


class CompositionTests(unittest.TestCase):
    def one(self, **kwargs):
        o=example(**kwargs);integrity(o);self.assertEqual(len(o.findings),1);return o,o.findings[0]
    def test_static_only(self):
        o,f=self.one();self.assertEqual(f['kind'],'sensitive_input_to_request')
        self.assertEqual(f['evidence_state'],'static_only');self.assertEqual(f['runtime_support'],'not_observed')
        self.assertEqual(f['source_roles'],['password']);self.assertEqual(f['static_fields'][0]['path'],'$.secret')
    def test_endpoint_enrichment(self):
        o,f=self.one(body='')
        self.assertEqual(f['evidence_state'],'static_with_runtime_endpoint');self.assertTrue(f['request_refs'])
    def test_payload_enrichment(self):
        o,f=self.one(body='{"secret":"hunter2"}')
        self.assertEqual(f['payload_support'],'structurally_correlated')
        self.assertEqual(f['evidence_state'],'static_with_runtime_and_interaction_context')
        self.assertTrue(f['runtime_payload_refs']);self.assertTrue(f['runtime_field_refs'])
    def test_same_id_across_enrichment(self):
        values=[example(body=b).findings[0]['id'] for b in (None,'','{"secret":"hunter2"}')]
        self.assertEqual(len(set(values)),1)
    def test_same_id_across_values_and_timestamps(self):
        a=example(body='{"secret":"hunter2"}');b=example(body='{"secret":"different-password"}')
        self.assertEqual(a.findings[0]['id'],b.findings[0]['id'])
        b.network_requests[0]['timestamp']=99999;compose(b)
        self.assertEqual(a.findings[0]['id'],b.findings[0]['id'])
    def test_full_conditional_helper(self):
        o,f=self.one(code=HELPER+'const flag=unknown;if(flag)send('+READ+');',body='{"secret":"hunter2"}')
        self.assertEqual(f['static_path_state'],'conditional');self.assertEqual(f['payload_support'],'structurally_correlated')
        self.assertTrue(any(v['call_edge_refs'] for v in f['path_variants']))
        self.assertTrue(f['interaction_support']['stage_refs'])
    def test_equivalent_helper_alias_dedup(self):
        o,f=self.one(code=HELPER+'const p='+READ+';const alias=p;send(p);send(alias);')
        self.assertEqual(len(f['static_flow_refs']),2)
        self.assertEqual(len(f['path_variants']),2)
    def test_two_password_producers(self):
        html=ONE.replace('<input id="email" type="email">','<input id="other" type="password">')
        o,f=self.one(code=HELPER+'send('+READ+');send(document.getElementById("other").value);',html=html,body='{"secret":"hunter2"}')
        self.assertEqual(len(f['source_refs']),2);self.assertEqual(f['possible_static_producers'],2)
        self.assertEqual(f['payload_support'],'ambiguous');self.assertEqual(f['source_identity'],'unresolved')
    def test_mixed_possible_producers(self):
        o,f=self.one(code=HELPER+'send('+READ+');send("constant");',body='{"secret":"hunter2"}')
        self.assertEqual(f['possible_static_producers'],2);self.assertNotEqual(f['payload_support'],'structurally_correlated')
    def test_different_path_states_preserved(self):
        o,f=self.one(code=HELPER+'send('+READ+');if(flag)send('+READ+');')
        self.assertEqual(f['static_path_state'],'conditional')
        self.assertEqual({p['static_path_state'] for p in f['path_variants']},{'conditional','unconditional'})
    def test_unresolved_target(self):
        o,f=self.one(code='fetch(config.endpoint,{method:"POST",body:'+READ+'});')
        self.assertEqual(f['kind'],'unresolved_sensitive_flow_target');self.assertIn('target_unresolved',f['limitations'])
    def test_import_unfollowed_is_not_causal_artifact_claim(self):
        # Module syntax must be explicitly declared by the artifact.
        from test_javascript import inspect
        o=inspect('import config from "./missing.js";fetch(config.endpoint,{body:'+READ+'});',html=ONE,script_type='module')
        integrity(o);self.assertIn('import_not_followed',o.findings[0]['limitations'])
        self.assertNotIn('imported_artifact_unavailable',o.findings[0]['limitations'])
    def test_dead_flow_kept_only_verbose(self):
        o,f=self.one(code='if(false){'+FLOW+'}')
        self.assertEqual(f['static_path_state'],'statically_unreachable')
        self.assertNotIn('has a static flow','\n'.join(finding_lines(o.to_dict())))
        self.assertIn('statically_unreachable','\n'.join(finding_lines(o.to_dict(),verbose=True)))
    def test_unreachable_without_runtime_is_not_contradictory(self):
        o,f=self.one(code='if(false){'+FLOW+'}')
        self.assertEqual(f['runtime_support'],'not_observed')
        self.assertNotEqual(f['evidence_state'],'contradictory')
    def test_mixed_dead_and_live_variants_not_flattened(self):
        o,f=self.one(code=HELPER+'send('+READ+');if(false)send('+READ+');')
        self.assertEqual(f['static_path_state'],'unresolved')
        self.assertEqual({v['static_path_state'] for v in f['path_variants']},{'unconditional','statically_unreachable'})
    def test_contradictory_not_enriched(self):
        o,f=self.one(code='if(false){'+FLOW+'}',body='{"secret":"hunter2"}')
        self.assertEqual(f['runtime_support'],'contradictory');self.assertEqual(f['evidence_state'],'contradictory')
        self.assertNotEqual(f['payload_support'],'structurally_correlated')
    def test_storage_and_navigation_are_not_request_flows(self):
        self.assertEqual(example(code='localStorage.setItem("p",'+READ+');location.href='+READ+';').findings,[])
    def test_no_static_source_relation(self):
        self.assertEqual(example(code='fetch("/api",{method:"POST",body:"constant"});',body='{"password":"hunter2"}').findings,[])
    def test_runtime_body_alone(self):
        self.assertEqual(example(code='',body='{"password":"hunter2"}').findings,[])
    def test_network_proximity(self):
        self.assertEqual(example(code='const p='+READ+';',body='{"password":"hunter2"}').findings,[])
    def test_declared_function_stays_declared(self):
        o,f=self.one(code='function neverCalled(){'+FLOW+'}',body='{"secret":"hunter2"}')
        self.assertEqual(f['flow_execution'],'not_established')
        self.assertEqual(f['path_variants'][0]['execution_context'],'declared')
    def test_unresolved_serialization_no_correspondence(self):
        code='const payload={secret:'+READ+'};fetch("/api",{method:"POST",body:JSON.stringify(payload,["other"])});'
        o,f=self.one(code=code,body='{"secret":"hunter2"}')
        self.assertNotEqual(f['payload_support'],'structurally_correlated')
        self.assertEqual(f['static_fields'][0]['path_basis'],'input_object')
        self.assertIn('input object fields (serialization unresolved)', '\n'.join(finding_lines(o.to_dict())))
        self.assertNotIn('static serialized fields:', '\n'.join(finding_lines(o.to_dict())))


class AuthorityAndReferenceTests(unittest.TestCase):
    def output(self): return example(body='{"secret":"hunter2"}')
    def test_unresolved_correlation_never_upgraded_from_candidates(self):
        o=self.output();o.javascript['runtime_correlations'][0]['state']='unresolved';compose(o);integrity(o)
        self.assertEqual(o.findings[0]['runtime_support'],'unavailable');self.assertNotEqual(o.findings[0]['payload_support'],'structurally_correlated')
    def test_empty_selection(self):
        o=self.output();o.javascript['runtime_correlations'][0]['selected_request_refs']=[];compose(o)
        self.assertEqual(o.findings[0]['runtime_support'],'unavailable')
    def test_ambiguous_correlation(self):
        o=self.output();o.javascript['runtime_correlations'][0]['state']='ambiguous_multiple_requests';compose(o)
        self.assertEqual(o.findings[0]['runtime_support'],'ambiguous')
    def test_context_mismatch(self):
        o=example(body='{"secret":"hunter2"}');o.javascript['runtime_correlations'][0]['relationship']='context_mismatch';compose(o)
        self.assertEqual(o.findings[0]['runtime_support'],'unavailable')
    def test_exact_initiator_state(self):
        o=self.output();o.javascript['runtime_correlations'][0]['state']='endpoint_method_initiator_match';compose(o)
        self.assertEqual(o.findings[0]['runtime_support'],'initiator_supported_request_observed');self.assertEqual(o.findings[0]['flow_execution'],'not_established')
    def test_invalid_source_skip(self):
        o=self.output();o.javascript['flows'][0]['source_id']='missing';compose(o);self.assertEqual(o.findings,[])
    def test_invalid_sink_skip(self):
        o=self.output();o.javascript['flows'][0]['sink_id']='missing';compose(o);self.assertEqual(o.findings,[])
    def test_invalid_core_evidence_skip(self):
        o=self.output();o.javascript['flows'][0]['evidence_refs'].append('missing');compose(o);self.assertEqual(o.findings,[])
    def test_invalid_transform_skip(self):
        o=self.output();o.javascript['flows'][0]['transform_ids'].append('missing');compose(o);self.assertEqual(o.findings,[])
    def test_invalid_predicate_skip(self):
        o=self.output();o.javascript['flows'][0]['path_condition_refs'].append('missing');compose(o);self.assertEqual(o.findings,[])
    def test_optional_correlation_absent(self):
        o=self.output();o.javascript['runtime_correlations']=[];compose(o);integrity(o)
        self.assertEqual(o.findings[0]['runtime_support'],'unavailable')
    def test_optional_payload_absent(self):
        o=self.output();o.runtime_payloads=[];compose(o);integrity(o)
        self.assertEqual(o.findings[0]['payload_support'],'body_unavailable')
    def test_optional_payload_field_absent(self):
        o=self.output();o.runtime_payloads[0]['fields']=[];compose(o);integrity(o)
        self.assertNotEqual(o.findings[0]['payload_support'],'structurally_correlated')
    def test_request_absent(self):
        o=self.output();o.network_requests=[];compose(o);integrity(o)
        self.assertEqual(o.findings[0]['runtime_support'],'unavailable')
    def test_stage_without_explicit_flow_ref_not_joined(self):
        o=self.output();o.interaction['stages'][0]['static_flow_refs']=[];compose(o)
        self.assertEqual(o.findings[0]['interaction_support']['stage_refs'],[])
    def test_payload_pc_unresolved_not_upgraded(self):
        o=self.output();o.javascript['payload_correlations'][0]['structural_relationship']='unresolved';compose(o)
        self.assertEqual(o.findings[0]['payload_support'],'runtime_field_observed')
    def test_payload_competing_producers_not_upgraded(self):
        o=self.output();p=o.javascript['payload_correlations'][0];p.update(structural_relationship='unresolved',possible_static_producers=2,reason='competing_static_producers');compose(o)
        self.assertEqual(o.findings[0]['payload_support'],'ambiguous')
    def test_unsupported_body(self):
        o=example(body='not-json');self.assertEqual(o.findings[0]['payload_support'],'body_unsupported')
    def test_missing_stage_no_duplicate_finding(self):
        o=self.output();old=o.findings[0]['id'];o.interaction['stages']=[];compose(o)
        self.assertEqual(o.findings[0]['id'],old)
        self.assertEqual(o.findings[0]['evidence_state'],'static_with_runtime_payload_structure')


class InteractionCompositionTests(unittest.TestCase):
    def test_query_prefill(self):
        code='document.getElementById("email").value=new URLSearchParams(location.search).get("email");fetch("/api",{method:"POST",body:document.getElementById("email").value});'
        o=example(code=code);integrity(o);self.assertTrue(o.findings[0]['interaction_support']['prefill_refs'])
        self.assertEqual(o.findings[0]['interaction_support']['submitted_value_origin'],'unresolved')
    def test_storage_prefill(self):
        code='document.getElementById("password").value=localStorage.getItem("saved");'+FLOW
        o=example(code=code);integrity(o);self.assertTrue(o.findings[0]['interaction_support']['prefill_refs'])
    def test_dom_prefill(self):
        code='document.getElementById("password").value=document.getElementById("email").value;'+FLOW
        o=example(code=code);integrity(o);self.assertTrue(o.findings[0]['interaction_support']['prefill_refs'])
    def test_retry_positive(self):
        code=FORM+'.addEventListener("submit",e=>{e.preventDefault();'+FLOW+ERROR+'.hidden=false;});'
        o=example(code=code);integrity(o);self.assertTrue(o.findings[0]['interaction_support']['retry_refs'])
    def test_retry_unresolved_not_promoted(self):
        code=FORM+'.addEventListener("submit",()=>{'+FLOW+ERROR+'.hidden=false;});'
        o=example(code=code);self.assertEqual(o.findings[0]['interaction_support']['retry_refs'],[])
    def test_navigation_related_only(self):
        o=example(code=FLOW+'location.href="/account";');integrity(o)
        self.assertTrue(o.findings[0]['interaction_support']['navigation_refs'])
    def test_unrelated_navigation_not_joined(self):
        o=example(code='function unrelated(){location.href="/account";}'+FLOW)
        self.assertEqual(o.findings[0]['interaction_support']['navigation_refs'],[])
    def test_opposing_branch_navigation_not_joined(self):
        o=example(code='if(flag){'+FLOW+'}else{location.href="/account";}')
        self.assertEqual(o.findings[0]['interaction_support']['navigation_refs'],[])
    def test_response_navigation_condition_kept(self):
        o=example(code=FLOW+'if(response.ok){location.href="/account";}');integrity(o)
        n=o.interaction['navigations'][0];self.assertEqual(n['path_state'],'conditional');self.assertTrue(n['path_condition_refs'])
        self.assertIn('conditional','\n'.join(finding_lines(o.to_dict())))
    def test_repetition_positive_only(self):
        o=example(code=HELPER+'send('+READ+');send('+READ+');');integrity(o)
        self.assertTrue(o.findings[0]['interaction_support']['retry_refs'])
    def test_alternative_paths_no_repetition_context(self):
        o=example(code=HELPER+'const flag=unknown;if(flag)send('+READ+');else send('+READ+');')
        self.assertEqual(o.findings[0]['interaction_support']['retry_refs'],[])


class BudgetAndPresentationTests(unittest.TestCase):
    def many(self): return example(code=''.join('fetch("/api'+str(i)+'",{method:"POST",body:'+READ+'});' for i in range(70)))
    def test_findings_budget_deterministic(self):
        a=self.many();b=self.many();self.assertEqual(len(a.findings),64);self.assertEqual(a.findings,b.findings)
        self.assertTrue(a.evidence_coverage['findings'].details['truncated']);self.assertEqual(len(a.javascript['flows']),70);integrity(a)
    def test_ref_budget_withholds_incomplete_composition(self):
        with patch.object(findings,'MAX_SUPPORTING_REFS_PER_FINDING',1): o=example()
        self.assertEqual(o.findings,[]);self.assertTrue(o.javascript['flows'])
        self.assertIn('supporting_refs_budget',o.evidence_coverage['findings'].details['reasons'])
    def test_variants_budget(self):
        with patch.object(findings,'MAX_FLOW_VARIANTS_PER_FINDING',1): o=example(code=HELPER+'send('+READ+');send('+READ+');')
        self.assertEqual(o.findings,[]);self.assertIn('flow_variant_budget',o.evidence_coverage['findings'].details['reasons'])
    def test_static_fields_budget(self):
        code='const p='+READ+';fetch("/api",{method:"POST",body:JSON.stringify({a:p,b:p})});'
        with patch.object(findings,'MAX_STATIC_FIELDS_PER_FINDING',1): o=example(code=code)
        self.assertEqual(o.findings,[]);self.assertEqual(len(o.javascript['sinks'][0]['payload']['fields']),2)
        self.assertIn('static_fields_budget',o.evidence_coverage['findings'].details['reasons'])
    def test_limitations_budget(self):
        with patch.object(findings,'MAX_LIMITATIONS_PER_FINDING',1): o=example()
        self.assertEqual(o.findings,[]);self.assertIn('limitations_budget',o.evidence_coverage['findings'].details['reasons'])
    def test_default_limit_verbose_all(self):
        o=self.many();a='\n'.join(finding_lines(o.to_dict()));b='\n'.join(finding_lines(o.to_dict(),verbose=True))
        self.assertIn('8 of 64 primary findings shown',a);self.assertNotIn('8 of 64 primary findings shown',b)
        self.assertIn(o.findings[-1]['id'],b)
    def test_renderer_does_not_mutate(self):
        o=example(body='{"secret":"hunter2"}');before=deepcopy(o.to_dict())
        for verbose in (False,True): finding_lines(o.to_dict(),verbose=verbose)
        self.assertEqual(o.to_dict(),before)
    def test_order_independent_of_list_order(self):
        o=self.many();before=deepcopy(o.findings)
        for key in ('flows','sources','sinks','runtime_correlations','payload_correlations'): o.javascript[key].reverse()
        compose(o);self.assertEqual(o.findings,before)
    def test_independent_layer(self):
        o=example(body='{"secret":"hunter2"}')
        with patch('urlscanx.analysis.findings_build',return_value=None): b=example(body='{"secret":"hunter2"}')
        a=o.to_dict();a.pop('findings');a['evidence_coverage'].pop('findings')
        baseline=b.to_dict();baseline.pop('findings')
        self.assertEqual(a,baseline)
    def test_lower_partial_coverage_not_hidden(self):
        o=example();o.evidence_coverage['javascript'].inspection='partial';compose(o)
        self.assertEqual(o.evidence_coverage['findings'].inspection,'partial')
        self.assertFalse(o.evidence_coverage['findings'].details['truncated'])
    def test_builder_observer_only(self):
        o=example(body='{"secret":"hunter2"}');before=deepcopy(o.to_dict());compose(o);after=o.to_dict()
        for d in (before,after): d.pop('findings');d['evidence_coverage'].pop('findings')
        self.assertEqual(before,after)


class PrivacyAndNeutralityTests(unittest.TestCase):
    FORBIDDEN=('phishing confirmed','malicious endpoint','fake login','fake error','victim','harvesting','exfiltrates','steals','MFA bypass','same actor','same campaign','backend received data','value_matched','same_value','password_sent')
    def check(self,o):
        integrity(o)
        text=json.dumps(o.findings)+'\n'+'\n'.join(finding_lines(o.to_dict(),verbose=True))
        for word in self.FORBIDDEN:self.assertNotIn(word.lower(),text.lower())
    def test_auth_hard_negative(self):
        o=example(code=FORM+'.addEventListener("submit",e=>{e.preventDefault();'+FLOW+ERROR+'.hidden=false;});',body='{"secret":"hunter2"}')
        self.assertTrue(o.findings);self.check(o)
    def test_payment_hard_negative(self):
        html=ONE.replace('id="password" type="password"','id="password" autocomplete="cc-number"')
        o=example(html=html,body='{"secret":"4111111111111111"}')
        self.assertEqual(o.findings[0]['source_roles'],['payment_pan']);self.check(o)
    def test_privacy_values_never_composed(self):
        secrets=('hunter2','123456','4111111111111111','ghp_'+'a'*36,'sk-'+'b'*32,'eyJabc.def.ghi','private@example.test')
        code='document.getElementById("email").value=new URLSearchParams(location.search).get("email");'+FLOW
        result=runtime(body_request(json.dumps({'secret':secrets[0],'otp':secrets[1],'pan':secrets[2],'other':secrets[3:]})))
        result['page']['url']='https://e.test/page/index.html?email='+secrets[-1]+'&otp=123456'
        before=deepcopy(result);o=model(code,result=result)
        self.assertEqual(result,before)
        self.assertEqual(analysis_envelope(result,SCAN,None,o)['result'],before)
        for verbose in (False,True):
            text=json.dumps(o.findings)+'\n'+'\n'.join(finding_lines(o.to_dict(),verbose=verbose))
            for secret in secrets:
                self.assertNotIn(secret,text);self.assertNotIn(hashlib.sha256(secret.encode()).hexdigest(),text)
    def test_privacy_token_field_keys(self):
        token='ghp_'+'a'*36
        o=example(code='fetch("/api",{method:"POST",body:JSON.stringify({"'+token+'":'+READ+'})});',body=json.dumps({token:'hunter2'}))
        for verbose in (False,True): self.assertNotIn(token,json.dumps(o.findings)+'\n'+'\n'.join(finding_lines(o.to_dict(),verbose=verbose)))
    def test_passive_boundary(self):
        example()  # Warm parser; no artifact ingestion within guards.
        with contextlib.ExitStack() as stack:
            for target in ('urllib.request.urlopen','urllib.request.OpenerDirector.open','socket.socket','socket.getaddrinfo','subprocess.Popen','subprocess.run','builtins.eval','builtins.exec','builtins.open','pathlib.Path.open'):
                stack.enter_context(patch(target,side_effect=AssertionError('passive boundary')))
            o=example(body='{"secret":"hunter2"}');integrity(o);self.assertTrue(o.findings)
