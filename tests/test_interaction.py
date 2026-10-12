"""Interaction declarations, provenance, independent budgets and neutral wording."""
import contextlib
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from urlscanx.analysis import analyze, analysis_envelope, interaction
from urlscanx.analysis.render import format_analysis, interaction_lines
from urlscanx.analysis.paths import PathFlowEngine
from test_javascript import inspect, SCAN, READ
from test_payloads import body_request
from test_static_paths import runtime

ONE = '<form id="login"><input id="email" type="email"><input id="password" type="password"><div id="error" role="alert" hidden></div><button id="send">Continue</button></form>'
MULTI = ('<form id="s3" hidden><input id="otp" autocomplete="one-time-code"><button>Continue</button></form>'
         '<form id="s2" hidden><input id="password" type="password"><div id="error" role="alert" hidden></div><button>Continue</button></form>'
         '<form id="s1" style="display:block"><input id="email" type="email"><button>Continue</button></form>')
ALIASES = 'const a=document.getElementById("s1");const b=document.getElementById("s2");const c=document.getElementById("s3");'
SWITCH = 'a.hidden=true;b.hidden=false;'
PREFILL = 'const email=document.getElementById("email");'
MULTI_CODE = ALIASES + '''
const p=document.getElementById("password");const err=document.getElementById("error");let attempts=0;
a.addEventListener("submit",()=>{a.hidden=true;b.hidden=false;});
b.addEventListener("submit",(event)=>{event.preventDefault();
  fetch("/api",{method:"POST",body:JSON.stringify({password:p.value})});
  if(failed){err.hidden=false;p.value="";attempts++;}
  else{b.hidden=true;c.hidden=false;}
});
c.addEventListener("submit",()=>{fetch("/verify",{method:"POST",body:document.getElementById("otp").value});location.href="/dashboard";});
'''
FORBIDDEN = ('phishing confirmed', 'credential harvesting', 'credential theft', 'fake login', 'fake error',
             'victim', 'card harvesting', 'OTP interception', 'MFA bypass', 'cloaking', 'anti-analysis',
             'backend received credentials', 'successful authentication', 'account compromise',
             'stage execution: observed', 'stage execution: executed', 'same actor', 'same campaign')


def model(code='', html=ONE, result=None): return inspect(code, html=html, result=result)


def integrity(output):
    data = output.interaction
    evidence = {e.id for e in output.evidence}
    stages = {s['id'] for s in data['stages']}
    controls = {c['id'] for c in (output.dom_inventory or {}).get('controls', [])}
    predicates = {p['id'] for p in output.javascript['path_conditions']}
    sources = {s['id'] for s in output.javascript['sources']}
    mutations = {m['id'] for m in data['mutations']}
    handlers = {h['id'] for h in data['handlers']}
    for category in ('stages', 'transitions', 'prefills', 'retry_paths', 'navigations', 'mutations', 'handlers', 'attempt_counters'):
        records = data[category]
        assert len({r['id'] for r in records}) == len(records), category
        for r in records:
            assert set(r['evidence_refs']) <= evidence, r
            assert set(r.get('path_condition_refs', [])) <= predicates
            assert r['runtime_execution'] == 'not_established'
            assert r.get('stage_ref') is None or r['stage_ref'] in stages
            assert r.get('handler_ref') is None or r['handler_ref'] in handlers
    for t in data['transitions']:
        assert t['from_stage_ref'] in stages and t['to_stage_ref'] in stages
        assert set(t['mutation_refs']) <= mutations
    for p in data['prefills']:
        assert p['target_control_ref'] in controls
        assert p.get('source_control_ref') is None or p['source_control_ref'] in controls
        assert p['source_ref'] is None or p['source_ref'] in sources | evidence
        assert p['final_submitted_value_provenance'] == 'unresolved'
    refs = {'control_refs': controls, 'container_refs': evidence,
            'static_flow_refs': {f['id'] for f in output.javascript['flows']},
            'sink_refs': {s['id'] for s in output.javascript['sinks']},
            'runtime_correlation_refs': {c['id'] for c in output.javascript['runtime_correlations']},
            'payload_correlation_refs': {c['id'] for c in output.javascript['payload_correlations']},
            'runtime_payload_refs': {p['id'] for p in output.runtime_payloads}, 'error_ui_refs': mutations}
    for stage in data['stages']:
        for key, ids in refs.items(): assert set(stage[key]) <= ids, (key,stage)


class StageTests(unittest.TestCase):
    def check(self, code='', html=MULTI):
        output = model(code, html); integrity(output); return output.interaction

    def test_one_form_multiple_roles_one_stage(self):
        d = self.check(html=ONE)
        self.assertEqual(len(d['stages']), 1)
        self.assertEqual(d['stages'][0]['semantic_roles'], ['identifier','password'])

    def test_multiple_forms_no_dom_sequence(self):
        d = self.check()
        self.assertEqual(len(d['stages']), 3); self.assertEqual(d['transitions'], [])
        self.assertEqual(d['ordering'], 'unresolved')

    def test_static_inline_visibility(self):
        d = self.check()
        self.assertEqual([s['static_visibility'] for s in d['stages']], ['hidden_candidate','hidden_candidate','visible_candidate'])

    def test_class_name_does_not_define_visibility(self):
        d = self.check(html=ONE.replace('id="login"','id="login" class="hidden active show"'))
        self.assertEqual(d['stages'][0]['static_visibility'], 'unresolved')

    def test_visibility_hidden_style(self):
        d = self.check(html=ONE.replace('id="login"','id="login" style="visibility:hidden"'))
        self.assertEqual(d['stages'][0]['static_visibility'], 'hidden_candidate')

    def test_hidden_ancestor(self):
        d = self.check(html='<section hidden>'+ONE+'</section>')
        self.assertEqual(d['stages'][0]['static_visibility'], 'hidden_candidate')

    def test_hidden_input_not_artificial_stage(self):
        d = self.check(html=ONE.replace('</form>','<input type="hidden" name="token"></form>'))
        self.assertEqual(len(d['stages']), 1)

    def test_arbitrary_div_not_stage(self):
        d = self.check(html='<div id="bag"><input type="email"></div>')
        self.assertEqual(d['stages'], [])

    def test_explicit_container_mutations_group_controls(self):
        html='<div id="s1"><input type="email"></div><div id="s2"><input type="password"></div>'
        d=self.check(ALIASES+SWITCH,html)
        self.assertEqual(len(d['stages']),2); self.assertEqual(len(d['transitions']),1)

    def test_transition_direction_not_dom_order(self):
        d=self.check(ALIASES+SWITCH); stages={s['id']:s for s in d['stages']}
        t=d['transitions'][0]
        self.assertEqual(stages[t['from_stage_ref']]['semantic_roles'],['identifier'])
        self.assertEqual(stages[t['to_stage_ref']]['semantic_roles'],['password'])

    def test_reverse_transition(self):
        d=self.check(ALIASES+'b.hidden=true;a.hidden=false;')
        roles_by_id={s['id']:s['semantic_roles'] for s in d['stages']}
        self.assertEqual(roles_by_id[d['transitions'][0]['from_stage_ref']],['password'])

    def test_display_transition(self):
        self.assertEqual(len(self.check(ALIASES+'a.style.display="none";b.style.display="block";')['transitions']),1)

    def test_conditional_transition(self):
        d=self.check(ALIASES+'if(flag){'+SWITCH+'}')
        self.assertEqual(d['transitions'][0]['path_state'],'conditional')
        self.assertTrue(d['transitions'][0]['path_condition_refs'])

    def test_dead_transition(self):
        self.assertEqual(self.check(ALIASES+'if(false){'+SWITCH+'}')['transitions'][0]['path_state'],'statically_unreachable')

    def test_opposing_branches_do_not_pair(self):
        d=self.check(ALIASES+'if(flag){a.hidden=true;}else{b.hidden=false;}')
        self.assertEqual(d['transitions'],[])

    def test_click_handler_declared(self):
        d=self.check(ALIASES+'a.addEventListener("click",()=>{'+SWITCH+'});')
        t=d['transitions'][0]; self.assertEqual(t['trigger'],'click'); self.assertEqual(t['execution_context'],'handler_declared')

    def test_submit_handler_declared(self):
        d=self.check(ALIASES+'a.addEventListener("submit",()=>{'+SWITCH+'});')
        self.assertEqual(d['transitions'][0]['trigger'],'submit')

    def test_onsubmit_handler(self):
        d=self.check(ALIASES+'a.onsubmit=()=>{'+SWITCH+'};')
        self.assertEqual(d['transitions'][0]['trigger'],'submit')

    def test_uncalled_function_declared_only(self):
        d=self.check(ALIASES+'function neverCalled(){'+SWITCH+'}')
        self.assertEqual(d['transitions'][0]['execution_context'],'declared')

    def test_deterministic_helper(self):
        d=self.check(ALIASES+'function next(){'+SWITCH+'}a.addEventListener("submit",()=>next());')
        self.assertTrue(any(t['execution_context']=='statically_reachable_from_call' for t in d['transitions']))

    def test_dynamic_selector_unresolved(self):
        d=self.check('document.getElementById(dynamic).hidden=true;')
        self.assertEqual(d['mutations'],[])

    def test_duplicate_id_unresolved(self):
        d=self.check(ALIASES+SWITCH,MULTI+'<div id="s1"></div>')
        self.assertEqual(d['transitions'],[])

    def test_shadowed_document_unresolved(self):
        d=self.check('function f(document){document.getElementById("s1").hidden=true;}')
        self.assertEqual(d['mutations'],[])

    def test_mutated_alias_unresolved(self):
        d=self.check('let a=document.getElementById("s1");a=unknown;a.hidden=true;')
        self.assertEqual(d['mutations'],[])

    def test_classlist_structural_only(self):
        d=self.check(ALIASES+'a.classList.add("hidden");b.classList.remove("hidden");')
        self.assertEqual(d['transitions'],[])
        self.assertTrue(all(m['visibility']=='unresolved' for m in d['mutations']))

    def test_content_replacement_not_generated_stage(self):
        d=self.check(ALIASES+'a.innerHTML="<input type=\\"password\\">";')
        self.assertEqual(len(d['stages']),3)
        self.assertEqual(d['mutations'][0]['kind'],'content_replacement')

    def test_multistage_retry_neutral(self):
        o=model(MULTI_CODE,MULTI,result=runtime(body_request('{"password":"hunter2"}'))); integrity(o)
        self.assertEqual(len(o.interaction['stages']),3); self.assertEqual(len(o.interaction['transitions']),2)
        self.assertEqual(len(o.interaction['retry_paths']),0)
        self.assertTrue(all(f['flow_execution']=='not_established' and f['value_relationship']=='unresolved' for f in o.findings))

    def test_named_callback_declared_registration(self):
        d=self.check(ALIASES+'function next(){'+SWITCH+'}a.addEventListener("submit",next);')
        self.assertEqual(d['transitions'][0]['trigger'],'submit')
        self.assertEqual(d['transitions'][0]['execution_context'],'declared')

    def test_named_onsubmit(self):
        d=self.check(ALIASES+'function next(){'+SWITCH+'}a.onsubmit=next;')
        self.assertEqual(d['transitions'][0]['trigger'],'submit')

    def test_multiple_registrations_no_unique_context(self):
        d=self.check(ALIASES+'function next(){'+SWITCH+'}a.addEventListener("submit",next);b.addEventListener("click",next);')
        self.assertEqual(d['transitions'][0]['trigger'],'unresolved')

    def test_unknown_call_between_mutations_not_transition_pair(self):
        d=self.check(ALIASES+'a.hidden=true;unknown();b.hidden=false;')
        self.assertEqual(d['transitions'],[])

    def test_invalid_style_value_not_visibility(self):
        d=self.check(ALIASES+'a.style.display="hidden";b.style.visibility="none";')
        self.assertEqual(d['transitions'],[])

    def test_plain_display_property_not_css(self):
        d=self.check(ALIASES+'a.display="none";b.display="block";')
        self.assertEqual(d['transitions'],[])

    def test_form_disabled_not_stage_availability(self):
        d=self.check(ALIASES+'a.disabled=true;b.disabled=false;')
        self.assertEqual(d['transitions'],[])

    def test_replaced_selector_intrinsic_not_trusted(self):
        d=self.check('document.getElementById=custom;document.getElementById("s1").hidden=true;')
        self.assertEqual(d['mutations'],[])

    def test_parameter_shadow_of_alias(self):
        d=self.check(ALIASES+'function f(a){'+SWITCH+'}')
        self.assertEqual(d['transitions'],[])

    def test_class_mutation_container_stage_without_visibility(self):
        d=self.check(ALIASES+'a.classList.add("hide");b.classList.remove("hide");',
                     '<div id="s1"><input type="email"></div><div id="s2"><input type="password"></div>')
        self.assertEqual(len(d['stages']),2);self.assertEqual(d['transitions'],[])
        self.assertTrue(all(s['static_visibility']=='unresolved' for s in d['stages']))

    def test_markup_submit_handler_not_callback_reconstruction(self):
        d=self.check(html=ONE.replace('id="login"','id="login" onsubmit="submitLogin(event)"'))
        self.assertTrue(d['stages'][0]['submission_handler_declared'])
        self.assertEqual(d['handlers'][0]['callback_body'],'not_analyzed');self.assertEqual(d['transitions'],[])

    def test_explicit_form_control_association(self):
        d=self.check(html='<form id="login"></form><input form="login" id="email" type="email">')
        self.assertEqual(len(d['stages']),1);self.assertEqual(d['stages'][0]['semantic_roles'],['identifier'])


class PrefillTests(unittest.TestCase):
    def check(self,expression,code_prefix='',html=ONE):
        o=model(PREFILL+code_prefix+'email.value='+expression+';',html); integrity(o)
        return o.interaction['prefills'][0]

    def test_url_query_prefill(self):
        p=self.check('new URLSearchParams(location.search).get("email")')
        self.assertEqual(p['source_kind'],'url_query'); self.assertEqual(p['key_name'],'email')

    def test_bound_query_params(self):
        p=self.check('params.get("email")','const params=new URLSearchParams(location.search);')
        self.assertEqual(p['source_kind'],'url_query')

    def test_otp_query_value_omitted(self):
        p=self.check('new URLSearchParams(location.search).get("otp")')
        self.assertEqual(p['key_name'],'otp'); self.assertEqual(p['values'],'[omitted]')

    def test_fragment_prefill(self):
        self.assertEqual(self.check('new URLSearchParams(location.hash.substring(1)).get("email")')['source_kind'],'url_fragment')

    def test_localstorage_prefill(self):
        self.assertEqual(self.check('localStorage.getItem("email")')['source_kind'],'localStorage')

    def test_sessionstorage_prefill(self):
        self.assertEqual(self.check('sessionStorage.getItem("email")')['source_kind'],'sessionStorage')

    def test_dom_to_dom_prefill(self):
        p=self.check('document.getElementById("password").value')
        self.assertEqual(p['source_kind'],'dom_control'); self.assertIsNotNone(p['source_control_ref'])

    def test_literal_prefill_omitted(self):
        p=self.check('"private@example.test"')
        self.assertEqual(p['source_kind'],'static_literal'); self.assertNotIn('private@',json.dumps(p))

    def test_markup_initialization(self):
        o=model('',ONE.replace('id="email"','id="email" value="private@example.test"'))
        integrity(o); self.assertEqual(o.interaction['prefills'][0]['source_kind'],'existing_dom_value')

    def test_conditional_prefill(self):
        o=model(PREFILL+'if(flag){email.value=localStorage.getItem("email");}')
        self.assertEqual(o.interaction['prefills'][0]['path_state'],'conditional')

    def test_prefill_payload_independent(self):
        o=model(PREFILL+'email.value=new URLSearchParams(location.search).get("email");fetch("/api",{body:JSON.stringify({email:email.value})});')
        integrity(o); self.assertTrue(o.javascript['flows']); self.assertTrue(o.interaction['prefills'])
        self.assertEqual(o.interaction['prefills'][0]['final_submitted_value_provenance'],'unresolved')

    def test_code_not_promoted_to_otp(self):
        o=model('', '<form><input id="code" maxlength="6"><input id="zip" autocomplete="postal-code"></form>')
        self.assertNotIn('otp_candidate',o.interaction['stages'][0]['semantic_roles'])


class RetryNavigationTests(unittest.TestCase):
    def check(self,code):
        o=model(code); integrity(o); return o.interaction

    def test_error_ui_mutation_without_retry(self):
        d=self.check('document.getElementById("error").hidden=false;')
        self.assertTrue(d['mutations'][0]['error_ui_candidate']); self.assertEqual(d['retry_paths'],[])

    def test_field_reset(self):
        d=self.check('document.getElementById("password").value="";')
        self.assertEqual(d['mutations'][0]['kind'],'field_reset'); self.assertEqual(d['prefills'],[])

    def test_counter_increment(self):
        self.assertEqual(len(self.check('let attempts=0;attempts++;')['attempt_counters']),1)

    def test_counter_plus_assignment(self):
        self.assertEqual(len(self.check('let attempts=0;attempts+=1;')['attempt_counters']),1)

    def test_unknown_counter_not_invented(self):
        self.assertEqual(self.check('attempts++;')['attempt_counters'],[])

    def test_error_retry_reset(self):
        d=self.check('document.getElementById("login").addEventListener("submit",(event)=>{event.preventDefault();if(flag){document.getElementById("error").hidden=false;document.getElementById("password").value="";}});')
        self.assertEqual(len(d['retry_paths']),1); self.assertEqual(d['retry_paths'][0]['path_state'],'conditional')
        self.assertTrue(d['retry_paths'][0]['field_reset_refs'])

    def test_hidden_error_not_retry(self):
        d=self.check('document.getElementById("login").addEventListener("submit",()=>{document.getElementById("error").hidden=true;});')
        self.assertEqual(d['retry_paths'],[])

    def test_disabled_submit_prevents_retry_candidate(self):
        d=self.check('document.getElementById("login").addEventListener("submit",()=>{document.getElementById("error").hidden=false;document.getElementById("send").disabled=true;});')
        self.assertEqual(d['retry_paths'],[])

    def test_location_href_declared(self):
        n=self.check('location.href="/home";')['navigations'][0]
        self.assertEqual(n['target_state'],'relative_static_url'); self.assertEqual(n['runtime_navigation'],'not_established')

    def test_location_replace_declared(self): self.assertEqual(len(self.check('location.replace("/home");')['navigations']),1)

    def test_window_location_declared(self): self.assertEqual(len(self.check('window.location="/home";')['navigations']),1)

    def test_location_assign_declared(self): self.assertEqual(len(self.check('location.assign("https://e.test/home");')['navigations']),1)

    def test_dynamic_target_unresolved(self):
        self.assertEqual(self.check('location.href=unknown;')['navigations'][0]['target_state'],'unresolved')

    def test_conditional_navigation(self):
        n=self.check('if(response.ok){location.href="/home";}')['navigations'][0]
        self.assertEqual(n['path_state'],'conditional'); self.assertTrue(n['path_condition_refs'])

    def test_after_request_static_order(self):
        n=self.check('fetch("/api");location.href="/home";')['navigations'][0]
        self.assertEqual(n['relation_to_submit'],'static_after_request')

    def test_before_request_not_post_submit(self):
        n=self.check('location.href="/home";fetch("/api");')['navigations'][0]
        self.assertEqual(n['relation_to_submit'],'ordering_unresolved')

    def test_request_other_branch_not_predecessor(self):
        n=self.check('if(flag){fetch("/api");}else{location.href="/home";}')['navigations'][0]
        self.assertEqual(n['relation_to_submit'],'ordering_unresolved')

    def test_timer_declared_deferred(self):
        n=self.check('setTimeout(()=>{location.href="/home";},2000);')['navigations'][0]
        self.assertTrue(n['deferred']); self.assertEqual(n['runtime_execution'],'not_established')

    def test_await_order_not_completion(self):
        n=self.check('async function submit(){await fetch("/api");location.href="/home";}')['navigations'][0]
        self.assertEqual(n['relation_to_submit'],'static_after_request'); self.assertEqual(n['network_completion'],'unresolved')

    def test_promise_callback_relation_unresolved(self):
        n=self.check('fetch("/api").then(()=>location.href="/home");')['navigations'][0]
        self.assertEqual(n['callback_relationship'],'callback_relation_unresolved'); self.assertEqual(n['relation_to_submit'],'ordering_unresolved')

    def test_request_before_conditional_navigation(self):
        n=self.check('fetch("/api");if(response.ok){location.href="/home";}')['navigations'][0]
        self.assertEqual(n['relation_to_submit'],'static_after_request');self.assertEqual(n['path_state'],'conditional')

    def test_await_then_transition_static_order_only(self):
        o=model(ALIASES+'async function send(){await fetch("/api");'+SWITCH+'}',MULTI)
        integrity(o);t=o.interaction['transitions'][0]
        self.assertEqual(t['relation_to_request'],'static_after_request');self.assertEqual(t['network_completion'],'unresolved')
        self.assertTrue(t['request_sink_refs'])

    def test_error_outside_form_has_handler_context(self):
        html=ONE.replace('<div id="error" role="alert" hidden></div>','')+'<div id="error" role="alert" hidden></div>'
        o=model('document.getElementById("login").addEventListener("submit",(event)=>{event.preventDefault();document.getElementById("error").hidden=false;});',html)
        integrity(o);self.assertEqual(o.interaction['mutations'][0]['stage_association'],'handler_context')
        self.assertEqual(len(o.interaction['retry_paths']),1)

    def test_initial_disabled_submit_no_retry(self):
        o=model('document.getElementById("login").addEventListener("submit",()=>{document.getElementById("error").hidden=false;});',ONE.replace('id="send"','id="send" disabled'))
        self.assertEqual(o.interaction['retry_paths'],[])

    def test_form_action_is_markup_target_not_post_submit(self):
        o=model('',ONE.replace('id="login"','id="login" action="/login?password=hunter2"'))
        integrity(o);n=o.interaction['navigations'][0]
        self.assertEqual(n['relation_to_submit'],'markup_submission_target');self.assertNotIn('hunter2',n['target'])

    def test_sensitive_binding_navigation_no_secret(self):
        d=self.check('const password="hunter2";window.location=password;')
        self.assertNotIn('hunter2',json.dumps(d))

    def test_camelcase_error_identifier_candidate(self):
        o=model('document.getElementById("errorMessage").textContent="Try again";',ONE.replace('id="error"','id="errorMessage"'))
        self.assertTrue(o.interaction['mutations'][0]['error_ui_candidate'])

    def test_named_timer_deferred_no_execution(self):
        n=self.check('function later(){location.href="/home";}setTimeout(later,2000);')['navigations'][0]
        self.assertTrue(n['deferred']);self.assertEqual(n['runtime_execution'],'not_established')

    def test_error_text_is_not_interpretation(self):
        o=model('document.getElementById("error").textContent="Incorrect password. Try again.";')
        text=json.dumps(o.interaction)+'\n'+'\n'.join(interaction_lines(o.to_dict()))
        self.assertNotIn('Incorrect password',text)
        for word in FORBIDDEN: self.assertNotIn(word,text)

    def test_loop_resubmission_no_execution_claim(self):
        o=model('function send(){fetch("/api",{body:'+READ+'});}while(flag){send();}')
        integrity(o); self.assertEqual(o.interaction['transitions'],[])
        self.assertTrue(all(s['runtime_execution']=='not_established' for s in o.interaction['stages']))

    def test_two_supported_calls_repeated_submission_candidate(self):
        d=self.check('function send(){fetch("/api",{body:'+READ+'});}send();send();')
        self.assertEqual(len(d['retry_paths']),1)
        self.assertEqual(d['retry_paths'][0]['kind'],'static_repeated_submission')
        self.assertEqual(d['retry_paths'][0]['retry_execution'],'not_established')

    def test_declaration_plus_one_call_not_repetition(self):
        d=self.check('function send(){fetch("/api",{body:'+READ+'});}send();')
        self.assertEqual(d['retry_paths'],[])

    def test_reassigned_counter_not_numeric_fact(self):
        self.assertEqual(self.check('let attempts=0;attempts=unknown;attempts++;')['attempt_counters'],[])


class InteractionIntegrityTests(unittest.TestCase):
    def test_runtime_request_not_stage_execution(self):
        o=model('fetch("/api",{method:"POST",body:'+READ+'});',result=runtime(body_request('{"password":"hunter2"}')))
        integrity(o); s=o.interaction['stages'][0]
        self.assertEqual(s['runtime_support'],'related_request_only'); self.assertEqual(s['runtime_execution'],'not_established')
        self.assertTrue(s['runtime_correlation_refs']); self.assertTrue(s['runtime_payload_refs'])

    def test_missing_dom_js_navigation_still_declared(self):
        o=analyze(runtime(),SCAN,archived_scripts=({'body':'location.href="/home";','document_url':'https://e.test/page/index.html'},))
        integrity(o); self.assertEqual(o.interaction['coverage']['stage_grouping'],'unavailable')
        self.assertEqual(len(o.interaction['navigations']),1)

    def test_missing_js_transition_unavailable(self):
        o=analyze(runtime(),SCAN,ONE.encode())
        self.assertEqual(o.interaction['coverage']['transition_analysis'],'unavailable')
        self.assertEqual(o.interaction['ordering'],'unresolved')

    def test_stage_budget_preserves_lower_layers(self):
        html=''.join('<form id="f'+str(n)+'"><input type="password"></form>' for n in range(40))
        o=model('fetch("/api",{body:document.querySelector("#f1").value});',html)
        self.assertEqual(len(o.interaction['stages']),32); self.assertTrue(o.interaction['coverage']['truncated'])
        self.assertEqual(o.dom_inventory['controls_count'],40)
        self.assertTrue(o.javascript['sinks'])

    def test_observation_budget_lower_js_preserved(self):
        with patch.object(interaction,'MAX_OBSERVATIONS',1):
            o=model(MULTI_CODE,MULTI)
        self.assertTrue(o.interaction['coverage']['truncated']); self.assertTrue(o.javascript['flows'])

    def test_prefill_budget_preserves_flow(self):
        with patch.object(interaction,'MAX_PREFILLS',1):
            o=model(PREFILL+'email.value="a";email.value="b";fetch("/api",{body:email.value});')
        self.assertEqual(len(o.interaction['prefills']),1); self.assertTrue(o.interaction['coverage']['truncated']); self.assertTrue(o.javascript['flows'])

    def test_independent_layer_preserves_lower_facts(self):
        o=model(MULTI_CODE,MULTI,result=runtime(body_request('{"password":"hunter2"}')))
        def baseline(*args,**kwargs):
            kwargs.pop('interaction',None); return PathFlowEngine(*args,**kwargs)
        with patch.object(interaction,'InteractionFlowEngine',side_effect=baseline):
            b=model(MULTI_CODE,MULTI,result=runtime(body_request('{"password":"hunter2"}')))
        self.assertEqual(o.javascript,b.javascript); self.assertEqual(o.runtime_payloads,b.runtime_payloads)
        self.assertEqual(o.network_requests,b.network_requests); self.assertEqual(o.dom_inventory,b.dom_inventory)

    def test_privacy_normal_verbose_json_raw_equal(self):
        secrets=('private@example.test','hunter2','123456','4111111111111111','ghp_'+'a'*36)
        r=runtime(body_request('{"password":"hunter2"}'));r['page']['url']='https://e.test/page/index.html?email=private@example.test&otp=123456#token='+secrets[-1]
        before=deepcopy(r)
        code=PREFILL+'email.value="'+secrets[0]+'";email.value=localStorage.getItem("'+secrets[-1]+'");document.getElementById("error").textContent="hunter2 123456 4111111111111111";location.href="/otp/123456?password=hunter2";'
        dom=(ONE+'<script>'+code+'</script>').encode(); o=analyze(r,SCAN,dom); e=analysis_envelope(r,SCAN,dom,o)
        integrity(o);self.assertEqual(before,r);self.assertEqual(before,e['result'])
        for text in (json.dumps(o.to_dict()),format_analysis(e),format_analysis(e,verbose=True)):
            for secret in secrets:self.assertNotIn(secret,text)

    def test_passive_boundary(self):
        r=runtime(body_request('{}'));dom=(MULTI+'<script>'+MULTI_CODE+'</script>').encode()
        with contextlib.ExitStack() as stack:
            for target in ('urllib.request.urlopen','urllib.request.OpenerDirector.open','socket.socket','socket.getaddrinfo',
                           'subprocess.Popen','subprocess.run','builtins.eval','builtins.exec','builtins.open','pathlib.Path.open'):
                stack.enter_context(patch(target,side_effect=AssertionError('passive boundary')))
            o=analyze(r,SCAN,dom); integrity(o)

    def test_neutral_auth_payment_hard_negative(self):
        for html,code in ((MULTI,MULTI_CODE),(ONE.replace('id="password" type="password"','id="pan" autocomplete="cc-number"'),'')):
            o=model(code,html);self.assertTrue(all(f['flow_execution']=='not_established' and f['value_relationship']=='unresolved' for f in o.findings))
            text=json.dumps(o.interaction)+'\n'+'\n'.join(interaction_lines(o.to_dict()))
            for word in FORBIDDEN:self.assertNotIn(word,text)

    def test_deterministic_ids(self): self.assertEqual(model(MULTI_CODE,MULTI).interaction,model(MULTI_CODE,MULTI).interaction)

    def test_normal_verbose_truncation_and_refs(self):
        html=''.join('<form id="f'+str(n)+'"><input type="email"></form>' for n in range(8))
        o=model('',html); before=deepcopy(o.to_dict())
        normal='\n'.join(interaction_lines(o.to_dict())); verbose='\n'.join(interaction_lines(o.to_dict(),verbose=True))
        self.assertIn('3 more stages',normal);self.assertNotIn('3 more stages',verbose)
        self.assertIn(o.interaction['stages'][-1]['id'],verbose);self.assertEqual(o.to_dict(),before)

    def test_dom_budget_breach_no_structural_ui(self):
        o=model('', '<div>'*257+ONE+'</div>'*257)
        self.assertIsNone(o.dom_inventory);self.assertEqual(o.interaction['stages'],[])

    def test_control_budget_soft_degrade(self):
        o=model('', '<form>'+''.join('<input id="p'+str(n)+'" type="password">' for n in range(40))+'</form>')
        self.assertEqual(len(o.interaction['stages'][0]['control_refs']),32)
        self.assertEqual(o.dom_inventory['controls_count'],40);self.assertTrue(o.interaction['coverage']['truncated'])

    def test_transition_budget_soft_degrade(self):
        with patch.object(interaction,'MAX_TRANSITIONS',1):
            o=model(ALIASES+SWITCH+'b.hidden=true;c.hidden=false;',MULTI)
        self.assertEqual(len(o.interaction['transitions']),1);self.assertTrue(o.interaction['coverage']['truncated']);integrity(o)

    def test_navigation_budget_soft_degrade(self):
        with patch.object(interaction,'MAX_NAVIGATIONS',1): o=model('location.href="/a";location.replace("/b");')
        self.assertEqual(len(o.interaction['navigations']),1);self.assertTrue(o.interaction['coverage']['truncated'])
        self.assertEqual(len(o.javascript['sinks']),2)

    def test_retry_budget_soft_degrade(self):
        with patch.object(interaction,'MAX_RETRY_PATHS',1):
            o=model('document.getElementById("login").onsubmit=(event)=>{event.preventDefault();if(a){document.getElementById("error").hidden=false;}else{document.getElementById("error").hidden=false;}};')
        self.assertEqual(len(o.interaction['retry_paths']),1);self.assertTrue(o.interaction['coverage']['truncated']);integrity(o)

    def test_interaction_dom_element_budget_isolated(self):
        html='<div></div>'*4100+ONE
        o=model('',html)
        self.assertTrue(o.interaction['coverage']['truncated']);self.assertEqual(o.dom_inventory['forms_count'],1)

    def test_failed_js_no_dangling_interaction_facts(self):
        o=model('document.getElementById("error").hidden=false;function broken( {')
        integrity(o);self.assertEqual(o.interaction['mutations'],[])

    def test_neutral_payment_multistage(self):
        html=MULTI.replace('id="email" type="email"','id="contact" autocomplete="email"').replace('id="password" type="password"','id="pan" autocomplete="cc-number"').replace('id="otp" autocomplete="one-time-code"','id="confirmation"')
        o=model(ALIASES+SWITCH+'b.hidden=true;c.hidden=false;',html);integrity(o)
        self.assertTrue(any('payment' in s['semantic_roles'] for s in o.interaction['stages']))
        self.assertTrue(all(f['flow_execution']=='not_established' and f['value_relationship']=='unresolved' for f in o.findings))

    def test_regexp_literal_no_observer_failure(self):
        o=model('if(/x/.test(unknown)){fetch("/api",{body:'+READ+'});}')
        self.assertTrue(o.javascript['scripts'][0]['code_analyzed']);self.assertTrue(o.javascript['flows'])

    def test_handler_budget_keeps_references_valid(self):
        with patch.object(interaction,'MAX_OBSERVATIONS',2):
            o=model('document.getElementById("login").onsubmit=()=>{document.getElementById("error").hidden=false;};',ONE.replace('id="login"','id="login" onsubmit="legacy(event)"').replace('id="send"','id="send" onclick="legacy(event)"'))
        integrity(o);self.assertTrue(o.interaction['coverage']['truncated'])

    def test_observation_does_not_consume_js_operation_budget(self):
        counts=[]
        original=PathFlowEngine.run
        def counted(engine,tree):
            result=original(engine,tree);counts.append(engine.operations);return result
        code=PREFILL+'const URLSearchParams=unknown;email.value=new URLSearchParams(location.search).get("email");fetch("/api",{body:email.value});'
        def baseline(*args,**kwargs):
            kwargs.pop('interaction',None);return PathFlowEngine(*args,**kwargs)
        with patch.object(PathFlowEngine,'run',counted):
            model(code)
            with patch.object(interaction,'InteractionFlowEngine',side_effect=baseline):model(code)
        self.assertEqual(counts[0],counts[1])

    def test_context_mismatch_not_runtime_stage_support(self):
        o=model('fetch("/api",{method:"POST",body:'+READ+'});',result=runtime(body_request('{}',document='https://other.test/')))
        self.assertEqual(o.interaction['stages'][0]['runtime_support'],'unresolved')


if __name__ == '__main__': unittest.main()
