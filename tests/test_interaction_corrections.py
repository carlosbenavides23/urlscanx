"""Slice 5 corrections: lower-layer authority, compatible calls and retained UI."""
import unittest
from unittest.mock import patch

from test_interaction import model, integrity, ONE, READ, runtime, body_request
from urlscanx.analysis import interaction
from urlscanx.analysis.render import interaction_lines

FETCH = 'fetch("/api",{method:"POST",body:'+READ+'});'
HELPER = 'function send(){'+FETCH+'}'
ERROR = 'document.getElementById("error")'
PASSWORD = 'document.getElementById("password")'
FORM = 'document.getElementById("login")'


def retry(code, *, cancel=True, html=ONE):
    return model(FORM+'.addEventListener("submit",(event)=>{'+('event.preventDefault();' if cancel else '')+code+'});', html)


def repeated(code):
    return [r for r in model(HELPER+code).interaction['retry_paths'] if r.get('kind') == 'static_repeated_submission']


class CorrelationAuthorityTests(unittest.TestCase):
    def output(self, code=FETCH, result=None):
        return model(code, result=result or runtime(body_request('{}')))

    def test_accepted_selection(self):
        o=self.output(); integrity(o)
        self.assertEqual(o.interaction['stages'][0]['runtime_support'], 'related_request_only')
        self.assertIn('compatible runtime request evidence', '\n'.join(interaction_lines(o.to_dict())))

    def test_unreachable_observed_endpoint(self):
        o=self.output('if(false){'+FETCH+'}'); integrity(o)
        self.assertEqual(o.javascript['runtime_correlations'][0]['relationship'], 'contradictory_evidence')
        self.assertEqual(o.interaction['stages'][0]['runtime_support'], 'unresolved')
        self.assertNotIn('compatible runtime request', '\n'.join(interaction_lines(o.to_dict())))

    def test_context_mismatch(self):
        o=self.output(result=runtime(body_request('{}', document='https://other.test/')))
        self.assertEqual(o.interaction['stages'][0]['runtime_support'], 'unresolved')

    def altered(self, change):
        finalize=interaction.InteractionInventory.finalize
        def wrapped(inv):
            for c in inv.output.javascript['runtime_correlations']: c.update(change)
            return finalize(inv)
        with patch.object(interaction.InteractionInventory, 'finalize', wrapped): return self.output()

    def test_empty_selection_does_not_use_candidates(self):
        o=self.altered({'selected_request_refs': []})
        self.assertTrue(o.javascript['runtime_correlations'][0]['requests'])
        self.assertEqual(o.interaction['stages'][0]['runtime_support'], 'unresolved')

    def test_contradictory_selected_correlation(self):
        o=self.altered({'relationship': 'contradictory_evidence'})
        self.assertEqual(o.interaction['stages'][0]['runtime_support_reason'], 'lower_layer_correlation_contradictory')

    def test_ambiguous_correlation(self):
        o=self.altered({'state': 'ambiguous_multiple_requests'})
        self.assertEqual(o.interaction['stages'][0]['runtime_support'], 'unresolved')

    def test_unresolved_correlation(self):
        self.assertEqual(self.altered({'state':'unresolved'}).interaction['stages'][0]['runtime_support'],'unresolved')

    def test_final_context_relationship_mismatch(self):
        self.assertEqual(self.altered({'relationship':'context_mismatch'}).interaction['stages'][0]['runtime_support'],'unresolved')

    def test_multiple_selected_refs(self):
        c={'state':'endpoint_method_match','selected_request_refs':['a','b'],'static_path_state':'conditional'}
        self.assertFalse(interaction.correlation_supports_stage_runtime(c))

    def test_truncated_selection(self):
        o=self.altered({'requests_truncated':True})
        self.assertEqual(o.interaction['stages'][0]['runtime_support'], 'unresolved')


class RepeatedPathTests(unittest.TestCase):
    def test_sequential(self): self.assertEqual(len(repeated('send();send();')),1)
    def test_if_else(self): self.assertEqual(repeated('const flag=unknown;if(flag){send();}else{send();}'),[])
    def test_opposite_guards(self): self.assertEqual(repeated('const flag=unknown;if(flag)send();if(!flag)send();'),[])
    def test_same_conditional_path(self): self.assertEqual(len(repeated('const flag=unknown;if(flag){send();send();}')),1)
    def test_unreachable_second_call(self): self.assertEqual(repeated('send();if(false)send();'),[])
    def test_distinct_handlers_not_sequential(self):
        self.assertEqual(repeated(FORM+'.addEventListener("submit",()=>{send();});'+FORM+'.addEventListener("click",()=>{send();});'),[])
    def test_dynamic_unknown_predicates(self): self.assertEqual(repeated('if(check())send();if(other())send();'),[])
    def test_helper_chain(self): self.assertEqual(len(repeated('function outer(){send();}outer();outer();')),1)
    def test_declaration_plus_call(self): self.assertEqual(repeated('send();'),[])
    def test_truncated_paths(self):
        a={'static_path_state':'truncated','path_condition_refs':[]}
        b={'static_path_state':'unconditional','path_condition_refs':[]}
        self.assertEqual(interaction.path_relationship(a,b,{}),'unresolved')
    def test_unknown_renderer(self):
        o=model(HELPER+'if(check())send();if(other())send();')
        self.assertIn('repeated submission relationship: unresolved','\n'.join(interaction_lines(o.to_dict())))
        self.assertNotIn('Repeated submission possibility','\n'.join(interaction_lines(o.to_dict())))


class RetryPersistenceTests(unittest.TestCase):
    def check(self, code, positive=False, **kwargs):
        o=retry(code,**kwargs); integrity(o)
        self.assertEqual(bool(o.interaction['retry_paths']),positive)
        return o
    def test_cancel_show_reset(self): self.check(ERROR+'.hidden=false;'+PASSWORD+'.value="";',True)
    def test_no_cancel(self): self.check(ERROR+'.hidden=false;',cancel=False)
    def test_no_action_is_still_native_submit(self): self.check(ERROR+'.hidden=false;',cancel=False,html=ONE)
    def test_action_without_cancel(self): self.check(ERROR+'.hidden=false;',cancel=False,html=ONE.replace('id="login"','id="login" action="/login"'))
    def test_click_handler_persistence_unresolved(self):
        o=model(FORM+'.addEventListener("click",()=>{'+ERROR+'.hidden=false;});')
        self.assertEqual(o.interaction['retry_paths'],[])

    def test_empty_text(self):
        o=self.check(ERROR+'.textContent="";')
        self.assertEqual(o.interaction['mutations'][0]['error_content_state'],'error_cleared')
    def test_empty_inner_text(self): self.check(ERROR+'.innerText="";')
    def test_empty_inner_html(self): self.check(ERROR+'.innerHTML="";')
    def test_dynamic_text(self):
        o=self.check(ERROR+'.textContent=dynamicMessage;')
        self.assertEqual(o.interaction['mutations'][0]['error_content_state'],'error_content_mutated_unresolved')
    def test_nonempty_static_text(self): self.check(ERROR+'.textContent="Incorrect password";',True)
    def test_navigation(self): self.check(ERROR+'.hidden=false;location.href="/next";')
    def test_stage_hide(self): self.check(ERROR+'.hidden=false;'+FORM+'.hidden=true;')
    def test_container_replacement(self): self.check(ERROR+'.hidden=false;'+FORM+'.innerHTML="";')
    def test_disabled_submit(self): self.check(ERROR+'.hidden=false;document.getElementById("send").disabled=true;')
    def test_reset_alone(self): self.check(PASSWORD+'.value="";')
    def test_conditional_cancel_not_sufficient(self): self.check('if(flag)event.preventDefault();'+ERROR+'.hidden=false;',cancel=False)
    def test_shadowed_event(self): self.check('{const event=other;event.preventDefault();}'+ERROR+'.hidden=false;',cancel=False)
    def test_named_callback(self):
        o=model('function handler(e){e.preventDefault();'+ERROR+'.hidden=false;}'+FORM+'.addEventListener("submit",handler);')
        integrity(o); self.assertEqual(len(o.interaction['retry_paths']),1)
    def test_non_event_prevent_default(self): self.check('other.preventDefault();'+ERROR+'.hidden=false;',cancel=False)
    def test_dynamic_error_privacy(self):
        o=self.check(ERROR+'.textContent=`Invalid OTP ${'+PASSWORD+'.value}`;')
        rendered='\n'.join(interaction_lines(o.to_dict(),verbose=True))
        self.assertNotIn('Invalid OTP', rendered)
    def test_unreachable_error(self): self.check('if(false){'+ERROR+'.hidden=false;}')
    def test_async_cancellation_not_promoted(self):
        o=model(FORM+'.addEventListener("submit",async (event)=>{await pending;event.preventDefault();'+ERROR+'.hidden=false;});')
        self.assertEqual(o.interaction['retry_paths'],[])

    def test_hidden_stage_not_retained(self):
        self.check(ERROR+'.hidden=false;',html=ONE.replace('id="login"','id="login" hidden'))

    def test_no_cancel_renderer(self):
        o=self.check(ERROR+'.hidden=false;',cancel=False)
        text='\n'.join(interaction_lines(o.to_dict()))
        self.assertIn('retry relationship: unresolved',text)
        self.assertNotIn('retry path: declared',text)
