"""Bounded viability and compatible requests remain independent claims."""
import contextlib
from copy import deepcopy
import hashlib
import json
import unittest
from unittest.mock import patch

from urlscanx.analysis import analyze, analysis_envelope
from urlscanx.analysis import paths
from urlscanx.analysis import correlation as joins
from urlscanx.analysis.render import javascript_lines
import test_interprocedural as previous
from test_javascript import inspect, sensitive, READ, HTML, SCAN
from test_analysis import request

FLOW = f'fetch("/api",{{method:"POST",body:{READ}}});'
HELPER = 'function send(x){fetch("/api",{method:"POST",body:x});}'


def runtime(*entries):
    return {'task':{},'page':{'url':'https://e.test/page/index.html'},'data':{'requests':list(entries)}}


def observed(url='https://e.test/api', method='POST', initiator=None, document='https://e.test/page/index.html'):
    entry = request(url, method)
    entry['request']['documentURL'] = document
    if initiator is not None:
        entry['request']['initiator'] = initiator
    return entry


def script_load(url='https://e.test/a.js', body=None, frame='frame-1', document='https://e.test/page/index.html'):
    entry = observed(url,'GET',document=document)
    entry['request'].update(type='Script',frameId=frame)
    if body is not None:
        entry['response']['body'] = body
    return entry


class PathTests(unittest.TestCase):
    def facts(self, code, expected, result=None):
        output = inspect(code, result=result)
        self.assertTrue(sensitive(output), output.javascript['scripts'])
        self.assertEqual({f['static_path_state'] for f in sensitive(output)}, set(expected))
        self.integrity(output)
        return output

    def integrity(self, output):
        previous.InterproceduralTests().integrity(output)
        js = output.javascript
        evidence = {e.id for e in output.evidence}
        predicates = {p['id'] for p in js['path_conditions']}
        for category in ('path_conditions','runtime_correlations'):
            ids = [r['id'] for r in js[category]]
            self.assertEqual(len(ids),len(set(ids)))
            for record in js[category]:
                self.assertTrue(set(record['evidence_refs']) <= evidence)
        for predicate in js['path_conditions']:
            self.assertTrue(predicate['binding_ref'] is None or predicate['binding_ref'] in evidence)
        for category in ('sources','transforms','sinks','flows','calls','call_edges'):
            for record in js[category]:
                self.assertTrue(set(record.get('path_condition_refs',[])) <= predicates)
                self.assertLessEqual(len(record.get('path_condition_refs',[])),paths.MAX_PREDICATES)
        sinks = {s['id'] for s in js['sinks']}
        self.assertTrue(all(c['sink_id'] in sinks for c in js['runtime_correlations']))

    def test_unconditional_direct(self):
        output = self.facts(FLOW, ['unconditional'])
        self.assertEqual(output.javascript['path_conditions'],[])

    def test_literal_true(self):
        self.facts('if(true){'+FLOW+'}', ['unconditional'])

    def test_literal_false(self):
        output = self.facts('if(false){'+FLOW+'}', ['statically_unreachable'])
        self.assertEqual(output.javascript['path_conditions'][0]['resolution'],'false')

    def test_unknown_if(self):
        self.facts('if(ready){'+FLOW+'}', ['conditional'])

    def test_if_else_opposite_predicates(self):
        output = self.facts('if(ready){'+FLOW+'}else{'+FLOW+'}', ['conditional'])
        predicates = output.javascript['path_conditions']
        self.assertEqual({p['polarity'] for p in predicates},{True,False})
        self.assertEqual(len(sensitive(output)),2)

    def test_nested_conditions(self):
        output = self.facts('if(ready){if(enabled){'+FLOW+'}}', ['conditional'])
        self.assertEqual(len(sensitive(output)[0]['path_condition_refs']),2)

    def test_ternary(self):
        self.facts(f'ready ? fetch("/a",{{body:{READ}}}) : fetch("/b",{{body:{READ}}});',['conditional'])

    def test_logical_and(self):
        output = self.facts(HELPER+f'ready && send({READ});',['conditional'])
        self.assertTrue(output.javascript['path_conditions'][0]['polarity'])

    def test_logical_or(self):
        output = self.facts(HELPER+f'ready || send({READ});',['conditional'])
        self.assertFalse(output.javascript['path_conditions'][0]['polarity'])

    def test_boolean_folding(self):
        for condition, state in [('!true','statically_unreachable'),('!false','unconditional'),
                                  ('true && ready','conditional'),('false && ready','statically_unreachable'),
                                  ('true || ready','unconditional'),('false || ready','conditional')]:
            with self.subTest(condition=condition):
                self.facts('if('+condition+'){'+FLOW+'}',[state])

    def test_short_circuit_dead_rhs(self):
        for prefix in ('false &&','true ||'):
            self.facts(HELPER+prefix+f'send({READ});',['statically_unreachable'])

    def test_immutable_boolean(self):
        self.facts('const FLAG=true;if(FLAG){'+FLOW+'}', ['unconditional'])

    def test_mutable_boolean_is_not_folded(self):
        self.facts('let FLAG=true;if(FLAG){'+FLOW+'}', ['conditional'])

    def test_let_alias_does_not_inherit_immutability(self):
        self.facts('const FLAG=true;let X=FLAG;if(X){'+FLOW+'}', ['conditional'])

    def test_const_boolean_alias(self):
        self.facts('const FLAG=true;const X=FLAG;if(X){'+FLOW+'}', ['unconditional'])

    def test_pure_boolean_const_initializer(self):
        self.facts('const FLAG=!false;if(FLAG){'+FLOW+'}', ['unconditional'])

    def test_function_result_is_not_constant_folded(self):
        self.facts('function yes(){return true;}const FLAG=yes();if(FLAG){'+FLOW+'}', ['conditional'])

    def test_function_result_in_boolean_initializer_not_folded(self):
        self.facts('const FLAG=unknown()||true;if(FLAG){'+FLOW+'}', ['conditional'])

    def test_computed_property_not_folded(self):
        self.facts('const config={flag:true};const FLAG=config.flag;if(FLAG){'+FLOW+'}', ['conditional'])

    def test_mutated_const_is_not_folded(self):
        self.facts('const FLAG=true;FLAG=false;if(FLAG){'+FLOW+'}', ['conditional'])

    def test_shadowed_boolean_binding(self):
        self.facts('const FLAG=true;{const FLAG=dynamic();if(FLAG){'+FLOW+'}}',['conditional'])

    def test_dynamic_boolean_const(self):
        self.facts('const FLAG=dynamic();if(FLAG){'+FLOW+'}', ['conditional'])

    def test_random_cookie_country_unknown_conditions(self):
        for condition in ('Math.random()','document.cookie','country === "US"','unknown()'):
            self.facts('if('+condition+'){'+FLOW+'}', ['conditional'])

    def test_guard_return(self):
        output = self.facts('function submit(){if(!email || !password){return;}'+FLOW+'}', ['conditional'])
        refs = sensitive(output)[0]['path_condition_refs']
        self.assertTrue(refs)
        predicate = next(p for p in output.javascript['path_conditions'] if p['id']==refs[-1])
        self.assertFalse(predicate['polarity'])

    def test_true_guard_makes_continuation_dead(self):
        self.facts('function f(){if(true){return;}'+FLOW+'}', ['statically_unreachable'])

    def test_false_guard_leaves_continuation_unconditional(self):
        self.facts('function f(){if(false){return;}'+FLOW+'}', ['unconditional'])

    def test_return_terminates(self):
        self.facts('function f(){return;'+FLOW+'}', ['statically_unreachable'])

    def test_throw_terminates(self):
        self.facts('function f(){throw "hidden";'+FLOW+'}', ['statically_unreachable'])

    def test_nested_block_return(self):
        self.facts('function f(){{return;}'+FLOW+'}', ['statically_unreachable'])

    def test_complex_nested_guard_is_unresolved(self):
        self.facts('function f(){if(ready){if(enabled){return;}}'+FLOW+'}', ['unresolved'])

    def test_guard_across_nested_block_is_unresolved(self):
        self.facts('function f(){{if(ready){return;}}'+FLOW+'}', ['unresolved'])

    def test_both_branches_return(self):
        self.facts('function f(){if(ready){return;}else{return;}'+FLOW+'}', ['statically_unreachable'])

    def test_dead_return_cannot_replace_live_return(self):
        output = inspect(f'function get(){{return "safe";return {READ};}}fetch("/api",{{body:get()}});')
        self.assertEqual(sensitive(output),[])

    def test_dead_branch_cannot_destroy_live_binding(self):
        self.facts(f'let p={READ};if(false){{p=unknown();}}fetch("/api",{{body:p}});',['unconditional'])

    def test_loop(self):
        output = self.facts('while(ready){'+FLOW+'}', ['conditional'])
        self.assertTrue(sensitive(output)[0]['loop_context'])
        self.assertEqual(output.javascript['sinks'][0]['iteration_count'],'unresolved')

    def test_loop_literal_not_solved(self):
        self.facts('while(false){'+FLOW+'}', ['conditional'])

    def test_loop_continuation_unresolved(self):
        self.facts('function f(){while(ready){return;}'+FLOW+'}', ['unresolved'])

    def test_break_continue(self):
        for stop in ('break','continue'):
            self.facts('while(ready){'+stop+';'+FLOW+'}', ['unresolved'])

    def test_try_catch_finally(self):
        self.facts('try{'+FLOW+'}catch(e){'+FLOW+'}finally{'+FLOW+'}', ['unresolved'])

    def test_after_try_is_unresolved(self):
        self.facts('function f(){try{return;}catch(e){}'+FLOW+'}', ['unresolved'])

    def test_switch_unresolved(self):
        self.facts('switch(x){case 1: break;}'+FLOW, ['unresolved'])

    def test_handler_context(self):
        output = self.facts('form.addEventListener("submit",()=>{if(ready){'+FLOW+'}});',['conditional'])
        self.assertEqual(output.javascript['sinks'][0]['execution_context'],'handler_declared')

    def test_caller_predicate_inherited(self):
        output = self.facts(HELPER+f'if(ready){{send({READ});}}',['conditional'])
        edge = next(e for e in output.javascript['call_edges'] if e['propagation']=='supported')
        self.assertEqual(edge['inherited_path_condition_refs'],sensitive(output)[0]['path_condition_refs'])

    def test_caller_callee_composition(self):
        output = self.facts('function send(x){if(enabled){fetch("/api",{body:x});}}'+f'if(ready){{send({READ});}}',['conditional'])
        self.assertEqual(len(sensitive(output)[0]['path_condition_refs']),2)

    def test_exact_immutable_contradiction(self):
        self.facts('const FLAG=dynamic();if(FLAG){if(!FLAG){'+FLOW+'}}',['statically_unreachable'])

    def test_mutable_not_a_contradiction(self):
        self.facts('let FLAG=dynamic();if(FLAG){if(!FLAG){'+FLOW+'}}',['conditional'])

    def test_shadow_not_a_contradiction(self):
        self.facts('const FLAG=dynamic();if(FLAG){const FLAG=other();if(!FLAG){'+FLOW+'}}',['conditional'])

    def test_caller_callee_exact_binding_contradiction(self):
        self.facts('const FLAG=dynamic();function send(x){if(!FLAG){fetch("/api",{body:x});}}'+f'if(FLAG){{send({READ});}}',['statically_unreachable'])

    def test_parameter_boolean_not_immutable(self):
        self.facts('function send(flag,x){if(flag){fetch("/api",{body:x});}}'+f'const FLAG=true;send(FLAG,{READ});',['conditional'])

    def test_nested_budget_soft(self):
        code = 'if(ready){' * 11 + FLOW + '}' * 11 + FLOW
        output = self.facts(code,['truncated','unconditional'])
        self.assertTrue(output.javascript['path_analysis']['truncated'])
        self.assertTrue(all(s['parser_status']=='parsed' and s['code_analyzed'] for s in output.javascript['scripts']))

    def test_sibling_budget_soft(self):
        output = self.facts(('if(ready){'+FLOW+'}')*19 + FLOW,['conditional','truncated','unconditional'])
        self.assertEqual(len(output.javascript['path_conditions']),paths.MAX_VARIANTS_SCOPE)

    def test_total_variant_budget_soft(self):
        with patch.object(paths,'MAX_VARIANTS_TOTAL',2):
            output = self.facts(('if(ready){'+FLOW+'}')*4 + FLOW,['conditional','truncated','unconditional'])
        self.assertEqual(len(output.javascript['path_conditions']),2)

    def test_hard_script_rollback_withdraws_path_facts(self):
        from urlscanx.analysis import jsflow
        with patch.object(jsflow,'MAX_RECORDS',1):
            output = inspect('if(ready){'+FLOW+'}')
        self.assertEqual(output.javascript['path_conditions'],[])
        self.assertEqual(output.javascript['runtime_correlations'],[])
        self.assertEqual(output.javascript['path_analysis']['branches_inspected'],0)
        self.integrity(output)

    def test_soft_invocation_rollback_leaves_valid_path_refs(self):
        output = inspect('function send(x){if(ready){fetch("/api",{body:x});}return send(x);}'+f'send({READ});'+FLOW)
        self.integrity(output)
        self.assertTrue(any(f['static_path_state']=='unconditional' for f in sensitive(output)))

    def test_per_flow_predicate_budget(self):
        code = ('function get(){'+'if(false){return;}'*4+'return '+READ+';}const p=get();'+
                'if(ready){'*5+'fetch("/api",{body:p});'+'}'*5)
        output = self.facts(code,['truncated'])
        self.assertIn('predicates per flow budget',output.javascript['path_analysis']['reasons'])

    def test_condition_privacy(self):
        secrets = ['123456','hunter2','4111111111111111','ghp_'+'A'*36,'sk-'+'B'*40]
        for secret in secrets:
            output = self.facts('if(otp === "'+secret+'"){'+FLOW+'}', ['conditional'])
            serialized = json.dumps(output.to_dict())
            for verbose in (False,True):
                serialized += '\n'.join(javascript_lines(output.javascript,verbose=verbose))
            self.assertNotIn(secret,serialized)
            self.assertNotIn(hashlib.sha256(secret.encode()).hexdigest(),serialized)

    def test_renderer_separates_unreachable(self):
        output = self.facts('if(false){'+FLOW+'}'+FLOW,['unconditional','statically_unreachable'])
        text = '\n'.join(javascript_lines(output.javascript))
        self.assertLess(text.index('Supported static flows:'),text.index('Statically unreachable flows'))
        self.assertIn('static path: statically unreachable',text)
        self.assertIn('runtime execution: not established',text)

    def test_verbose_preserves_all_bounded_conditions(self):
        output = self.facts('if(ready){'*5+FLOW+'}'*5,['conditional'])
        normal = '\n'.join(javascript_lines(output.javascript))
        verbose = '\n'.join(javascript_lines(output.javascript,verbose=True))
        self.assertEqual(normal.count('condition:'),3)
        self.assertEqual(verbose.count('condition:'),5)
        self.assertIn('2 more conditions',normal)
        self.assertNotIn('more conditions',verbose)

    def test_result_only_predicate_evidence_independent_of_dom(self):
        entry = observed('https://e.test/a.js','GET')
        entry['request']['type'] = 'Script'
        entry['response']['body'] = 'const FLAG=true;if(FLAG){fetch("https://e.test/api",{method:"POST"});}'
        result = runtime(entry,observed())
        with_dom = analyze(result,SCAN,HTML.encode())
        without_dom = analyze(result,SCAN)
        self.assertEqual(with_dom.javascript['path_conditions'],without_dom.javascript['path_conditions'])
        self.assertEqual(with_dom.javascript['runtime_correlations'],without_dom.javascript['runtime_correlations'])

    def test_no_semantic_verdicts(self):
        text = '\n'.join(javascript_lines(inspect('function f(){if(isBot){return;}if(country==="US"){'+FLOW+'}}').javascript,verbose=True))
        for claim in ('anti-analysis','cloaking','geofencing','phishing confirmed','same actor','flow executed','branch executed'):
            self.assertNotIn(claim,text)

    def test_raw_equality_and_passive_boundary(self):
        result = runtime(observed('https://e.test/api?otp=123456'))
        before = deepcopy(result)
        dom = (HTML+'<script>if(otp === "123456"){'+FLOW+'}</script>').encode()
        with contextlib.ExitStack() as guards:
            for target in ('urllib.request.urlopen','socket.socket','socket.getaddrinfo','subprocess.Popen',
                           'subprocess.run','builtins.eval','builtins.exec','builtins.open','pathlib.Path.open'):
                guards.enter_context(patch(target,side_effect=AssertionError('passive boundary')))
            output = analyze(result,SCAN,dom)
            envelope = analysis_envelope(result,SCAN,dom,output)
        self.assertEqual(result,before)
        self.assertEqual(envelope['result'],before)


class CorrelationTests(unittest.TestCase):
    def correlation(self, code=FLOW, entries=()):
        output = inspect(code,result=runtime(*entries))
        PathTests().integrity(output)
        sink = next(s for s in output.javascript['sinks'] if s['sink_kind']=='fetch')
        return output,next(c for c in output.javascript['runtime_correlations'] if c['sink_id']==sink['id'])

    def test_exact_endpoint_method(self):
        output, correlation = self.correlation('if(ready){'+FLOW+'}',[observed()])
        self.assertEqual(correlation['state'],'endpoint_method_match')
        self.assertEqual(sensitive(output)[0]['static_path_state'],'conditional')
        self.assertEqual(correlation['requests'][0]['initiator_relationship'],'unresolved')
        self.assertEqual(correlation['condition_satisfaction'],'not_established')
        self.assertEqual(correlation['payload_relationship'],'unresolved')

    def test_none(self):
        _, c = self.correlation(entries=[observed('https://other.test/api')])
        self.assertEqual(c['state'],'none')

    def test_wrong_method(self):
        _, c = self.correlation(entries=[observed(method='GET')])
        self.assertEqual(c['state'],'none')

    def test_unknown_method(self):
        _, c = self.correlation(f'fetch("/api",{{method:verb,body:{READ}}});',[observed()])
        self.assertEqual(c['state'],'unresolved')

    def test_multiple_requests(self):
        _, c = self.correlation(entries=[observed(),observed(),observed()])
        self.assertEqual(c['state'],'ambiguous_multiple_requests')
        self.assertEqual(c['compatible_request_count'],3)
        self.assertEqual(len(c['selected_request_refs']),3)

    def test_query_mismatch_is_not_exact(self):
        _, c = self.correlation(FLOW.replace('"/api"','"/api?otp=111111"'),[observed('https://e.test/api?otp=222222')])
        self.assertEqual(c['state'],'unresolved')
        self.assertEqual(c['requests'][0]['query_relationship'],'unresolved')
        self.assertEqual(c['requests'][0]['target_relationship'],'origin_path_only')
        self.assertNotIn('111111',json.dumps(c))
        self.assertNotIn('222222',json.dumps(c))

    def test_exact_query_transiently(self):
        _, c = self.correlation(FLOW.replace('"/api"','"/api?code=123456"'),[observed('https://e.test/api?code=123456')])
        self.assertEqual(c['state'],'endpoint_method_match')
        self.assertNotIn('123456',json.dumps(c))

    def test_dynamic_query_unresolved(self):
        _, c = self.correlation(FLOW.replace('"/api"','"/api?id="+x'),[observed('https://e.test/api?id=123')])
        self.assertEqual(c['state'],'unresolved')

    def test_unreachable_runtime_contradiction(self):
        output,c = self.correlation('if(false){'+FLOW+'}',[observed()])
        self.assertEqual(c['relationship'],'contradictory_evidence')
        self.assertEqual(c['static_path_state'],'statically_unreachable')
        self.assertEqual(c['flow_execution'],'not_established')
        self.assertIn('contradictory evidence','\n'.join(javascript_lines(output.javascript)))

    def test_external_exact_initiator(self):
        event = observed(initiator={'type':'script','stack':{'callFrames':[{'url':'https://e.test/a.js','lineNumber':0,'columnNumber':0}]}})
        result = runtime(event,script_load())
        output = analyze(result,SCAN,HTML.encode(),archived_scripts=[{'url':'https://e.test/a.js','document_url':result['page']['url'],'body':FLOW}])
        c = output.javascript['runtime_correlations'][0]
        self.assertEqual(c['state'],'endpoint_method_initiator_match')
        PathTests().integrity(output)

    def test_initiator_false_script_match(self):
        event = observed(initiator={'type':'script','stack':{'callFrames':[{'url':'https://e.test/b.js','lineNumber':0,'columnNumber':0}]}})
        result = runtime(event,script_load(),script_load('https://e.test/b.js'))
        output = analyze(result,SCAN,HTML.encode(),archived_scripts=[{'url':'https://e.test/'+s+'.js','document_url':result['page']['url'],'body':FLOW} for s in ('a','b')])
        a,b = output.javascript['runtime_correlations']
        self.assertEqual(a['state'],'endpoint_method_match')
        self.assertEqual(a['requests'][0]['initiator_relationship'],'script_mismatch')
        self.assertEqual(b['state'],'endpoint_method_initiator_match')

    def test_duplicate_script_identity_unresolved(self):
        result = runtime(observed(initiator={'url':'https://e.test/a.js'}))
        output = analyze(result,SCAN,HTML.encode(),archived_scripts=[{'url':'https://e.test/a.js','document_url':result['page']['url'],'body':FLOW}]*2)
        self.assertTrue(all(c['state']=='endpoint_method_match' for c in output.javascript['runtime_correlations']))

    def test_inline_exact_callsite(self):
        code = FLOW
        output = inspect(code)
        location = output.javascript['sinks'][0]['location']
        event = observed(initiator={'type':'script','stack':{'callFrames':[{'url':'https://e.test/page/index.html',
            'lineNumber':location['dom_line']-1,'columnNumber':location['dom_column']}]}})
        _, c = self.correlation(code,[event])
        self.assertEqual(c['state'],'endpoint_method_initiator_match')

    def test_inline_url_without_callsite_insufficient(self):
        _, c = self.correlation(entries=[observed(initiator={'url':'https://e.test/page/index.html'})])
        self.assertEqual(c['state'],'endpoint_method_match')
        self.assertEqual(c['requests'][0]['initiator_relationship'],'unresolved')

    def test_document_mismatch(self):
        _, c = self.correlation(entries=[observed(initiator={'url':'https://e.test/a.js'},document='https://other.test/')])
        self.assertEqual(c['requests'][0]['initiator_relationship'],'context_mismatch')

    def test_unique_initiator_disambiguates_multiple(self):
        good = observed(initiator={'type':'script','url':'https://e.test/a.js'})
        bad = observed(initiator={'type':'script','url':'https://e.test/b.js'})
        result = runtime(good,bad,script_load())
        output = analyze(result,SCAN,HTML.encode(),archived_scripts=[{'url':'https://e.test/a.js','document_url':result['page']['url'],'body':FLOW}])
        c = output.javascript['runtime_correlations'][0]
        self.assertEqual(c['state'],'endpoint_method_initiator_match')
        self.assertEqual(c['compatible_request_count'],2)
        self.assertEqual(c['selected_request_refs'],['/data/requests/0'])

    def test_order_timing_not_causality(self):
        _, c = self.correlation(entries=[observed()])
        self.assertEqual(c['requests'][0]['context_role'],'supporting_metadata_only')
        self.assertEqual(c['requests'][0]['request_order'],0)
        self.assertEqual(c['flow_execution'],'not_established')

    def test_ancestor_script_is_not_the_initiating_script(self):
        event = observed(initiator={'type':'script','stack':{'callFrames':[{'url':'https://e.test/b.js'}, {'url':'https://e.test/a.js'}]}})
        result = runtime(event,script_load(),script_load('https://e.test/b.js'))
        output = analyze(result,SCAN,HTML.encode(),archived_scripts=[{'url':'https://e.test/'+s+'.js','document_url':result['page']['url'],'body':FLOW} for s in ('a','b')])
        a,b = output.javascript['runtime_correlations']
        self.assertEqual(a['requests'][0]['initiator_relationship'],'script_mismatch')
        self.assertEqual(b['state'],'endpoint_method_initiator_match')

    def test_inline_two_scripts_false_match(self):
        dom = (HTML+'<script>'+FLOW+'</script><script>'+FLOW+'</script>').encode()
        output = analyze(runtime(),SCAN,dom)
        location = output.javascript['sinks'][1]['location']
        event = observed(initiator={'type':'script','stack':{'callFrames':[{'url':'https://e.test/page/index.html',
            'lineNumber':location['dom_line']-1,'columnNumber':location['dom_column']}]}})
        output = analyze(runtime(event),SCAN,dom)
        a,b = output.javascript['runtime_correlations']
        self.assertEqual(a['state'],'endpoint_method_match')
        self.assertEqual(b['state'],'endpoint_method_initiator_match')

    def test_frame_mismatch(self):
        code_event = observed('https://e.test/a.js','GET')
        code_event['request']['type'] = 'Script'
        code_event['response']['body'] = FLOW
        code_event['request']['frameId'] = 'source-frame'
        post = observed(initiator={'type':'script','url':'https://e.test/a.js'})
        output = analyze(runtime(code_event,post),SCAN,HTML.encode())
        self.assertEqual(output.javascript['runtime_correlations'][0]['requests'][0]['initiator_relationship'],'context_mismatch')

    def test_parser_initiator_cannot_prove_script(self):
        _, c = self.correlation(entries=[observed(initiator={'type':'parser','url':'https://e.test/page/index.html'})])
        self.assertEqual(c['requests'][0]['initiator_relationship'],'unresolved')

    def test_context_budget_does_not_pick_from_partial_candidates(self):
        with patch.object(joins,'MAX_REQUEST_CONTEXTS_PER_SINK',2):
            output,c = self.correlation(entries=[observed(),observed(),observed()])
        self.assertEqual(c['state'],'unresolved')
        self.assertEqual(c['compatible_request_count'],3)
        self.assertTrue(c['requests_truncated'])
        self.assertEqual(c['selected_request_refs'],[])
        self.assertEqual(len(output.javascript['runtime_joins']),3)

    def test_total_context_budget_preserves_counts(self):
        with patch.object(joins,'MAX_REQUEST_CONTEXTS_TOTAL',1):
            output = inspect(FLOW*2,result=runtime(observed()))
        a,b = output.javascript['runtime_correlations']
        self.assertEqual(a['state'],'endpoint_method_match')
        self.assertEqual(b['state'],'unresolved')
        self.assertEqual(b['compatible_request_count'],1)
        PathTests().integrity(output)

    def test_malformed_initiator_and_deep_parent(self):
        parent = {'callFrames':[]}
        for _ in range(100):
            parent = {'callFrames':[], 'parent':parent}
        for initiator in ({'url':{}}, {'stack':{'callFrames':'bad'}}, {'stack':parent}):
            _, c = self.correlation(entries=[observed(initiator=initiator)])
            self.assertEqual(c['state'],'endpoint_method_match')
            self.assertEqual(c['requests'][0]['initiator_relationship'],'unresolved')

    def test_malformed_initiator_type_does_not_withdraw_script(self):
        for kind in ({},[]):
            output,c = self.correlation(entries=[observed(initiator={'type':kind,'url':'https://e.test/page/index.html'})])
            self.assertTrue(sensitive(output))
            self.assertEqual(output.javascript['scripts'][0]['parser_status'],'parsed')
            self.assertEqual(c['requests'][0]['initiator_relationship'],'unresolved')

    def test_invalid_script_urls_cannot_compare_as_equal(self):
        event = observed(initiator={'type':'script','url':'blob:invalid'})
        result = runtime(event)
        output = analyze(result,SCAN,HTML.encode(),archived_scripts=[{'url':'blob:invalid','document_url':result['page']['url'],'body':FLOW}])
        c = output.javascript['runtime_correlations'][0]
        self.assertEqual(c['state'],'endpoint_method_match')
        self.assertEqual(c['requests'][0]['initiator_relationship'],'unresolved')
