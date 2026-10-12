"""Bounded caller/parameter/return propagation and refusal boundaries."""
from copy import deepcopy
import contextlib
import json
import unittest
from unittest.mock import patch

from urlscanx.analysis import analyze, analysis_envelope
from urlscanx.analysis import interprocedural as engine
from urlscanx.analysis.render import javascript_lines, format_analysis
from test_javascript import inspect, sensitive, READ, HTML, SCAN
from test_analysis import request

SEND = 'function send(data){fetch("/api/collect",{method:"POST",body:JSON.stringify(data)});}'


class InterproceduralTests(unittest.TestCase):
    def positive(self, code):
        output = inspect(code)
        self.assertTrue(sensitive(output), output.javascript['scripts'])
        self.assertTrue(all(f['state'] == 'static_flow_inferred' for f in sensitive(output)))
        self.integrity(output)
        return output

    def integrity(self, output):
        js = output.javascript
        evidence = {e.id for e in output.evidence}
        self.assertEqual(len(evidence), len(output.evidence))
        for category in ('functions', 'call_edges', 'sources', 'transforms', 'sinks', 'flows', 'runtime_joins', 'calls'):
            ids = [r['id'] for r in js[category]]
            self.assertEqual(len(ids), len(set(ids)), category)
            for record in js[category]:
                self.assertTrue(set(record['evidence_refs']) <= evidence, category)
        sources = {s['id'] for s in js['sources']}
        transforms = {t['id'] for t in js['transforms']}
        sinks = {s['id'] for s in js['sinks']}
        functions = {f['id'] for f in js['functions']}
        edges = {e['id'] for e in js['call_edges']}
        for e in js['call_edges']:
            self.assertTrue(e['callee_function_id'] is None or e['callee_function_id'] in functions)
            self.assertEqual(e['runtime_execution'], 'not_established')
            for mapping in e['argument_mappings']:
                self.assertTrue(set(mapping['source_refs']) <= sources)
        for t in js['transforms']:
            self.assertTrue(set(t['input_source_refs']) <= sources)
            self.assertTrue(set(t['input_transform_refs']) <= transforms)
            if t.get('call_edge_ref'):
                self.assertIn(t['call_edge_ref'], edges)
        for f in js['flows']:
            self.assertIn(f['source_id'], sources)
            self.assertIn(f['sink_id'], sinks)
            self.assertTrue(set(f['transform_ids']) <= transforms)
            self.assertTrue(set(f.get('call_edge_refs', [])) <= edges)

    def test_direct_argument_parameter(self):
        o = self.positive(SEND + f'const p={READ};send({{password:p}});')
        flow = sensitive(o)[0]
        kinds = {t['kind'] for t in o.javascript['transforms'] if t['id'] in flow['transform_ids']}
        self.assertTrue({'call_argument', 'function_parameter', 'JSON.stringify'} <= kinds)
        sequence = [next(t['kind'] for t in o.javascript['transforms'] if t['id'] == i) for i in flow['transform_ids']]
        self.assertLess(sequence.index('object_construction'), sequence.index('call_argument'))
        self.assertLess(sequence.index('call_argument'), sequence.index('function_parameter'))
        sink = next(s for s in o.javascript['sinks'] if s['id'] == flow['sink_id'])
        self.assertEqual(sink['execution_context'], 'statically_reachable_from_call')
        self.assertEqual(sink['runtime_endpoint'], 'not_observed')

    def test_function_expression_and_arrow(self):
        for helper in ['const send=function(x){fetch("/api",{body:x});};',
                       'const send=(x)=>fetch("/api",{body:x});']:
            with self.subTest(helper=helper):
                self.positive(helper + f'send({READ});')

    def test_forward_hoisted_call(self):
        self.positive(f'send({READ});function send(x){{fetch("/api",{{body:x}});}}')

    def test_two_hop_build_and_send(self):
        o = self.positive('function build(p){return {secret:p};}' + SEND + f'send(build({READ}));')
        self.assertTrue(any(t['kind'] == 'function_return' for t in o.javascript['transforms']))
        sink = next(s for s in o.javascript['sinks'] if s['id'] == sensitive(o)[0]['sink_id'])
        self.assertIn('secret', [f['name'] for f in sink['payload']['fields']])

    def test_return_source_to_caller(self):
        o = self.positive(f'function read(){{return {READ};}}const p=read();fetch("/api",{{body:p}});')
        self.assertEqual(sensitive(o)[0]['support_scope'], 'interprocedural')

    def test_three_hop_nested_call(self):
        self.positive(f'function a(x){{b(x)}}function b(x){{c(x)}}function c(x){{fetch("/api",{{body:x}})}}a({READ});')

    def test_object_argument_property_and_alias(self):
        self.positive(f'function send(data){{fetch("/api",{{body:data.a}})}}const payload={{a:{READ}}};send(payload);')

    def test_renamed_payload_roles(self):
        o = self.positive(SEND + f'send({{user:document.getElementById("email").value,secret:{READ}}});')
        self.assertEqual({f['semantic_role'] for f in sensitive(o)}, {'email', 'password'})
        sink = next(s for s in o.javascript['sinks'] if s['id'] == sensitive(o)[0]['sink_id'])
        fields = {f['name']: f['semantic_roles'] for f in sink['payload']['fields']}
        self.assertEqual(fields['secret'], ['password'])

    def test_immutable_alias(self):
        o = self.positive(SEND + f'const submit=send;submit({READ});')
        self.assertTrue(any(t['kind'] == 'function_alias' for t in o.javascript['transforms']))

    def test_conditional_call(self):
        o = self.positive(SEND + f'if(unknown){{send({READ});}}')
        self.assertTrue(any(e['path_condition'] == 'conditional' for e in o.javascript['call_edges']))

    def test_event_handler_calls_helper(self):
        o = self.positive(SEND + f'button.addEventListener("click",()=>{{send({READ});}});')
        edge = next(e for e in o.javascript['call_edges'] if e['callee_name'] == 'send')
        self.assertEqual(edge['execution_context'], 'handler_declared')
        text = '\n'.join(javascript_lines(o.javascript))
        self.assertIn('runtime execution: not established', text)

    def test_loop_call_once_no_iteration_claim(self):
        o = self.positive(SEND + f'while(unknown){{send({READ});}}')
        self.assertEqual(len(sensitive(o)), 1)

    def test_local_static_configuration(self):
        o = self.positive(f'const Config={{endpoint:"/api",method:"POST"}};fetch(Config.endpoint,{{method:Config.method,body:{READ}}});')
        self.assertEqual(o.javascript['sinks'][0]['method'], 'POST')
        self.assertEqual(o.javascript['sinks'][0]['target'], 'https://e.test/api')

    def test_nested_configuration(self):
        o = self.positive(f'const Config={{api:{{collect:"/api"}}}};fetch(Config.api.collect,{{body:{READ}}});')
        self.assertEqual(o.javascript['sinks'][0]['target'], 'https://e.test/api')

    def test_helper_static_configuration(self):
        o = self.positive(f'const Config={{api:{{collect:"/api"}}}};function send(x){{fetch(Config.api.collect,{{body:x}})}}send({READ});')
        sink = next(s for s in o.javascript['sinks'] if s['id'] == sensitive(o)[0]['sink_id'])
        self.assertEqual(sink['target'], 'https://e.test/api')

    def test_runtime_join_only_endpoint(self):
        result = {'page': {'url': 'https://e.test/page/index.html'}, 'data': {'requests': [request('https://e.test/api/collect', method='POST')]}}
        o = inspect(SEND + f'send({READ});', result=result)
        sink = next(s for s in o.javascript['sinks'] if s['id'] == sensitive(o)[0]['sink_id'])
        self.assertEqual(sink['runtime_endpoint'], 'endpoint_observed')
        self.assertEqual(sink['payload_relationship'], 'unresolved')
        self.assertTrue(all(j['state'] == 'endpoint_observed' for j in o.javascript['runtime_joins']))

    def test_missing_and_extra_arguments(self):
        o = inspect('function send(a,b){fetch("/api",{body:b});}send("context");')
        self.assertEqual(sensitive(o), [])
        o = self.positive(f'function send(a){{fetch("/api",{{body:a}})}}send({READ},unknown);')
        self.assertEqual(len(o.javascript['call_edges'][0]['argument_mappings']), 1)

    def test_uncalled_parameter_helper(self):
        o = inspect(SEND + f'const p={READ};')
        self.assertEqual(sensitive(o), [])
        self.assertEqual(o.javascript['call_edges'], [])
        self.assertTrue(o.javascript['sinks'])

    def test_unknown_return_is_not_identity(self):
        for expression in ['mystery(p)', 'identity(p)']:
            o = inspect(f'function identity(x){{return unknown(x)}}const p={READ};const x={expression};fetch("/api",{{body:x}});')
            self.assertEqual(sensitive(o), [])

    def test_reassigned_alias_unresolved(self):
        o = inspect(SEND + f'let fn=send;fn=unknownFn;fn({READ});')
        self.assertEqual(sensitive(o), [])
        self.assertTrue(any(e['call_resolution'] == 'unresolved' for e in o.javascript['call_edges']))

    def test_dynamic_dispatch_and_factory(self):
        for call in ['obj[key](p)', 'window[name](p)', 'unknown.method(p)', 'getHandler()(p)', 'factory().send(p)', 'importedUnknown(p)']:
            with self.subTest(call=call):
                o = inspect(SEND + f'const p={READ};const x={call};fetch("/api",{{body:x}});')
                self.assertEqual(sensitive(o), [])
                self.assertTrue(any(e['call_resolution'] == 'unresolved' for e in o.javascript['call_edges']))

    def test_config_mutation_no_stale_target(self):
        for mutation in ['cfg.endpoint=dynamic()', 'const alias=cfg;alias.endpoint=dynamic()', 'escape(cfg)']:
            o = inspect(f'const cfg={{endpoint:"/safe"}};{mutation};fetch(cfg.endpoint);')
            self.assertEqual(o.javascript['sinks'][-1]['target_resolution'], 'unresolved')
        o = inspect('const cfg={api:{endpoint:"/safe"}};const a=cfg.api;a.endpoint=dynamic();fetch(cfg.api.endpoint);')
        self.assertEqual(o.javascript['sinks'][-1]['target_resolution'], 'unresolved')

    def test_helper_outer_mutation_invalidates_caller_configuration(self):
        o = inspect('const cfg={endpoint:"/safe"};function change(){cfg.endpoint=dynamic()}change();fetch(cfg.endpoint);')
        self.assertEqual(o.javascript['sinks'][-1]['target_resolution'], 'unresolved')

    def test_nested_configuration_alias_escape_not_stale(self):
        for call in ['escape(cfg);', 'escape({nested:cfg});', 'function change(x){x.api.endpoint=unknown}change(cfg);',
                     'function change(){cfg.api.endpoint=unknown}change();']:
            o = inspect('const cfg={api:{endpoint:"/safe"}};const alias=cfg.api;' + call + 'fetch(alias.endpoint);')
            self.assertEqual(o.javascript['sinks'][-1]['target_resolution'], 'unresolved')

    def test_callee_local_write_does_not_invalidate_caller_source(self):
        self.positive(f'function helper(email){{email=unknown}}const email={READ};helper("context");fetch("/api",{{body:email}});')

    def test_multiple_contexts_share_unique_runtime_evidence(self):
        result = {'page':{'url':'https://e.test/'}, 'data':{'requests':[request('https://e.test/api/collect',method='POST')]}}
        o = inspect(SEND + f'send({READ});send({READ});', result=result)
        self.integrity(o)
        self.assertEqual(len(sensitive(o)), 2)

    def test_return_and_call_evidence_provenance(self):
        o = self.positive(f'function read(){{return {READ};}}fetch("/api",{{body:read()}});')
        edge = o.javascript['call_edges'][0]
        self.assertTrue(edge['source_evidence_refs'])
        self.assertTrue(edge['sink_evidence_refs'])
        self.assertEqual(edge['flow_refs'], [sensitive(o)[0]['id']])
        steps = [t for t in o.javascript['transforms'] if t['kind'] == 'function_return']
        self.assertTrue(any(t.get('return_location') for t in steps))

    def test_distinct_positional_parameters_and_flow_fields(self):
        o = self.positive(f'function send(a,b){{fetch("/api",{{body:JSON.stringify({{user:a,secret:b}})}})}}send(document.getElementById("email").value,{READ});')
        edge = o.javascript['call_edges'][0]
        self.assertEqual([(m['argument_index'],m['parameter_name']) for m in edge['argument_mappings']], [(0,'a'),(1,'b')])
        self.assertEqual({f['semantic_role'] for f in sensitive(o)}, {'email','password'})

    def test_spread_argument_unresolved(self):
        o = inspect(SEND + f'const args=[{READ}];send(...args);')
        self.assertEqual(sensitive(o), [])

    def test_return_constant_target_has_callee_evidence(self):
        o = inspect('function target(){return "https://e.test/api"}fetch(target());')
        sink = o.javascript['sinks'][0]
        self.assertEqual(sink['target'], 'https://e.test/api')
        self.assertTrue(set(o.javascript['call_edges'][0]['evidence_refs']) <= set(sink['evidence_refs']))

    def test_token_names_and_argument_values_omitted(self):
        token = 'ghp_' + 'a'*36
        o = inspect(f'function {token}(password){{fetch(password)}}{token}("hunter2");')
        for text in [json.dumps(o.javascript), '\n'.join(javascript_lines(o.javascript,verbose=True))]:
            self.assertNotIn(token, text)
            self.assertNotIn('hunter2', text)

    def test_cycles_truncate_without_flow(self):
        o = inspect(f'function a(x){{return b(x)}}function b(x){{return a(x)}}fetch("/api",{{body:a({READ})}});')
        self.assertEqual(sensitive(o), [])
        self.assertTrue(o.javascript['truncated'])
        self.assertTrue(any(e['reason'] == 'interprocedural_cycle_detected' for e in o.javascript['call_edges']))
        self.integrity(o)

    def test_cycle_with_early_sink_withheld(self):
        o = inspect(f'function a(x){{fetch("/api",{{body:x}});return a(x)}}a({READ});')
        self.assertEqual(sensitive(o), [])
        self.integrity(o)

    def test_depth_limit(self):
        o = inspect(f'function a(x){{b(x)}}function b(x){{c(x)}}function c(x){{d(x)}}function d(x){{fetch("/api",{{body:x}})}}a({READ});')
        self.assertEqual(sensitive(o), [])
        self.assertTrue(o.javascript['truncated'])
        self.assertTrue(any(e['reason'] == 'interprocedural_depth_limit' for e in o.javascript['call_edges']))
        self.integrity(o)

    def test_shadowed_intrinsics(self):
        for code in [f'function send(fetch){{fetch("/api",{{body:{READ}}})}}send(unknown);',
                     'function f(document){fetch("/api",{body:document.querySelector("#password").value})}f(document);']:
            self.assertEqual(sensitive(inspect(code)), [])

    def test_unknown_framework_callback_not_invoked(self):
        self.assertEqual(sensitive(inspect(SEND + 'someFramework(send);')), [])

    def test_conditional_return_not_propagated(self):
        for body in [f'if(c)return {READ};', f'if(c)return {READ};return "context";']:
            self.assertEqual(sensitive(inspect(f'function read(){{{body}}}fetch("/api",{{body:read()}});')), [])

    def test_async_and_destructuring_unresolved(self):
        for helper in ['async function f(p){return p}', 'function f({p}){return p}', 'function f(...p){return p}']:
            o = inspect(helper + f'fetch("/api",{{body:f({READ})}});')
            self.assertEqual(sensitive(o), [])

    def test_complex_return_control_withheld(self):
        o = inspect(f'function read(){{try{{return {READ}}}finally{{return "context"}}}}fetch("/api",{{body:read()}});')
        self.assertEqual(sensitive(o), [])
        self.assertEqual(o.javascript['call_edges'][0]['propagation'], 'unresolved')

    def test_unsupported_callee_invalidates_mutable_argument(self):
        o = inspect(f'async function change(x){{x.secret=unknown}}const data={{secret:{READ}}};change(data);fetch("/api",{{body:JSON.stringify(data)}});')
        self.assertEqual(sensitive(o), [])

    def test_prototype_configuration_unresolved(self):
        o = inspect('const cfg={__proto__:{endpoint:"/api"}};fetch(cfg.endpoint);')
        self.assertEqual(o.javascript['sinks'][0]['target_resolution'], 'unresolved')

    def test_nested_configuration_depth_limit(self):
        o = inspect('const cfg={a:{b:{c:{d:{e:{endpoint:"/api"}}}}}};fetch(cfg.a.b.c.d.e.endpoint);')
        self.assertEqual(o.javascript['sinks'][0]['target_resolution'], 'unresolved')

    def test_mutable_parameter_escape_invalidates(self):
        o = inspect(f'function send(data){{escape(data);fetch("/api",{{body:JSON.stringify(data)}})}}send({{secret:{READ}}});')
        self.assertEqual(sensitive(o), [])

    def test_mutable_caller_after_call_not_stale(self):
        o = inspect(f'function change(x){{x.secret=unknown}}const data={{secret:{READ}}};change(data);fetch("/api",{{body:JSON.stringify(data)}});')
        self.assertEqual(sensitive(o), [])

    def test_duplicate_functions_no_arbitrary_choice(self):
        o = inspect(f'function send(x){{fetch("/api",{{body:x}})}}function send(x){{return x}}send({READ});')
        self.assertEqual(sensitive(o), [])

    def test_no_caller_local_dynamic_scope(self):
        o = inspect(f'function send(){{fetch("/api",{{body:p}})}}function caller(){{const p={READ};send()}}caller();')
        self.assertEqual(sensitive(o), [])

    def test_callsite_isolation(self):
        o = self.positive(f'function send(x){{fetch("/api",{{body:x}})}}send({READ});send("context");')
        self.assertEqual(len(sensitive(o)), 1)
        self.assertEqual(len({s['id'] for s in o.javascript['sinks']}), 3)

    def test_determinism_and_raw_integrity(self):
        code = SEND + f'send({READ});'
        a, b = inspect(code), inspect(code)
        self.assertEqual(a.to_dict(), b.to_dict())
        result = {'page': {'url': 'https://e.test/?password=hunter2'}, 'raw': {'token': 'unchanged'}}
        before = deepcopy(result)
        o = inspect(code, result=result)
        self.assertEqual(result, before)
        self.assertEqual(analysis_envelope(result, SCAN, b'', o)['result'], before)

    def test_literal_secret_privacy(self):
        tokens = ['ghp_' + 'a'*36, 'sk-' + 'b'*40, 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature']
        code = 'function send(password,otp,cvv,pan){fetch(password);fetch(otp);fetch(cvv);fetch(pan)}send("hunter2","123456","123","4111111111111111");'
        o = inspect(code)
        for verbose in (False, True):
            text = '\n'.join(javascript_lines(o.javascript, verbose=verbose)) + json.dumps(o.javascript)
            for secret in ['hunter2', '123456', '4111111111111111', '/123']:
                self.assertNotIn(secret, text)
        for token in tokens:
            o = inspect(f'const {token.replace("-","_").replace(".","_")}=(x)=>fetch("/api",{{body:x}});')
            self.assertNotIn(token, json.dumps(o.javascript))

    def test_passive_boundary_with_calls(self):
        with contextlib.ExitStack() as guards:
            for target in ['urllib.request.urlopen','socket.socket','socket.getaddrinfo','subprocess.Popen','subprocess.run','builtins.eval','builtins.exec','builtins.open','pathlib.Path.open']:
                guards.enter_context(patch(target, side_effect=AssertionError('passive boundary')))
            o = inspect(SEND + f'send({READ});')
        self.assertTrue(sensitive(o))

    def test_interprocedural_budget_withholds_only_dependent_propagation(self):
        for budget, value in [('MAX_CALL_EDGES',0),('MAX_INVOCATIONS',0),('MAX_ARGUMENT_MAPPINGS',0),('MAX_RETURNS',0),('MAX_CROSS_STEPS',0)]:
            with self.subTest(budget=budget), patch.object(engine, budget, value):
                o = inspect(f'function read(p){{return p}}fetch("/api",{{body:read({READ})}});')
                self.assertTrue(o.javascript['truncated'])
                self.assertEqual(sensitive(o), [])
                self.assertEqual(o.javascript['scripts'][0]['parser_status'], 'parsed')
                self.assertTrue(o.javascript['interprocedural']['truncated'])
                self.integrity(o)

    def test_execution_renderer_static_relationship(self):
        o = self.positive(SEND + f'send({READ});')
        for verbose in (False,True):
            text = '\n'.join(javascript_lines(o.javascript,verbose=verbose))
            self.assertIn('statically reachable from call', text)
            self.assertIn('runtime execution: not established', text)
            self.assertIn('Static helper path:', text)


class OrderedConfigurationTests(unittest.TestCase):
    def scripts(self, *scripts):
        return analyze({'page':{'url':'https://e.test/'}},SCAN,(HTML+''.join(scripts)).encode())

    def test_ordered_inline_constant(self):
        o = self.scripts('<script>const API="/api";</script>',f'<script>fetch(API,{{body:{READ}}});</script>')
        self.assertEqual(o.javascript['sinks'][0]['target'],'https://e.test/api')
        refs = {e.id:e for e in o.evidence}
        self.assertTrue(any(refs[r].location.get('script_index') == 0 for r in o.javascript['sinks'][0]['evidence_refs']))

    def test_ordered_nested_config(self):
        o=self.scripts('<script>const Config={api:{endpoint:"/api"},method:"POST"};</script>',f'<script>fetch(Config.api.endpoint,{{method:Config.method,body:{READ}}});</script>')
        self.assertEqual(o.javascript['sinks'][0]['target'],'https://e.test/api')
        self.assertEqual(o.javascript['sinks'][0]['method'],'POST')

    def test_reverse_order_not_guessed(self):
        o=self.scripts('<script>fetch(API);</script>','<script>const API="/api";</script>')
        self.assertEqual(o.javascript['sinks'][0]['target_resolution'],'unresolved')

    def test_prior_script_builtin_shadow_not_browser_intrinsic(self):
        for declaration in ['const fetch=unknown;', 'function fetch(x){}', 'var fetch=unknown;']:
            o=self.scripts('<script>'+declaration+'</script>',f'<script>fetch("/api",{{body:{READ}}});</script>')
            self.assertEqual(o.javascript['sinks'], [])

    def test_duplicate_names_unresolved(self):
        o=self.scripts('<script>const API="/a";</script>','<script>const API="/b";</script>','<script>fetch(API);</script>')
        self.assertEqual(o.javascript['sinks'][0]['target_resolution'],'unresolved')

    def test_external_async_module_boundaries(self):
        for boundary in ['<script src="/missing.js"></script>','<script type="module">const x=1;</script>','<script async>const x=1;</script>']:
            o=self.scripts('<script>const API="/a";</script>',boundary,'<script>fetch(API);</script>')
            self.assertEqual(o.javascript['sinks'][0]['target_resolution'],'unresolved')

    def test_archive_order_not_document_order(self):
        o=analyze({'page':{'url':'https://e.test/'}},SCAN,HTML.encode(),archived_scripts=(
            {'body':'const API="https://e.test/api";','document_url':'https://e.test/'},
            {'body':'fetch(API);','document_url':'https://e.test/'}))
        self.assertEqual(o.javascript['sinks'][0]['target_resolution'],'unresolved')

    def test_cross_script_mutation_invalidates(self):
        o=self.scripts('<script>const cfg={endpoint:"/a"};</script>','<script>cfg.endpoint=dynamic();</script>','<script>fetch(cfg.endpoint);</script>')
        self.assertEqual(o.javascript['sinks'][0]['target_resolution'],'unresolved')

    def test_no_cross_script_sensitive_source(self):
        o=self.scripts(f'<script>const p={READ};</script>','<script>fetch("/api",{body:p});</script>')
        self.assertEqual(sensitive(o),[])

    def test_cross_script_parse_failure_no_export(self):
        o=self.scripts('<script>const API="/a";</script>','<script>function bad(</script>','<script>fetch(API);</script>')
        self.assertEqual(o.javascript['sinks'][0]['target_resolution'],'unresolved')


if __name__ == '__main__':
    unittest.main()
