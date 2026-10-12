"""Offline AST primitives, false-positive boundaries, budgets and privacy."""
import contextlib
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from urlscanx.analysis import analyze, analysis_envelope
from urlscanx.analysis import javascript as frontend
from urlscanx.analysis.render import format_analysis, javascript_lines
from urlscanx.cli import main
from test_analysis import request, SCAN, fixture

HTML = ('<form id="login"><input id="email" name="email" type="email">'
        '<input id="password" name="password" type="password">'
        '<input id="otp" name="otp" autocomplete="one-time-code"></form>')
READ = 'document.getElementById("password").value'


def inspect(code, html=HTML, result=None, script_type=''):
    result = result or {'task': {}, 'page': {'url': 'https://e.test/page/index.html'}}
    dom = (html + '<script type="' + script_type + '">' + code + '</script>').encode()
    output = analyze(result, SCAN, dom)
    return output


def sensitive(output):
    return [f for f in output.javascript['flows'] if f['sensitive']]


class ExecutionWordingTests(unittest.TestCase):
    def assert_execution_wording(self, code, context, result=None):
        output = inspect(code, result=result)
        before = deepcopy(output.to_dict())
        self.assertEqual(len(output.javascript['sources']), 1)
        self.assertEqual(len(output.javascript['sinks']), 1)
        self.assertEqual(len(sensitive(output)), 1)
        self.assertEqual(sensitive(output)[0]['state'], 'static_flow_inferred')
        for verbose in (False, True):
            text = '\n'.join(javascript_lines(output.javascript, verbose=verbose))
            self.assertIn('execution context: ' + context + '; runtime execution: not established', text)
            self.assertIn('state: static_flow_inferred', text)
            for claim in ('runtime execution: executed', 'runtime execution: observed',
                          'runtime execution: active', 'runtime execution: triggered'):
                self.assertNotIn(claim, text)
        self.assertEqual(output.to_dict(), before)
        return output

    def test_uncalled_function_declared_only(self):
        output = self.assert_execution_wording(
            f'function neverCalled() {{const p={READ}; fetch("/api", {{body:p}});}}',
            'function declared only')
        sink = output.javascript['sinks'][0]
        self.assertEqual(sink['execution_context'], 'declared')
        self.assertIn(':function:', sink['scope_ref'])

    def test_event_handler_declared_only(self):
        output = self.assert_execution_wording(
            f'form.addEventListener("submit", () => {{const p={READ}; fetch("/api", {{body:p}});}});',
            'handler declared only')
        self.assertEqual(output.javascript['sinks'][0]['execution_context'], 'handler_declared')

    def test_top_level_static_execution_unestablished(self):
        output = self.assert_execution_wording(f'const p={READ}; fetch("/api", {{body:p}});',
                                               'top-level static code')
        self.assertTrue(output.javascript['sinks'][0]['scope_ref'].endswith(':script'))
        self.assertNotIn('function declared only', '\n'.join(javascript_lines(output.javascript)))

    def test_endpoint_overlap_does_not_establish_function_execution(self):
        result = {'task': {}, 'page': {'url': 'https://e.test/page/index.html'},
                  'data': {'requests': [request('https://e.test/api', method='POST')]}}
        output = self.assert_execution_wording(
            f'function neverCalled() {{const p={READ}; fetch("/api", {{method:"POST", body:p}});}}',
            'function declared only', result)
        self.assertEqual(output.javascript['sinks'][0]['runtime_endpoint'], 'endpoint_observed')


class SourceTests(unittest.TestCase):
    def test_get_element_by_id(self):
        o = inspect(f'fetch("/api", {{body:{READ}}});')
        self.assertEqual([f['semantic_role'] for f in sensitive(o)], ['password'])
        c = next(c for c in o.dom_inventory['controls'] if c['semantic_role'] == 'password')
        self.assertEqual(o.javascript['sources'][0]['control_id'], c['id'])
        self.assertTrue(set(c['evidence_refs']) <= set(o.javascript['sources'][0]['evidence_refs']))

    def test_query_selector_and_input_alias(self):
        for expression in ['document.querySelector("#password")', 'document.querySelector("input[name=\\"password\\"]")']:
            with self.subTest(expression=expression):
                o = inspect(f'const input={expression}; const p=input.value; fetch("/api", {{body:p}});')
                self.assertEqual(len(sensitive(o)), 1)

    def test_form_elements(self):
        o = inspect('const form=document.getElementById("login"); fetch("/api", {body:form.elements["password"].value});')
        self.assertEqual(len(sensitive(o)), 1)

    def test_unknown_selector_and_duplicate_id(self):
        for code, html in [(f'const id=unknown; fetch("/api",{{body:document.querySelector(id).value}});', HTML),
                           (f'fetch("/api",{{body:{READ}}});', HTML + '<div id="password"></div>'),
                           ('fetch("/api", {body:document.querySelector("#password-label").textContent});', HTML + '<label id="password-label">Password</label>')]:
            with self.subTest(code=code):
                self.assertEqual(sensitive(inspect(code, html)), [])

    def test_incompatible_and_inert_controls(self):
        for html in ['<input id="password" type="checkbox" name="password">', '<template>' + HTML + '</template>']:
            with self.subTest(html=html):
                self.assertEqual(sensitive(inspect(f'fetch("/api", {{body:{READ}}});', html)), [])

    def test_url_parameter(self):
        o = inspect('const params=new URLSearchParams(location.search); fetch("/api", {body:params.get("email")});')
        source = next(s for s in o.javascript['sources'] if s['source_kind'] == 'url_parameter')
        self.assertEqual(source['parameter_name'], 'email')
        self.assertTrue(any(f['source_id'] == source['id'] for f in o.javascript['flows']))

    def test_storage_reads(self):
        for storage in ['localStorage', 'sessionStorage']:
            with self.subTest(storage=storage):
                o = inspect(f'fetch("/api", {{body:{storage}.getItem("x")}});')
                self.assertEqual(o.javascript['sources'][0]['source_kind'], 'storage_read')
                self.assertEqual(o.javascript['sources'][0]['key_name'], 'x')

    def test_browser_properties(self):
        for expression in ['navigator.userAgent', 'navigator.language', 'document.referrer', 'screen.width', 'screen.height',
                           'location.href', 'location.search', 'location.hash', 'window.location.search']:
            with self.subTest(expression=expression):
                o = inspect(f'fetch("/api", {{body:{expression}}});')
                self.assertEqual(o.javascript['sources'][0]['source_kind'], 'browser_context')
                self.assertEqual(len(o.javascript['flows']), 1)
                self.assertEqual(sensitive(o), [])


class TransformTests(unittest.TestCase):
    def chain(self, code):
        o = inspect(f'const p={READ}; ' + code)
        self.assertEqual(len(sensitive(o)), 1)
        f = sensitive(o)[0]
        ts = {t['id']: t for t in o.javascript['transforms']}
        return o, [ts[i]['kind'] for i in f['transform_ids']]

    def test_alias_and_assignment(self):
        _, chain = self.chain('let a=p; let b; b=a; fetch("/api", {body:b});')
        self.assertIn('variable_alias', chain)
        self.assertIn('direct_assignment', chain)

    def test_object_and_stringify(self):
        o, chain = self.chain('const data={password:p}; fetch("/api", {body:JSON.stringify(data)});')
        for transform in ['object_property', 'object_construction', 'JSON.stringify']:
            self.assertIn(transform, chain)
        self.assertEqual(o.javascript['sinks'][0]['payload']['encoding'], 'json')
        self.assertEqual(o.javascript['sinks'][0]['payload']['fields'][0]['name'], 'password')

    def test_property_assignment_and_alias_identity(self):
        o, chain = self.chain('const data={}; const alias=data; alias.password=p; fetch("/api", {body:JSON.stringify(data)});')
        self.assertIn('property_assignment', chain)
        self.assertEqual(o.javascript['sinks'][0]['payload']['fields'][0]['name'], 'password')

    def test_array_insertion(self):
        _, chain = self.chain('const data=[p]; fetch("/api", {body:JSON.stringify(data)});')
        self.assertIn('array_insertion', chain)

    def test_concatenation_and_template(self):
        for expression, kind in [('"password=" + p', 'string_concatenation'), ('`password=${p}`', 'template_interpolation')]:
            with self.subTest(expression=expression):
                _, chain = self.chain(f'fetch("/api", {{body:{expression}}});')
                self.assertIn(kind, chain)

    def test_named_transforms(self):
        for expression, kind in [('encodeURIComponent(p)', 'encodeURIComponent'), ('decodeURIComponent(p)', 'decodeURIComponent'),
                                 ('btoa(p)', 'btoa'), ('atob(p)', 'atob'), ('p.trim()', 'trim'),
                                 ('p.toLowerCase()', 'toLowerCase'), ('p.toUpperCase()', 'toUpperCase')]:
            with self.subTest(expression=expression):
                _, chain = self.chain(f'fetch("/api", {{body:{expression}}});')
                self.assertIn(kind, chain)

    def test_form_data_append_set(self):
        for ctor in ['FormData', 'URLSearchParams']:
            for method in ['append', 'set']:
                with self.subTest(ctor=ctor, method=method):
                    o, chain = self.chain(f'const d=new {ctor}(); d.{method}("password", p); fetch("/api", {{body:d}});')
                    self.assertIn(method, chain)
                    self.assertEqual(o.javascript['sinks'][0]['payload']['encoding'], 'form_data' if ctor == 'FormData' else 'url_search_params')

    def test_form_data_from_form(self):
        o = inspect('const f=document.getElementById("login"); const d=new FormData(f); fetch("/api", {body:d});')
        self.assertEqual({f['semantic_role'] for f in sensitive(o)}, {'email', 'password', 'otp_candidate'})

    def test_url_search_params_from_object(self):
        _, chain = self.chain('const d=new URLSearchParams({password:p}); fetch("/api", {body:d});')
        self.assertIn('URLSearchParams_construction', chain)


class SinkTests(unittest.TestCase):
    def test_fetch_method_headers_body(self):
        o = inspect(f'fetch("/api", {{method:"post", headers:{{"Content-Type":"application/json", Authorization:"hunter2"}}, body:{READ}}});')
        s = o.javascript['sinks'][0]
        self.assertEqual((s['sink_kind'], s['method'], s['target']), ('fetch', 'POST', 'https://e.test/api'))
        self.assertTrue(all(h['value'] == '[omitted]' for h in s['headers']))
        self.assertNotIn('hunter2', json.dumps(o.to_dict()))

    def test_xhr_alias_receiver(self):
        o = inspect(f'const x=new XMLHttpRequest(); const y=x; y.open("POST", "/api"); x.send({READ});')
        self.assertEqual(o.javascript['sinks'][0]['sink_kind'], 'xmlhttprequest')
        self.assertEqual(o.javascript['sinks'][0]['method'], 'POST')
        self.assertEqual(len(sensitive(o)), 1)

    def test_xhr_identity_does_not_cross_receiver(self):
        o = inspect(f'const x=new XMLHttpRequest(); const y=new XMLHttpRequest(); x.open("POST","/api"); y.send({READ});')
        self.assertEqual(o.javascript['sinks'][0]['target_resolution'], 'unresolved')

    def test_beacon(self):
        o = inspect(f'navigator.sendBeacon("/api", {READ});')
        self.assertEqual(o.javascript['sinks'][0]['sink_kind'], 'send_beacon')
        self.assertEqual(o.javascript['sinks'][0]['method'], 'POST')

    def test_storage_write(self):
        o = inspect(f'sessionStorage.setItem("x", {READ});')
        self.assertEqual(o.javascript['sinks'][0]['sink_kind'], 'browser_storage_write')
        self.assertEqual(o.javascript['sinks'][0]['key_name'], 'x')
        self.assertEqual(len(sensitive(o)), 1)

    def test_navigation(self):
        for expression in [f'location.href="/next?x="+{READ}', f'location.assign("/next?x="+{READ})', f'location.replace("/next?x="+{READ})']:
            with self.subTest(expression=expression):
                o = inspect(expression + ';')
                self.assertEqual(o.javascript['sinks'][0]['sink_kind'], 'navigation')
                self.assertEqual(sensitive(o)[0]['channel'], 'target')
                self.assertEqual(o.javascript['sinks'][0]['target_resolution'], 'unresolved')

    def test_explicit_form_calls_only(self):
        for method in ['submit', 'requestSubmit']:
            with self.subTest(method=method):
                o = inspect(f'document.getElementById("login").{method}();')
                self.assertEqual(len(o.javascript['sinks']), 1)
                self.assertTrue(o.javascript['sinks'][0]['sink_kind'].startswith('form_'))
        self.assertEqual(inspect('').javascript['sinks'], [])

    def test_resolution(self):
        for target, expected in [('https://other.test/a', 'https://other.test/a'), ('//other.test/a', 'https://other.test/a'),
                                 ('/api', 'https://e.test/api'), ('api', 'https://e.test/page/api')]:
            with self.subTest(target=target):
                self.assertEqual(inspect(f'fetch("{target}");').javascript['sinks'][0]['target'], expected)
        self.assertEqual(inspect('fetch("api");', '<base href="/else/">' + HTML).javascript['sinks'][0]['target_resolution'], 'unresolved')

    def test_endpoint_join_requires_target_and_method(self):
        result = {'task': {}, 'page': {'url': 'https://e.test/'}, 'data': {'requests': [request(url='https://e.test/api?x=raw-secret', method='POST')]}}
        o = inspect(f'fetch("/api?x=different",{{method:"POST",body:{READ}}});', result=result)
        self.assertEqual(len(o.javascript['runtime_joins']), 1)
        self.assertEqual(o.javascript['runtime_joins'][0]['state'], 'endpoint_observed')
        self.assertEqual(o.javascript['runtime_joins'][0]['payload_relationship'], 'unresolved')
        self.assertTrue(any(e.state == 'runtime_observed' for e in o.evidence))
        for code in ['fetch("/api",{method:"GET"});', 'fetch("/different",{method:"POST"});', 'fetch(unknown,{method:"POST"});']:
            self.assertEqual(inspect(code, result=result).javascript['runtime_joins'], [])


class BoundaryTests(unittest.TestCase):
    def test_literal_names_are_not_sensitive_sources(self):
        for code in ['const password="label only";', 'console.log("password");', 'fetch("/science");',
                     'const payload={message:"password reset available"}; fetch("/api",{body:JSON.stringify(payload)});']:
            with self.subTest(code=code):
                self.assertEqual(sensitive(inspect(code)), [])

    def test_scopes_and_shadowing(self):
        for code in [f'const p={READ}; function f(){{fetch("/api",{{body:p}});}}',
                     f'const p={READ}; {{const p="label";fetch("/api",{{body:p}});}}',
                     f'function f(document){{fetch("/api",{{body:{READ}}});}}',
                     f'function f(fetch){{fetch("/api",{{body:{READ}}});}}',
                     f'const p={READ}; const fetch=unknown; fetch("/api",{{body:p}});',
                     f'function f(){{fetch("/api",{{body:p}}); var p={READ};}}']:
            with self.subTest(code=code):
                self.assertEqual(sensitive(inspect(code)), [])

    def test_function_local_and_handlers(self):
        for code in [f'function unused(){{const p={READ}; fetch("/api",{{body:p}});}}',
                     f'document.addEventListener("submit",()=>{{const p={READ};fetch("/api",{{body:p}});}});',
                     f'button.onclick=function(){{const p={READ};fetch("/api",{{body:p}});}};']:
            with self.subTest(code=code):
                o = inspect(code)
                self.assertEqual(len(sensitive(o)), 1)
                self.assertEqual(sensitive(o)[0]['state'], 'static_flow_inferred')
                self.assertTrue(all(s['execution_context'] in {'declared', 'handler_declared'} for s in o.javascript['sinks']))

    def test_interprocedural_explicit_local_call_propagated(self):
        o = inspect(f'function collect(x){{fetch("/api",{{body:x}});}} const p={READ}; collect(p);')
        self.assertEqual(len(sensitive(o)), 1)
        self.assertEqual(o.javascript['call_edges'][0]['call_resolution'], 'resolved')
        self.assertTrue(o.javascript['sources'])

    def test_cross_script_and_return_boundary(self):
        o = analyze({'task': {}}, SCAN, (HTML + f'<script>const p={READ};</script><script>fetch("/api",{{body:p}});</script>').encode())
        self.assertEqual(sensitive(o), [])
        dead = sensitive(inspect(f'function f(){{return;fetch("/api",{{body:{READ}}});}}'))
        self.assertTrue(dead)
        self.assertTrue(all(f['static_path_state'] == 'statically_unreachable' for f in dead))

    def test_ambiguous_mutation_and_unsupported_object(self):
        for code in [f'const p={READ}; let x=p; if(unknown) x="constant";fetch("/api",{{body:x}});',
                     f'const d={{password:{READ}}}; mutate(d);fetch("/api",{{body:JSON.stringify(d)}});',
                     f'const d={{...unknown, password:{READ}}};fetch("/api",{{body:JSON.stringify(d)}});',
                     f'const d={{get password(){{return {READ};}}}};fetch("/api",{{body:JSON.stringify(d)}});']:
            with self.subTest(code=code):
                self.assertEqual(sensitive(inspect(code)), [])

    def test_parse_failure_nonfatal_and_no_source_excerpt(self):
        o = inspect('const password="hunter2"; const broken = ;')
        self.assertEqual(o.javascript['scripts'][0]['parser_status'], 'failed')
        self.assertNotIn('hunter2', json.dumps(o.to_dict()))
        self.assertIsNotNone(o.dom_inventory)
        self.assertEqual(o.javascript['flows'], [])

    def test_inert_script_types(self):
        code = f'fetch("/api", {{body:{READ}}});'
        for script_type in ['application/json', 'application/ld+json', 'text/template']:
            self.assertEqual(sensitive(inspect(code, script_type=script_type)), [])
        for context in ['template', 'noscript']:
            o = analyze({'task': {}}, SCAN, (HTML + f'<{context}><script>{code}</script></{context}>').encode())
            self.assertEqual(sensitive(o), [])
            self.assertEqual(o.javascript['scripts'][0]['parser_status'], 'skipped')

    def test_module_imports_not_followed(self):
        o = inspect('import config from "./not-preserved.js"; fetch(config.url);', script_type='module')
        self.assertEqual(o.javascript['scripts'][0]['parser_status'], 'parsed')
        self.assertEqual(o.javascript['sinks'][0]['target_resolution'], 'unresolved')
        self.assertEqual(o.javascript['calls'][0]['kind'], 'import_unfollowed')

    def test_external_unavailable_and_archived_explicit(self):
        o = analyze({'task': {}}, SCAN, b'<script src="https://target.test/a.js"></script>')
        self.assertTrue(all(not s['code_analyzed'] for s in o.javascript['scripts']))
        self.assertEqual(o.javascript['scripts'][0]['state'], 'artifact_unavailable')
        o = analyze({'task': {}, 'page': {'url': 'https://e.test/'}}, SCAN, HTML.encode(),
                    archived_scripts=({'body': f'fetch("/api",{{body:{READ}}});', 'url': 'https://e.test/a.js', 'document_url': 'https://e.test/'},))
        self.assertEqual(len(sensitive(o)), 1)
        self.assertEqual(o.javascript['scripts'][0]['kind'], 'archived')

    def test_preserved_result_body_and_dom_independent_provenance(self):
        r = request(url='https://e.test/a.js')
        r['request']['type'] = 'Script'
        r['response']['body'] = 'fetch("/api");'
        result = {'task': {}, 'page': {'url': 'https://e.test/'}, 'data': {'requests': [r]}}
        a = analyze(result, SCAN)
        b = analyze(result, SCAN, (HTML + '<script>const n=1;</script>').encode())
        self.assertEqual([e for e in a.evidence if e.origin == 'urlscan_result'], [e for e in b.evidence if e.origin == 'urlscan_result'])
        self.assertTrue(any(s['kind'] == 'external_preserved' and s['code_analyzed'] for s in a.javascript['scripts']))

    def test_privacy_literals_names_and_verbose(self):
        token = 'ghp_' + 'a' * 36
        code = f'const password="hunter2"; fetch(password); localStorage.setItem("{token}", "hunter2"); fetch("/otp%253D123456?password=hunter2");'
        o = inspect(code)
        env = analysis_envelope({'task': {}}, SCAN, b'', o)
        for rendered in [json.dumps(o.to_dict()), format_analysis(env), format_analysis(env, verbose=True)]:
            for secret in ['hunter2', '123456', token]:
                self.assertNotIn(secret, rendered)

    def test_determinism_raw_integrity_and_refs(self):
        result = {'task': {}, 'page': {'url': 'https://e.test/?password=hunter2'}}
        before = deepcopy(result)
        code = f'const p={READ};fetch("/api",{{body:JSON.stringify({{password:p}})}});'
        a, b = inspect(code, result=result), inspect(code, result=result)
        self.assertEqual(a.to_dict(), b.to_dict())
        self.assertEqual(result, before)
        ids = {e.id for e in a.evidence}
        self.assertEqual(len(ids), len(a.evidence))
        for category in ['artifacts', 'scripts', 'sources', 'transforms', 'sinks', 'flows', 'runtime_joins', 'calls']:
            for obj in a.javascript[category]:
                self.assertTrue(set(obj['evidence_refs']) <= ids)
        self.assertEqual(analysis_envelope(result, SCAN, b'', a)['result'], before)

    def test_passive_with_supported_flows(self):
        with contextlib.ExitStack() as guards:
            for target in ['urllib.request.urlopen', 'urllib.request.OpenerDirector.open', 'socket.socket', 'socket.getaddrinfo',
                           'subprocess.Popen', 'subprocess.run', 'builtins.eval', 'builtins.exec', 'builtins.open', 'pathlib.Path.open']:
                guards.enter_context(patch(target, side_effect=AssertionError('passive boundary')))
            o = inspect(f'fetch("https://target.test/api",{{body:{READ}}});', HTML + '<script src="https://target.test/a.js"></script>')
        self.assertEqual(len(sensitive(o)), 1)

    def test_verbose_truncation(self):
        o = inspect(';'.join(f'fetch("/api/{i}",{{body:{READ}}})' for i in range(12)))
        env = analysis_envelope({'task': {}}, SCAN, b'', o)
        self.assertIn('8 of 12 primary findings shown', format_analysis(env))
        self.assertNotIn('8 of 12 primary findings shown', format_analysis(env, verbose=True))
        self.assertIn('Transforms:', format_analysis(env, verbose=True))

    def test_script_and_total_byte_budgets(self):
        o = inspect(' ' * (frontend.MAX_SCRIPT_BYTES + 1))
        self.assertTrue(o.javascript['truncated'])
        self.assertEqual(o.javascript['scripts'][0]['parser_status'], 'budget_exceeded')
        with patch.object(frontend, 'MAX_TOTAL_BYTES', 50):
            o = inspect('const name="' + 'x' * 51 + '";')
            self.assertTrue(o.javascript['truncated'])

    def test_script_count_and_nesting_budgets(self):
        dom = b'<script>const x=1;</script>' * (frontend.MAX_SCRIPTS + 1)
        o = analyze({'task': {}}, SCAN, dom)
        self.assertEqual(len(o.javascript['scripts']), frontend.MAX_SCRIPTS)
        self.assertEqual(o.javascript['skipped_scripts'], 1)
        o = inspect('(' * 60 + '1' + ')' * 60 + ';')
        self.assertEqual(o.javascript['scripts'][0]['parser_status'], 'budget_exceeded')

    def test_ast_node_and_token_budgets(self):
        for name in ['MAX_AST_NODES', 'MAX_TOKENS']:
            with self.subTest(name=name), patch.object(frontend, name, 5):
                o = inspect('const a=1;const b=2;')
                self.assertEqual(o.javascript['scripts'][0]['parser_status'], 'budget_exceeded')

    def test_flow_budget_withholds_prefix(self):
        with patch('urlscanx.analysis.jsflow.MAX_FLOWS', 1):
            o = inspect(f'fetch("/a",{{body:{READ}}});fetch("/b",{{body:{READ}}});')
        self.assertEqual(o.javascript['flows'], [])
        self.assertEqual(o.javascript['sources'], [])
        self.assertTrue(o.javascript['truncated'])

    def test_transform_budget_withholds_prefix(self):
        with patch('urlscanx.analysis.jsflow.MAX_TRANSFORMS', 2):
            o = inspect(f'const p={READ};const a=p;const b=a;fetch("/api",{{body:b}});')
        self.assertEqual(o.javascript['flows'], [])
        self.assertTrue(o.javascript['truncated'])

    def test_failure_keeps_other_script(self):
        o = analyze({'task': {}, 'page': {'url': 'https://e.test/'}}, SCAN,
                    (HTML + f'<script>fetch("/a",{{body:{READ}}});</script><script>let broken=;</script>').encode())
        self.assertEqual(len(sensitive(o)), 1)
        self.assertEqual([s['parser_status'] for s in o.javascript['scripts']], ['parsed', 'failed'])

    def test_replaced_or_escaped_builtins_are_unresolved(self):
        for code in [f'document.getElementById=unknown;fetch("/api",{{body:{READ}}});',
                     f'const p={READ};fetch=unknown;fetch("/api",{{body:p}});',
                     f'mutate(document);fetch("/api",{{body:{READ}}});',
                     f'const p={READ}; const d={{password:p}};d.reset();fetch("/api",{{body:JSON.stringify(d)}});']:
            with self.subTest(code=code):
                self.assertEqual(sensitive(inspect(code)), [])

    def test_record_budget_and_incomplete_markup(self):
        with patch('urlscanx.analysis.jsflow.MAX_RECORDS', 2):
            o = inspect(f'const p={READ};fetch("/api",{{body:p}});')
            self.assertEqual(o.javascript['flows'], [])
            self.assertTrue(o.javascript['truncated'])
        o = analyze({'task': {}}, SCAN, (HTML + f'<script>fetch("/api",{{body:{READ}}});').encode())
        self.assertEqual(sensitive(o), [])
        self.assertFalse(o.javascript['scripts'][0]['code_analyzed'])

    def test_shadowed_builtin_closure_and_conditional_mutation(self):
        for code in [f'const document=unknown; function f(){{fetch("/api",{{body:{READ}}});}}',
                     f'function outer(document){{function inner(){{fetch("/api",{{body:{READ}}});}}}}',
                     f'let p={READ}; cond ? p="x" : p={READ}; fetch("/api",{{body:p}});',
                     f'let p={READ}; for(let p="x"; unknown;){{fetch("/api",{{body:p}});}}']:
            with self.subTest(code=code):
                self.assertEqual(sensitive(inspect(code)), [])

    def test_sensitive_literal_property_not_displayed_as_target(self):
        for code in ['const d={password:"hunter2"};fetch(d.password);', 'const d={};d.otp="123456";fetch(d.otp);']:
            o = inspect(code)
            self.assertNotIn('hunter2', json.dumps(o.to_dict()))
            self.assertNotIn('123456', json.dumps(o.to_dict()))

    def test_abstract_operation_and_graph_budgets(self):
        for name in ['MAX_OPERATIONS', 'MAX_VALUE_NODES']:
            with self.subTest(name=name), patch('urlscanx.analysis.jsflow.' + name, 0):
                o = inspect(f'const p={READ};const a=p;fetch("/api",{{body:a}});')
                self.assertTrue(o.javascript['truncated'])
                self.assertEqual(o.javascript['flows'], [])

    def test_nested_mutable_alias_not_frozen_into_flow(self):
        o = inspect(f'const a={{password:{READ}}};const b={{nested:a}};a.password="constant";fetch("/api",{{body:JSON.stringify(b)}});')
        self.assertEqual(sensitive(o), [])

    def test_unsupported_foreign_document_body_has_no_dom_link(self):
        r = request(url='https://foreign.test/a.js')
        r['request']['type'] = 'Script'
        r['response']['body'] = f'fetch("https://foreign.test/api",{{body:{READ}}});'
        result = {'task': {}, 'page': {'url': 'https://e.test/'}, 'data': {'requests': [r]}}
        self.assertEqual(sensitive(inspect('', result=result)), [])

    def test_invalid_unicode_archived_source_nonfatal(self):
        o = analyze({'task': {}}, SCAN, archived_scripts=({'body': '\ud800'},))
        self.assertEqual(o.javascript['scripts'][0]['parser_status'], 'failed')
        self.assertEqual(o.javascript['flows'], [])

    def test_mutable_body_alias_is_refreshed_before_sink(self):
        o = inspect(f'const d={{password:{READ}}};const opts={{body:d}};d.password="constant";fetch("/api",opts);')
        self.assertEqual(sensitive(o), [])

    def test_cli_json_and_saved_raw(self):
        dom = (HTML + f'<script>fetch("/otp%253D123456",{{body:{READ}}});</script>').encode()
        result = {'task': {}, 'page': {'url': 'https://e.test/'}, 'raw': 'hunter2'}
        with tempfile.TemporaryDirectory() as root, patch('urlscanx.cli.api_key', return_value='offline'), \
             patch('urlscanx.cli.fetch_result', return_value=result), patch('urlscanx.cli.fetch_asset', return_value=dom), \
             contextlib.redirect_stdout(io.StringIO()) as out, \
             patch('urlscanx.cli.Path', side_effect=lambda p: Path(root) / p):
            self.assertEqual(main([SCAN, '--analyze', '--json', '--save']), 0)
            env = json.loads(out.getvalue())
            self.assertEqual(env['result'], result)
            self.assertIn('javascript', env['analysis'])
            saved = Path(root) / 'urlscanx-output' / SCAN
            self.assertEqual(json.loads((saved / 'result.json').read_text(encoding='utf8')), result)
            self.assertEqual((saved / 'dom.html').read_bytes(), dom)
            self.assertNotIn('123456', (saved / 'analysis.json').read_text(encoding='utf8'))

    def test_network_and_hard_negatives_unchanged(self):
        for n in [4, 5, 6, 7, 8, 9, 10, 11]:
            r, scan, dom = fixture(n)
            before = deepcopy(r)
            a = analyze(r, scan, dom)
            self.assertEqual(a.findings, [])
            self.assertEqual(r, before)
            self.assertEqual(sensitive(a), [])  # CI projections contain no code bodies
            if n == 9:
                p = next(p for p in a.network_patterns if p.kind == 'socket_io_http_polling')
                self.assertEqual(p.request_count, 7)
                self.assertEqual(p.method_counts, {'GET': 4, 'POST': 3})


class PrimaryScriptTests(unittest.TestCase):
    def load(self, number):
        r, scan, dom = fixture(number)
        body = (Path(__file__).parent / 'fixtures' / 'analysis' / 'javascript' / f'F{number:03}.js').read_text(encoding='utf8')
        return analyze(r, scan, dom, archived_scripts=({'body': body, 'document_url': r['page']['url'],
                       'type': 'module' if number == 3 else ''},))

    def test_f001_primary_password_username_json_fetch_path(self):
        o = self.load(1)
        sinks = {s['id']: s for s in o.javascript['sinks']}
        flows = [f for f in sensitive(o) if sinks[f['sink_id']]['target'] and sinks[f['sink_id']]['target'].endswith('/api/collect')]
        self.assertEqual({f['semantic_role'] for f in flows}, {'username', 'password'})
        transforms = {t['id']: t for t in o.javascript['transforms']}
        for flow in flows:
            kinds = [transforms[i]['kind'] for i in flow['transform_ids']]
            self.assertIn('variable_alias', kinds)
            self.assertIn('object_property', kinds)
            self.assertIn('JSON.stringify', kinds)
            self.assertEqual(sinks[flow['sink_id']]['method'], 'POST')
            self.assertEqual(sinks[flow['sink_id']]['runtime_endpoint'], 'not_observed')
            self.assertEqual(flow['state'], 'static_flow_inferred')
        self.assertTrue(o.findings)
        self.assertTrue(all(f['flow_execution']=='not_established' for f in o.findings))

    def test_f003_primary_create_and_otp_config_unresolved(self):
        o = self.load(3)
        sinks = {s['id']: s for s in o.javascript['sinks']}
        flows = sensitive(o)
        create = [f for f in flows if 'PaymentConfig.apiEndpoints.createPayment' in sinks[f['sink_id']]['target_expression']['references']]
        webhook = [f for f in flows if 'PaymentConfig.apiEndpoints.webhook' in sinks[f['sink_id']]['target_expression']['references']]
        self.assertEqual({f['semantic_role'] for f in create}, {'email', 'password'})
        self.assertEqual({f['semantic_role'] for f in webhook}, {'otp_candidate'})
        self.assertTrue(all('apiUrl' in sinks[f['sink_id']]['target_expression']['references'] for f in create + webhook))
        self.assertTrue(all(sinks[f['sink_id']]['target_resolution'] == 'unresolved' for f in create + webhook))
        self.assertTrue(all(sinks[f['sink_id']]['payload_relationship'] == 'unresolved' for f in flows))
        otp_sink = sinks[webhook[0]['sink_id']]
        payment = next(f for f in otp_sink['payload']['fields'] if f['name'] == 'payment_id')
        self.assertTrue(payment['unresolved'])
        self.assertEqual(payment['source_refs'], [])
        self.assertTrue(o.findings)
        self.assertTrue(all(f['flow_execution']=='not_established' for f in o.findings))


if __name__ == '__main__':
    unittest.main()
