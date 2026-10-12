"""Slice 2 corrections: explicit global shadows and isolated graph budgets."""
import unittest
from unittest.mock import patch
from urlscanx.analysis import analyze
from urlscanx.analysis import interprocedural as engine
from test_javascript import inspect, READ, HTML, SCAN, sensitive
import test_interprocedural as support

DIRECT = f'const p={READ};fetch("/api",{{body:p}});'


class GlobalShadowTests(unittest.TestCase):
    def scripts(self, *scripts):
        return analyze({'page':{'url':'https://e.test/'}},SCAN,(HTML+''.join(scripts)).encode())

    def test_cross_script_global_assignments(self):
        cases = [('fetch','customFetch',DIRECT,'sinks'),
                 ('document','fakeDocument',DIRECT,'sources'),
                 ('XMLHttpRequest','CustomXHR',f'const x=new XMLHttpRequest();x.open("POST","/api");x.send({READ});','sinks'),
                 ('navigator','fakeNavigator',f'navigator.sendBeacon("/api",{READ});','sinks'),
                 ('location','fakeLocation',f'location.assign({READ});','sinks')]
        for name,value,code,category in cases:
            with self.subTest(global_name=name):
                o=self.scripts(f'<script>{name}={value};</script>',f'<script>{code}</script>')
                self.assertEqual(o.javascript[category],[])
                self.assertEqual(sensitive(o),[])

    def test_same_script_explicit_global_alias_writes(self):
        for alias in ('window','globalThis','self'):
            with self.subTest(alias=alias):
                o=inspect(f'{alias}.fetch=customFetch;'+DIRECT)
                self.assertTrue(o.javascript['sources'])
                self.assertEqual(o.javascript['sinks'],[])
                self.assertEqual(sensitive(o),[])

    def test_cross_script_global_alias_writes(self):
        for alias in ('window','globalThis','self'):
            o=self.scripts(f'<script>{alias}.fetch=customFetch;</script>',f'<script>{DIRECT}</script>')
            self.assertEqual(o.javascript['sinks'],[])

    def test_repeated_window_property_writes(self):
        o=inspect('window.fetch=customFetch;window.document=fakeDocument;'+DIRECT)
        self.assertEqual(o.javascript['sources'],[])
        self.assertEqual(o.javascript['sinks'],[])
        for write in ('location=fakeLocation;', 'window.location=fakeLocation;'):
            o=inspect(write+'fetch("/api",{body:window.location.href});')
            self.assertEqual(o.javascript['sources'],[])
            o=self.scripts('<script>'+write+'</script>','<script>fetch("/api",{body:window.location.href});</script>')
            self.assertEqual(o.javascript['sources'],[])

    def test_shadowed_global_alias_is_not_canonical(self):
        for alias in ('window','globalThis','self'):
            o=inspect(f'const {alias}={{}};{alias}.fetch=customFetch;'+DIRECT)
            self.assertEqual(len(sensitive(o)),1)

    def test_top_level_block_var_global_shadow(self):
        for declaration in ('{var fetch=customFetch;}', 'if(condition){var fetch=customFetch;}'):
            o=inspect(declaration+DIRECT)
            self.assertEqual(o.javascript['sinks'],[])
            o=self.scripts('<script>'+declaration+'</script>',f'<script>{DIRECT}</script>')
            self.assertEqual(o.javascript['sinks'],[])

    def test_block_lexical_shadows_do_not_leak(self):
        for kind in ('let','const'):
            o=inspect('{'+kind+' fetch=customFetch;}'+DIRECT)
            self.assertEqual(len(sensitive(o)),1)
            o=self.scripts('<script>{'+kind+' fetch=customFetch;}</script>',f'<script>{DIRECT}</script>')
            self.assertEqual(len(sensitive(o)),1)

    def test_block_lexical_assignment_does_not_leak(self):
        o=inspect('{let fetch;fetch=customFetch;}'+DIRECT)
        self.assertEqual(len(sensitive(o)),1)

    def test_module_local_shadow_does_not_leak(self):
        o=self.scripts('<script type="module">const fetch=customFetch;</script>',f'<script>{DIRECT}</script>')
        self.assertEqual(len(sensitive(o)),1)

    def test_declared_function_assignment_not_global_execution(self):
        o=self.scripts('<script>function never(){fetch=customFetch;}</script>',f'<script>{DIRECT}</script>')
        self.assertEqual(len(sensitive(o)),1)

    def test_classic_block_function_availability_conservative(self):
        o=inspect('if(condition){function fetch(x){}}'+DIRECT)
        self.assertEqual(o.javascript['sinks'],[])

    def test_order_not_inferred_from_archive_listing(self):
        o=analyze({'page':{'url':'https://e.test/'}},SCAN,HTML.encode(),archived_scripts=(
          {'body':'fetch=customFetch;','document_url':'https://e.test/'},
          {'body':DIRECT,'document_url':'https://e.test/'}))
        self.assertEqual(len(sensitive(o)),1)
        # Independent scope analysis; no cross-artifact execution order claim.
        self.assertEqual(o.javascript['sinks'][0]['runtime_endpoint'],'not_observed')


class BudgetIsolationTests(unittest.TestCase):
    def check(self,o):
        self.assertTrue(o.javascript['interprocedural']['truncated'])
        self.assertTrue(o.javascript['interprocedural']['reasons'])
        self.assertEqual(len(sensitive(o)),1)
        self.assertEqual(sensitive(o)[0]['support_scope'],'intraprocedural')
        self.assertTrue(all(s['parser_status']=='parsed' for s in o.javascript['scripts']))
        self.assertTrue(all(s['intraprocedural_analysis']=='complete' for s in o.javascript['scripts']))
        support.InterproceduralTests().integrity(o)

    def test_noisy_calls_before_direct_flow(self):
        o=inspect('foo();'*(engine.MAX_CALL_EDGES+20)+DIRECT)
        self.check(o)
        self.assertEqual(len(o.javascript['call_edges']),engine.MAX_CALL_EDGES)

    def test_noisy_script_does_not_poison_later_script(self):
        dom=HTML+'<script>'+'foo();'*(engine.MAX_CALL_EDGES+20)+'</script><script>'+DIRECT+'</script>'
        o=analyze({'page':{'url':'https://e.test/'}},SCAN,dom.encode())
        self.check(o)

    def test_each_soft_budget_preserves_direct_flow(self):
        for budget in ('MAX_CALL_EDGES','MAX_INVOCATIONS','MAX_ARGUMENT_MAPPINGS','MAX_RETURNS','MAX_CROSS_STEPS'):
            with self.subTest(budget=budget),patch.object(engine,budget,0):
                o=inspect(f'function helper(x){{return x}}helper({READ});'+DIRECT)
                self.check(o)
                self.assertFalse(any(e['call_resolution']=='resolved' for e in o.javascript['call_edges']))

    def test_partial_parameter_mapping_withheld(self):
        with patch.object(engine,'MAX_ARGUMENT_MAPPINGS',1):
            o=inspect(f'function helper(a,b){{fetch("/helper",{{body:a}})}}helper({READ},{READ});'+DIRECT)
        self.check(o)
        self.assertFalse(any(e['propagation']=='supported' for e in o.javascript['call_edges']))

    def test_prior_complete_helper_flow_retained(self):
        with patch.object(engine,'MAX_INVOCATIONS',1):
            o=inspect(f'function helper(x){{fetch("/helper",{{body:x}})}}helper({READ});helper({READ});'+DIRECT)
        self.assertEqual(len(sensitive(o)),2)
        self.assertEqual({f['support_scope'] for f in sensitive(o)},{'interprocedural','intraprocedural'})
        self.assertTrue(o.javascript['interprocedural']['truncated'])
        support.InterproceduralTests().integrity(o)

    def test_depth_truncation_preserves_direct_flow(self):
        with patch.object(engine,'MAX_CALL_DEPTH',0):
            o=inspect(f'function helper(x){{fetch("/helper",{{body:x}})}}helper({READ});'+DIRECT)
        self.check(o)

    def test_cycle_truncation_preserves_direct_flow(self):
        o=inspect(f'function helper(x){{return helper(x)}}helper({READ});'+DIRECT)
        self.check(o)

    def test_soft_truncation_does_not_restore_global_builtin(self):
        dom=HTML+'<script>'+'foo();'*(engine.MAX_CALL_EDGES+20)+'fetch=customFetch;</script><script>'+DIRECT+'</script>'
        o=analyze({'page':{'url':'https://e.test/'}},SCAN,dom.encode())
        self.assertTrue(o.javascript['interprocedural']['truncated'])
        self.assertEqual(sensitive(o),[])
        self.assertEqual(o.javascript['sinks'],[])


if __name__=='__main__':
    unittest.main()
