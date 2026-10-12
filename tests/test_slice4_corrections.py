"""Slice 4 correction: serialization uncertainty and body coverage semantics."""
import json
import contextlib
from unittest.mock import patch
import unittest
from copy import deepcopy

from urlscanx.analysis import analyze, analysis_envelope
from urlscanx.analysis.render import format_analysis, payload_lines
from test_javascript import READ, SCAN, sensitive
import test_payloads as original
from test_static_paths import runtime

PREFIX=f'const p={READ};const payload={{password:p,other:"x"}};'


def inspect_serialization(mutation='',arguments='payload',prefix=PREFIX):
    code=prefix+mutation+f'fetch("/api",{{method:"POST",body:JSON.stringify({arguments})}});'
    return original.inspect_body('{"password":"hunter2","other":"private"}',code=code)


def payload(output):
    return next(s['payload'] for s in output.javascript['sinks'] if s['sink_kind']=='fetch')


class SerializedShapeTests(unittest.TestCase):
    def exact(self,output):
        p=payload(output)
        self.assertEqual(p['serialization_shape'],'exact',p)
        self.assertIn('$.password',[f['path'] for f in p['fields']])
        self.assertTrue(sensitive(output))
        self.assertEqual(original.relations(output)[0]['structural_relationship'],'field_structure_match')
        return output

    def unresolved(self,output,reason=None):
        p=payload(output)
        self.assertEqual(p['serialization_shape'],'unresolved',p)
        self.assertEqual(p['fields'],[])
        if reason: self.assertIn(reason,p['serialization_shape_reasons'])
        self.assertTrue(sensitive(output),output.javascript)
        records=original.relations(output)
        self.assertTrue(records)
        for record in records:
            self.assertEqual(record['structural_relationship'],'unresolved')
            self.assertEqual(record['reason'],'serialization_shape_unresolved')
            self.assertEqual(record['static_field_path_basis'],'input_object')
            self.assertIsNone(record['serialized_field_path'])
            self.assertIsNone(record['runtime_field_path'])
            self.assertEqual(record['runtime_field_refs'],[])
            self.assertEqual(record['value_relationship'],'unresolved')
            self.assertEqual(record['flow_execution'],'not_established')
        self.assertEqual(output.runtime_payloads[0]['parser_status'],'parsed')
        return output

    def test_plain_stringify_exact(self): self.exact(inspect_serialization())

    def test_null_replacer_exact(self): self.exact(inspect_serialization(arguments='payload,null'))

    def test_space_argument_preserves_exact(self): self.exact(inspect_serialization(arguments='payload,null,2'))

    def test_array_replacer_invalidates_serialized_fields(self):
        self.unresolved(inspect_serialization(arguments='payload,["other"]'),'replacer_unresolved')

    def test_function_replacer_invalidates_serialized_fields(self):
        self.unresolved(inspect_serialization('function replacer(k,v){return v;}','payload,replacer'),'replacer_unresolved')

    def test_dynamic_replacer_invalidates_serialized_fields(self):
        self.unresolved(inspect_serialization(arguments='payload,dynamicValue'),'replacer_unresolved')

    def test_unknown_replacer_invalidates_serialized_fields(self):
        self.unresolved(inspect_serialization(arguments='payload,unknown'),'replacer_unresolved')

    def test_regex_replacer_not_mistaken_for_null(self):
        self.unresolved(inspect_serialization(arguments='payload,/other/'),'replacer_unresolved')

    def test_bound_null_not_assumed_no_replacer(self):
        self.unresolved(inspect_serialization('const absent=null;','payload,absent'),'replacer_unresolved')

    def test_replacer_preserves_dataflow_and_input_object_facts(self):
        out=self.unresolved(inspect_serialization(arguments='payload,["other"]'))
        self.assertIn('$.password',[f['path'] for f in payload(out)['object_fields']])
        flow=sensitive(out)[0]
        kinds={t['kind'] for t in out.javascript['transforms'] if t['id'] in flow['transform_ids']}
        self.assertIn('JSON.stringify',kinds)

    def test_tojson_literal_method(self):
        prefix=f'const p={READ};const payload={{password:p,toJSON(){{return {{safe:true}};}}}};'
        self.unresolved(inspect_serialization(prefix=prefix),'toJSON_possible')

    def test_tojson_literal_function_property(self):
        prefix=f'const p={READ};const payload={{password:p,toJSON:function(){{return {{other:"constant"}};}}}};'
        self.unresolved(inspect_serialization(prefix=prefix),'toJSON_possible')

    def test_tojson_literal_getter_not_evaluated(self):
        prefix=f'const p={READ};const payload={{password:p,get toJSON(){{return custom;}}}};'
        self.unresolved(inspect_serialization(prefix=prefix),'toJSON_possible')

    def test_tojson_assigned_function(self):
        self.unresolved(inspect_serialization('payload.toJSON=function(){return {password:"constant"};};'),'toJSON_possible')

    def test_tojson_assigned_dynamic(self):
        self.unresolved(inspect_serialization('payload["toJSON"]=custom;'),'toJSON_possible')

    def test_unrelated_tojson_does_not_contaminate(self):
        self.exact(inspect_serialization('const other={toJSON(){return {safe:true};}};'))

    def test_tojson_assignment_through_alias(self):
        self.unresolved(inspect_serialization('const alias=payload;alias.toJSON=custom;'),'toJSON_possible')

    def test_nested_tojson_invalidates_whole_serialized_shape(self):
        prefix=f'const p={READ};const payload={{auth:{{password:p,toJSON(){{return {{safe:true}};}}}}}};'
        self.unresolved(inspect_serialization(prefix=prefix),'toJSON_possible')

    def test_conditional_tojson_invalidates_shape(self):
        out=inspect_serialization('if(ready){payload.toJSON=custom;}')
        self.assertEqual(payload(out)['serialization_shape'],'unresolved')
        self.assertEqual(payload(out)['fields'],[])
        self.assertTrue(original.relations(out))
        self.assertTrue(all(c['structural_relationship']=='unresolved' for c in original.relations(out)))

    def test_prototype_property_mutation(self):
        self.unresolved(inspect_serialization('payload.__proto__=custom;'),'prototype_mutation')

    def test_setprototypeof_mutation(self):
        self.unresolved(inspect_serialization('Object.setPrototypeOf(payload,custom);'),'prototype_mutation')

    def test_unrelated_prototype_mutation_does_not_contaminate(self):
        self.exact(inspect_serialization('const other={x:1};Object.setPrototypeOf(other,custom);'))

    def test_static_delete_removes_field(self):
        out=inspect_serialization('delete payload.password;')
        self.assertEqual(payload(out)['serialization_shape'],'exact')
        self.assertEqual([f['path'] for f in payload(out)['fields']],['$.other'])
        self.assertEqual(original.relations(out),[])
        self.assertTrue(any(s['semantic_role']=='password' for s in out.javascript['sources']))

    def test_static_computed_delete_removes_field(self):
        out=inspect_serialization('delete payload["password"];')
        self.assertNotIn('$.password',[f['path'] for f in payload(out)['fields']])
        self.assertEqual(original.relations(out),[])

    def test_delete_through_alias_identity(self):
        out=inspect_serialization('const alias=payload;delete alias.password;')
        self.assertNotIn('$.password',[f['path'] for f in payload(out)['fields']])
        self.assertEqual(original.relations(out),[])

    def test_delete_unrelated_property_preserves_password(self):
        self.exact(inspect_serialization('delete payload.other;'))

    def test_dynamic_delete_invalidates_shape(self):
        self.unresolved(inspect_serialization('delete payload[field];'),'dynamic_or_ambiguous_delete')

    def test_conditional_delete_no_exact_correlation(self):
        out=inspect_serialization('if(flag){delete payload.password;}')
        self.assertEqual(payload(out)['serialization_shape'],'unresolved')
        self.assertEqual(payload(out)['fields'],[])
        self.assertTrue(original.relations(out))
        self.assertTrue(all(c['structural_relationship']=='unresolved' for c in original.relations(out)))

    def test_unrelated_object_delete_does_not_contaminate(self):
        self.exact(inspect_serialization('const other={password:"constant"};delete other[field];'))

    def test_delete_before_reassignment_order(self):
        self.exact(inspect_serialization('delete payload.password;payload.password=p;'))

    def test_dynamic_delete_after_branch_candidate_stays_unresolved(self):
        prefix=f'const p={READ};const payload={{}};if(ready){{payload.password=p;}}'
        out=inspect_serialization('delete payload[field];',prefix=prefix)
        self.assertEqual(payload(out)['serialization_shape'],'unresolved')
        self.assertTrue(all(c['structural_relationship']=='unresolved' for c in original.relations(out)))

    def test_privacy_and_raw_result_preserved(self):
        for mutation,args in (('', 'payload,["other"]'),('payload.toJSON=custom;','payload'),('delete payload[field];','payload')):
            out=inspect_serialization(mutation,args)
            original.PayloadPrivacyTests().assert_private(out)
            for verbose in (False,True):
                rendered=format_analysis(analysis_envelope({'task':{}},SCAN,None,out),verbose=verbose)
                self.assertIn('serialization shape: unresolved',rendered)
                self.assertIn('Serialized field identity: unresolved',rendered)
                self.assertNotIn('Static payload $.password',rendered)


    def test_literal_true_delete_stays_conservative(self):
        out=inspect_serialization('if(true){delete payload.password;}')
        self.assertEqual(payload(out)['serialization_shape'],'unresolved')
        self.assertEqual(payload(out)['fields'],[])
        self.assertTrue(all(c['structural_relationship']=='unresolved' for c in original.relations(out)))

    def test_dead_delete_does_not_contaminate_live_shape(self):
        self.exact(inspect_serialization('if(false){delete payload.password;}'))

    def test_delete_sole_field_leaves_exact_empty_object(self):
        prefix=f'const p={READ};const payload={{password:p}};'
        out=inspect_serialization('delete payload.password;',prefix=prefix)
        self.assertEqual(payload(out)['serialization_shape'],'exact')
        self.assertEqual(payload(out)['fields'],[])
        self.assertEqual(original.relations(out),[])
        self.assertTrue(any(s['semantic_role']=='password' for s in out.javascript['sources']))

    def test_computed_setprototypeof_stays_unresolved(self):
        self.unresolved(inspect_serialization('Object["setPrototypeOf"](payload,custom);'),'prototype_mutation')

    def test_later_mutation_does_not_rewrite_serialized_snapshot(self):
        code=PREFIX+'const body=JSON.stringify(payload);payload.toJSON=custom;fetch("/api",{method:"POST",body});'
        self.exact(original.inspect_body('{"password":"hunter2"}',code=code))

    def test_helper_replacer_retains_flow_provenance(self):
        code=f'function send(p){{fetch("/api",{{method:"POST",body:JSON.stringify({{password:p}},custom)}});}}send({READ});'
        out=self.unresolved(original.inspect_body('{"password":"hunter2"}',code=code))
        self.assertTrue(sensitive(out)[0]['call_edge_refs'])

    def test_correction_paths_passive_and_raw_equal(self):
        # Warm the already configured AST parser before blocking all runtime I/O.
        inspect_serialization()
        for mutation,args in (('','payload,["other"]'),('payload.toJSON=custom;','payload'),('delete payload[field];','payload')):
            result=runtime(original.body_request('{"password":"hunter2"}'))
            before=deepcopy(result)
            code=PREFIX+mutation+f'fetch("/api",{{method:"POST",body:JSON.stringify({args})}});'
            with contextlib.ExitStack() as stack:
                for target in ('urllib.request.urlopen','urllib.request.OpenerDirector.open','socket.socket','socket.getaddrinfo',
                               'subprocess.Popen','subprocess.run','builtins.eval','builtins.exec','builtins.open','pathlib.Path.open'):
                    stack.enter_context(patch(target,side_effect=AssertionError('passive boundary')))
                out=original.inspect(code,result=result)
                envelope=analysis_envelope(result,SCAN,None,out)
            self.assertEqual(result,before)
            self.assertEqual(envelope['result'],before)
            original.PayloadPrivacyTests().assert_private(out)


class BodyCoverageCorrectionTests(unittest.TestCase):
    def coverage(self,entries):
        result=runtime(*entries);before=deepcopy(result)
        output=analyze(result,SCAN)
        self.assertEqual(result,before)
        return output,output.evidence_coverage['request_bodies']

    def test_ten_requests_zero_bodies(self):
        out,cov=self.coverage([original.body_request() for _ in range(10)])
        self.assertEqual((cov.availability,cov.count,cov.inspection),('unavailable',0,'partial'))
        self.assertEqual(cov.details['requests_inspected'],10)
        self.assertEqual(cov.details['bodies_available'],0)
        self.assertEqual(cov.details['bodies_unavailable'],10)
        self.assertEqual(out.evidence_coverage['request_payloads'].availability,'unavailable')

    def test_ten_requests_one_preserved_body(self):
        _,cov=self.coverage([original.body_request() for _ in range(9)]+[original.body_request('{"password":"hidden"}')])
        self.assertEqual((cov.availability,cov.count,cov.inspection),('available',1,'partial'))
        self.assertEqual(cov.details['requests_inspected'],10)
        self.assertEqual(cov.details['bodies_unavailable'],9)

    def test_preserved_empty_body_counts(self):
        out,cov=self.coverage([original.body_request('')])
        self.assertEqual((cov.availability,cov.count,cov.inspection),('available',1,'complete'))
        self.assertEqual(cov.details['empty'],1)
        self.assertEqual(out.runtime_payloads[0]['body_format'],'empty')

    def test_preserved_unsupported_body_counts(self):
        _,cov=self.coverage([original.body_request('opaque','text/plain')])
        self.assertEqual((cov.availability,cov.count),('available',1))
        self.assertEqual(cov.details['unsupported'],1)

    def test_preserved_malformed_and_truncated_count(self):
        _,cov=self.coverage([original.body_request('{'),original.body_request('x'*300000)])
        self.assertEqual((cov.availability,cov.count),('available',2))
        self.assertEqual((cov.details['malformed'],cov.details['truncated']),(1,1))

    def test_all_requests_preserve_parsed_bodies(self):
        _,cov=self.coverage([original.body_request('{}') for _ in range(10)])
        self.assertEqual((cov.availability,cov.count,cov.inspection),('available',10,'complete'))

    def test_zero_requests_uses_available_empty_inventory(self):
        _,cov=self.coverage([])
        self.assertEqual((cov.availability,cov.count,cov.inspection),('available',0,'complete'))

    def test_missing_requests_not_run(self):
        cov=analyze({'task':{}},SCAN).evidence_coverage['request_bodies']
        self.assertEqual((cov.availability,cov.count,cov.inspection),('unavailable',None,'not_run'))

    def test_f001_f003_request_counts_zero_bodies(self):
        for n in (17,7):
            out,cov=self.coverage([original.body_request() for _ in range(n)])
            self.assertEqual((cov.availability,cov.count),('unavailable',0))
            text=format_analysis(analysis_envelope({'task':{}},SCAN,None,out))
            self.assertIn('Request bodies: unavailable; not preserved does not mean empty',text)
            self.assertIn(f'{n} preserved requests',text)

    def test_renderer_prioritizes_parsed_preserved_bodies(self):
        entries=[original.body_request(url=f'https://e.test/absent-{i}') for i in range(6)]
        entries += [original.body_request('opaque','text/plain',url='https://e.test/opaque'),original.body_request('{',url='https://e.test/malformed'),original.body_request('{}',url='https://e.test/parsed')]
        out,_=self.coverage(entries);before=deepcopy(out.to_dict())
        text='\n'.join(payload_lines(out.to_dict()))
        self.assertLess(text.index('https://e.test/parsed'),text.index('https://e.test/malformed'))
        self.assertLess(text.index('https://e.test/malformed'),text.index('https://e.test/opaque'))
        self.assertEqual(out.to_dict(),before)
        verbose='\n'.join(payload_lines(out.to_dict(),verbose=True))
        self.assertLess(verbose.index('https://e.test/absent-0'),verbose.index('https://e.test/parsed'))


    def test_encoded_placeholders_over_budget_do_not_invent_preserved_body(self):
        entry=original.body_request();entry['request']['request']['postDataEntries']=[{'bytes':''}]*300
        _,cov=self.coverage([entry])
        self.assertEqual((cov.availability,cov.count),('unavailable',0))
        self.assertEqual(cov.details['bodies_unavailable'],1)
        self.assertEqual(cov.details['truncated'],1)

    def test_opaque_encoded_entries_count_as_preserved(self):
        entry=original.body_request();entry['request']['request']['postDataEntries']=[{'bytes':'c2VjcmV0'}]
        out,cov=self.coverage([entry])
        self.assertEqual((cov.availability,cov.count),('available',1))
        self.assertEqual(cov.details['unsupported'],1)
        self.assertEqual(out.evidence_coverage['request_payloads'].count,1)


if __name__=='__main__': unittest.main()
