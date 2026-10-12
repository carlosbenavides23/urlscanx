"""Request-payload structure, privacy, bounds and conservative correspondence."""
import contextlib
from copy import deepcopy
import hashlib
import json
import unittest
from unittest.mock import patch

from urlscanx.analysis import analyze, analysis_envelope
from urlscanx.analysis import payloads
from urlscanx.analysis.render import format_analysis
from test_javascript import inspect, READ, SCAN, HTML
from test_static_paths import runtime, observed


MISSING = object()
JSON_FLOW = f'fetch("/api",{{method:"POST",body:JSON.stringify({{password:{READ}}})}});'


def body_request(body=MISSING, media='application/json', **kwargs):
    entry=observed(**kwargs)
    request=entry['request']['request']
    if body is not MISSING: request['postData']=body
    if media is not None: request['headers']={'Content-Type':media}
    return entry


def inspect_body(body=MISSING, media='application/json', code=None, **kwargs):
    result=runtime(body_request(body,media,**kwargs))
    return inspect(code,result=result) if code is not None else analyze(result,SCAN)


def multipart(parts):
    body=''
    for name,value,filename in parts:
        body+='--bounded\r\nContent-Disposition: form-data; name="'+name+'"'
        if filename is not None: body+='; filename="'+filename+'"'
        body+='\r\n\r\n'+value+'\r\n'
    return body+'--bounded--\r\n'


def relations(output):
    return output.javascript['payload_correlations']


class BodyParsingTests(unittest.TestCase):
    def check(self,body,media='application/json',status='parsed'):
        output=inspect_body(body,media)
        payload=output.runtime_payloads[0]
        self.assertEqual(payload['parser_status'],status,payload)
        evidence={e.id for e in output.evidence}
        self.assertTrue(set(payload['evidence_refs'])<=evidence)
        for field in payload['fields']:
            self.assertTrue(set(field['evidence_refs'])<=evidence)
            self.assertEqual(field['value_state'],'present_omitted')
        return payload

    def test_json_object(self):
        p=self.check('{"password":"hunter2","code":"123456","cvv":"123","pan":"4111111111111111"}')
        self.assertEqual([f['semantic_role'] for f in p['fields']],['password','unknown','payment_cvc','payment_pan'])

    def test_nested_json(self):
        p=self.check('{"auth":{"password":"x"}}')
        self.assertEqual([f['path'] for f in p['fields']],['$.auth','$.auth.password'])

    def test_json_arrays(self):
        p=self.check('{"users":[{"password":"x"},{"password":"y"}]}')
        self.assertIn('$.users[0].password',[f['path'] for f in p['fields']])
        self.assertIn('$.users[1].password',[f['path'] for f in p['fields']])

    def test_json_duplicate_keys(self):
        p=self.check('{"password":"a","password":"b"}')
        self.assertEqual(len(p['fields']),2)
        self.assertEqual([f['multiplicity'] for f in p['fields']],[2,2])
        self.assertNotEqual(p['fields'][0]['id'],p['fields'][1]['id'])

    def test_json_duplicate_parent_paths(self):
        p=self.check('{"auth":{"password":"a"},"auth":{"password":"b"}}')
        self.assertEqual([f['multiplicity'] for f in p['fields']],[2,2,2,2])

    def test_json_primitives(self):
        for body,kind in [('true','boolean'),('42','number'),('null','null'),('"hidden"','string')]:
            with self.subTest(kind=kind): self.assertEqual(self.check(body)['fields'][0]['value_type'],kind)

    def test_json_malformed(self):
        p=self.check('{"password":"secret",',status='malformed')
        self.assertEqual(p['fields'],[])
        self.assertEqual(p['body_format'],'json')

    def test_json_nonfinite_invalid(self):
        self.check('{"x":NaN}',status='malformed')

    def test_json_no_sniffing(self):
        self.check('{"password":"x"}',None,'unsupported')

    def test_json_vendor_content_type(self):
        self.assertEqual(self.check('{"x":1}','application/vnd.test+json; charset=utf-8')['body_format'],'json')

    def test_json_byte_budget(self):
        with patch.object(payloads,'MAX_BODY_BYTES',10): self.check('{"password":"hunter2"}',status='truncated')

    def test_json_depth_budget_atomic(self):
        p=self.check('{"password":"x","nested":'+ '['*20+'0'+']'*20+'}',status='truncated')
        self.assertEqual(p['fields'],[])

    def test_json_array_budget_atomic(self):
        with patch.object(payloads,'MAX_ARRAY_ITEMS',1):
            self.assertEqual(self.check('{"password":"x","list":[1,2]}',status='truncated')['fields'],[])

    def test_json_fields_budget_atomic(self):
        with patch.object(payloads,'MAX_FIELDS',1): self.check('{"password":"x","email":"y"}',status='truncated')

    def test_json_parameter_budget(self):
        with patch.object(payloads,'MAX_PARAMETERS',1): self.check('{"a":1,"b":2}',status='truncated')

    def test_total_byte_budget_soft(self):
        result=runtime(body_request('{"a":1}'),body_request('{"b":2}'),body_request(''))
        with patch.object(payloads,'MAX_TOTAL_BODY_BYTES',7): out=analyze(result,SCAN)
        self.assertEqual([p['parser_status'] for p in out.runtime_payloads],['parsed','truncated','parsed'])

    def test_form_urlencoded(self):
        p=self.check('email=a%40b.test&password=hunter2','application/x-www-form-urlencoded')
        self.assertEqual([f['name'] for f in p['fields']],['email','password'])

    def test_form_duplicates(self):
        p=self.check('a=1&a=2','application/x-www-form-urlencoded')
        self.assertEqual([f['multiplicity'] for f in p['fields']],[2,2])

    def test_blank_values_and_bare_parameter(self):
        p=self.check('a=&b','application/x-www-form-urlencoded')
        self.assertEqual([f['value_state'] for f in p['fields']],['present_omitted']*2)

    def test_form_bad_percent_encoding(self):
        for body in ('password=%ZZ','password=%FF','%ZZ=x','a=%1'):
            with self.subTest(body=body): self.check(body,'application/x-www-form-urlencoded','malformed')

    def test_form_parameters_budget(self):
        with patch.object(payloads,'MAX_PARAMETERS',1): self.check('a=1&b=2','application/x-www-form-urlencoded','truncated')

    def test_multipart_simple(self):
        p=self.check(multipart([('password','hunter2',None)]),'multipart/form-data; boundary=bounded')
        self.assertEqual(p['fields'][0]['name'],'password')

    def test_multipart_file_metadata(self):
        p=self.check(multipart([('upload','secret file bytes','hunter2.pdf')]),'multipart/form-data; boundary=bounded')
        self.assertTrue(p['fields'][0]['filename_present'])
        self.assertEqual(p['fields'][0]['filename'],'[omitted]')
        self.assertEqual(p['fields'][0]['value_type'],'file')

    def test_multipart_duplicates(self):
        p=self.check(multipart([('a','1',None),('a','2',None)]),'multipart/form-data; boundary=bounded')
        self.assertEqual([f['multiplicity'] for f in p['fields']],[2,2])

    def test_multipart_parts_budget(self):
        with patch.object(payloads,'MAX_PARTS',1):
            self.check(multipart([('a','1',None),('b','2',None)]),'multipart/form-data; boundary=bounded','truncated')

    def test_multipart_boundary_unavailable(self):
        self.check(multipart([('a','1',None)]),'multipart/form-data','malformed')

    def test_multipart_incomplete(self):
        self.check('--bounded\r\nContent-Disposition: form-data; name="a"\r\n\r\nx','multipart/form-data; boundary=bounded','malformed')

    def test_multipart_no_content_inspection(self):
        p=self.check(multipart([('file','{"password":"hunter2"}','x.json')]),'multipart/form-data; boundary=bounded')
        self.assertEqual([f['path'] for f in p['fields']],['$.file'])

    def test_unsupported_media_type(self):
        self.check('password=hunter2','text/plain','unsupported')

    def test_absent_body(self):
        self.assertEqual(self.check(MISSING,status='not_run')['body_availability'],'unavailable')

    def test_empty_preserved_body(self):
        p=self.check('')
        self.assertEqual((p['body_availability'],p['body_format'],p['fields']),('available','empty',[]))

    def test_binary_body(self):
        self.check('\u0000hidden','application/octet-stream','unsupported')

    def test_encoded_entries_opaque(self):
        entry=body_request();entry['request']['request']['postDataEntries']=[{'bytes':'c2VjcmV0'}]
        out=analyze(runtime(entry),SCAN)
        self.assertEqual(out.runtime_payloads[0]['body_format'],'binary_or_opaque')

    def test_empty_encoded_placeholders_unavailable(self):
        entry=body_request();entry['request']['request']['postDataEntries']=[{'bytes':''}]
        self.assertEqual(analyze(runtime(entry),SCAN).runtime_payloads[0]['body_availability'],'unavailable')

    def test_http_encoding_unsupported(self):
        entry=body_request('{"password":"x"}');entry['request']['request']['headers']['Content-Encoding']='gzip'
        self.assertEqual(analyze(runtime(entry),SCAN).runtime_payloads[0]['parser_status'],'unsupported')

    def test_any_method_body_and_no_query_merge(self):
        p=inspect_body('{"x":1}',method='GET',url='https://e.test/api?password=hidden').runtime_payloads[0]
        self.assertEqual([f['name'] for f in p['fields']],['x'])

    def test_missing_request_inventory(self):
        out=analyze({'task':{}},SCAN)
        self.assertEqual(out.runtime_payloads,[])
        self.assertEqual(out.evidence_coverage['request_bodies'].inspection,'not_run')

    def test_coverage_counts(self):
        out=analyze(runtime(body_request(),body_request(''),body_request('{'),body_request('x','text/plain')),SCAN)
        d=out.evidence_coverage['request_bodies'].details
        self.assertEqual({k:d[k] for k in ('requests_inspected','bodies_available','bodies_unavailable','parsed','malformed','unsupported')},
                         {'requests_inspected':4,'bodies_available':3,'bodies_unavailable':1,'parsed':1,'malformed':1,'unsupported':1})

    def test_name_semantics_weak_and_normalized(self):
        p=self.check('{"verification-code":"x","code":"x","security_code":"x","secret":"x"}')
        self.assertEqual([f['semantic_role'] for f in p['fields']],['otp_candidate','unknown','unknown','unknown'])


    def test_null_body_not_empty(self):
        self.assertEqual(self.check(None,status='not_run')['body_availability'],'unavailable')

    def test_invalid_literal_representation_unsupported(self):
        self.check(42,status='unsupported')

    def test_name_budget_masks_instead_of_retaining(self):
        out=self.check(json.dumps({'x'*100:'hidden'}))
        self.assertEqual(out['fields'][0]['name'],'[omitted]')
        self.assertFalse(out['fields'][0]['structural_matchable'])

    def test_conflicting_content_type_headers(self):
        entry=body_request('{"password":"x"}')
        entry['request']['request']['headers']['content-type']='text/plain'
        self.assertEqual(analyze(runtime(entry),SCAN).runtime_payloads[0]['parser_status'],'unsupported')

    def test_header_count_budget(self):
        entry=body_request('{"password":"x"}')
        entry['request']['request']['headers'].update({str(i):'hidden' for i in range(300)})
        self.assertEqual(analyze(runtime(entry),SCAN).runtime_payloads[0]['parser_status'],'truncated')

    def test_encoded_entry_count_budget(self):
        entry=body_request();entry['request']['request']['postDataEntries']=[{'bytes':''}]*300
        self.assertEqual(analyze(runtime(entry),SCAN).runtime_payloads[0]['parser_status'],'truncated')

    def test_body_parsing_continues_after_malformed(self):
        out=analyze(runtime(body_request('{'),body_request('{"password":"x"}')),SCAN)
        self.assertEqual([p['parser_status'] for p in out.runtime_payloads],['malformed','parsed'])

    def test_json_key_path_exact_and_escaped(self):
        out=self.check('{"pass-word":"x","a.b":"y"}')
        self.assertEqual([f['path'] for f in out['fields']],['$["pass-word"]','$["a.b"]'])

    def test_multipart_duplicate_disposition_rejected(self):
        body=multipart([('password','x',None)]).replace('Content-Disposition:', 'Content-Disposition: form-data; name="other"\r\nContent-Disposition:')
        self.check(body,'multipart/form-data; boundary=bounded','malformed')

    def test_multipart_duplicate_name_rejected(self):
        body=multipart([('password','x',None)]).replace('name="password"','name="password"; name="other"')
        self.check(body,'multipart/form-data; boundary=bounded','malformed')


    def test_total_fields_budget_atomic_and_soft(self):
        result=runtime(body_request('{"a":1}'),body_request('{"b":2,"c":3}'),body_request(''))
        with patch.object(payloads,'MAX_TOTAL_FIELDS',2): out=analyze(result,SCAN)
        self.assertEqual([p['parser_status'] for p in out.runtime_payloads],['parsed','truncated','parsed'])
        self.assertEqual(out.runtime_payloads[1]['fields'],[])

    def test_field_evidence_distinguishes_duplicate_occurrences(self):
        p=self.check('{"password":"a","password":"b"}')
        self.assertNotEqual(p['fields'][0]['evidence_refs'],p['fields'][1]['evidence_refs'])

    def test_body_evidence_result_only_provenance(self):
        result=runtime(body_request('{"password":"x"}'))
        a=analyze(result,SCAN);b=analyze(result,SCAN,HTML.encode())
        ra=[e.id for e in a.evidence if e.layer=='request_payload']
        rb=[e.id for e in b.evidence if e.layer=='request_payload']
        self.assertEqual(ra,rb)

    def test_unsupported_transport_not_automatically_decoded(self):
        p=self.check('eyJwYXNzd29yZCI6Imh1bnRlcjIifQ==','text/plain','unsupported')
        self.assertEqual(p['fields'],[])


    def test_multipart_header_budget_truncated(self):
        body=multipart([('password','x','f'*9000)])
        self.check(body,'multipart/form-data; boundary=bounded','truncated')

    def test_content_type_header_budget_truncated(self):
        self.check('{"password":"x"}','application/json; boundary='+'x'*9000,'truncated')


class PayloadCorrelationTests(unittest.TestCase):
    def check(self,code=JSON_FLOW,body='{"password":"hidden"}',media='application/json',relationship='field_structure_match',**kwargs):
        out=inspect_body(body,media,code,**kwargs)
        records=relations(out)
        self.assertTrue(records,out.javascript['sinks'])
        self.assertEqual(records[-1]['structural_relationship'],relationship,records)
        for record in records:
            self.assertEqual(record['value_relationship'],'unresolved')
            self.assertEqual(record['flow_execution'],'not_established')
            self.assertEqual(record['condition_satisfaction'],'not_established')
            self.assertTrue(set(record['evidence_refs'])<={e.id for e in out.evidence})
        return out

    def test_exact_json_field(self): self.check()

    def test_renamed_field(self):
        out=self.check(JSON_FLOW.replace('password:', 'secret:'),'{"secret":"hidden"}')
        r=relations(out)[0]
        self.assertEqual(r['source_semantic_role'],'password')
        self.assertEqual(r['runtime_semantic_roles'],['unknown'])

    def test_nested_json_field(self):
        code=f'fetch("/api",{{method:"POST",body:JSON.stringify({{auth:{{password:{READ}}}}})}});'
        out=self.check(code,'{"auth":{"password":"hidden"}}')
        self.assertEqual(relations(out)[-1]['static_field_path'],'$.auth.password')

    def test_exact_array_path(self):
        code=f'fetch("/api",{{method:"POST",body:JSON.stringify({{users:[{{password:{READ}}}]}})}});'
        out=self.check(code,'{"users":[{"password":"hidden"}]}')
        self.assertEqual(relations(out)[-1]['static_field_path'],'$.users[0].password')

    def test_context_mismatch(self):
        out=self.check(document='https://other.test/',relationship='unresolved')
        self.assertEqual(out.runtime_payloads[0]['parser_status'],'parsed')
        self.assertIsNone(relations(out)[0]['runtime_request_ref'])

    def test_multiple_requests_not_merged(self):
        out=inspect(JSON_FLOW,result=runtime(body_request('{"password":"x"}'),body_request('{"other":"y"}')))
        self.assertEqual(relations(out)[0]['structural_relationship'],'unresolved')
        self.assertIsNone(relations(out)[0]['runtime_request_ref'])
        self.assertEqual(len(out.runtime_payloads),2)

    def test_conditional_flow(self):
        out=self.check('if(ready){'+JSON_FLOW+'}')
        self.assertEqual(relations(out)[0]['static_path_state'],'conditional')

    def test_conditional_property_producer(self):
        code=f'const p={READ}; const payload={{}};if(ready){{payload.password=p;}}fetch("/api",{{method:"POST",body:JSON.stringify(payload)}});'
        out=self.check(code)
        self.assertEqual(relations(out)[0]['static_path_state'],'conditional')

    def test_unreachable_flow(self):
        out=self.check('if(false){'+JSON_FLOW+'}',relationship='unresolved')
        self.assertEqual(relations(out)[0]['reason'],'unreachable_static_producer')
        self.assertEqual(relations(out)[0]['static_path_state'],'statically_unreachable')

    def test_unreachable_property_not_promoted(self):
        code=f'const p={READ}; const payload={{}};if(false){{payload.password=p;}}fetch("/api",{{method:"POST",body:JSON.stringify(payload)}});'
        out=inspect_body('{"password":"x"}',code=code)
        self.assertEqual(relations(out),[])
        self.assertTrue(any(t['static_path_state']=='statically_unreachable' for t in out.javascript['transforms']))

    def test_competing_static_producers(self):
        code=f'const a={READ};const b=document.getElementById("email").value;const payload={{}};if(ready){{payload.password=a;}}else{{payload.password=b;}}fetch("/api",{{method:"POST",body:JSON.stringify(payload)}});'
        out=self.check(code,relationship='unresolved')
        self.assertEqual(relations(out)[0]['reason'],'competing_static_producers')
        self.assertEqual(relations(out)[0]['possible_static_producers'],2)

    def test_competing_sinks(self):
        self.check(JSON_FLOW+JSON_FLOW,relationship='unresolved')

    def test_no_static_producer(self):
        out=inspect_body('{"password":"hidden"}')
        self.assertEqual(relations(out),[])
        self.assertEqual(out.runtime_payloads[0]['source_relationship'],'unresolved')

    def test_form_urlencoded(self):
        self.check(f'const b=new URLSearchParams();b.set("password",{READ});fetch("/api",{{method:"POST",body:b}});',
                   'password=hidden','application/x-www-form-urlencoded')

    def test_formdata(self):
        self.check(f'const b=new FormData();b.append("password",{READ});fetch("/api",{{method:"POST",body:b}});',
                   multipart([('password','hidden',None)]),'multipart/form-data; boundary=bounded')

    def test_runtime_duplicates_only_name_match(self):
        self.check(body='{"password":"x","password":"y"}',relationship='field_name_match')

    def test_static_form_multiplicity_not_unique(self):
        code=f'const b=new URLSearchParams();b.append("password",{READ});b.append("password",{READ});fetch("/api",{{method:"POST",body:b}});'
        self.check(code,'password=x&password=y','application/x-www-form-urlencoded','unresolved')

    def test_media_type_disagreement(self): self.check(media='text/plain',relationship='unresolved')

    def test_absent_body(self): self.check(body=MISSING,relationship='unresolved')

    def test_endpoint_not_observed(self):
        out=inspect(JSON_FLOW,result=runtime())
        self.assertTrue(relations(out))
        self.assertIsNone(relations(out)[0]['runtime_request_ref'])

    def test_exact_field_names_not_semantic_normalization(self):
        self.check(body='{"pass-word":"x"}',relationship='unresolved')

    def test_helpers_provenance_retained(self):
        code=f'function send(p){{fetch("/api",{{method:"POST",body:JSON.stringify({{password:p}})}});}}send({READ});'
        out=self.check(code)
        flow=next(f for f in out.javascript['flows'] if f['id']==relations(out)[0]['static_flow_id'])
        self.assertTrue(flow['call_edge_refs'])

    def test_correlation_budget_no_partial_selection(self):
        with patch('urlscanx.analysis.payload_correlation.MAX_PAYLOAD_CORRELATIONS',1):
            out=self.check(JSON_FLOW+JSON_FLOW,relationship='unresolved')
            self.assertEqual(relations(out)[0]['reason'],'correlation_budget')


    def test_root_array_static_path(self):
        code=f'fetch("/api",{{method:"POST",body:JSON.stringify([{READ}])}});'
        out=self.check(code,'["hidden"]')
        self.assertEqual(relations(out)[0]['static_field_path'],'$[0]')

    def test_json_stringify_formdata_not_object_entries(self):
        code=f'const fd=new FormData();fd.append("password",{READ});fetch("/api",{{method:"POST",body:JSON.stringify(fd)}});'
        out=inspect_body('{"password":"hidden"}',code=code)
        self.assertEqual(relations(out),[])

    def test_constant_competing_builder_counted(self):
        self.check(JSON_FLOW+'fetch("/api",{method:"POST",body:JSON.stringify({password:"literal"})});',relationship='unresolved')

    def test_candidate_escape_withheld(self):
        code=f'const p={READ};const payload={{}};if(ready){{payload.password=p;}}escape(payload);fetch("/api",{{method:"POST",body:JSON.stringify(payload)}});'
        out=inspect_body('{"password":"x"}',code=code)
        self.assertEqual(relations(out),[])

    def test_nested_mutable_alias_remains_unresolved(self):
        code=f'const a={{password:{READ}}};const b={{auth:a}};a.password="literal";fetch("/api",{{method:"POST",body:JSON.stringify(b)}});'
        out=inspect_body('{"auth":{"password":"hidden"}}',code=code)
        self.assertEqual(relations(out),[])

    def test_callsite_uniquely_selects_one_body(self):
        result=runtime()
        out=inspect(JSON_FLOW,result=result)
        loc=out.javascript['sinks'][0]['location']
        match={'type':'script','stack':{'callFrames':[{'url':'https://e.test/page/index.html','lineNumber':loc['dom_line']-1,'columnNumber':loc['dom_column']}]}}
        result=runtime(body_request('{"password":"x"}',initiator=match),body_request('{"other":"y"}'))
        out=inspect(JSON_FLOW,result=result)
        self.assertEqual(relations(out)[0]['structural_relationship'],'field_structure_match')
        self.assertEqual(relations(out)[0]['runtime_request_ref'],'/data/requests/0')

    def test_script_mismatch_not_positive(self):
        initiator={'type':'script','stack':{'callFrames':[{'url':'https://other.test/a.js','lineNumber':0,'columnNumber':0}]}}
        self.check(initiator=initiator,relationship='unresolved')

    def test_field_token_name_no_positive_match(self):
        code=JSON_FLOW.replace('password:','"ghp_hiddenTokenValue":')
        self.check(code,'{"ghp_hiddenTokenValue":"hidden"}',relationship='unresolved')

    def test_duplicate_candidate_sources_have_unique_ids(self):
        code=f'const p={READ};const payload={{}};if(ready){{payload.a=p;payload.b=p;}}fetch("/api",{{method:"POST",body:JSON.stringify(payload)}});'
        out=inspect_body('{"a":"x","b":"y"}',code=code)
        records=relations(out)
        self.assertEqual(len(records),2)
        self.assertEqual(len({r['id'] for r in records}),2)


    def test_known_external_frame_mismatch_blocks_body(self):
        from test_static_paths import script_load
        entry=body_request('{"password":"x"}')
        entry['request']['frameId']='other-frame'
        result=runtime(script_load(body=JSON_FLOW),entry)
        out=analyze(result,SCAN,(HTML+'<script src="https://e.test/a.js"></script>').encode())
        self.assertTrue(relations(out))
        self.assertEqual(relations(out)[0]['structural_relationship'],'unresolved')
        self.assertIsNone(relations(out)[0]['runtime_request_ref'])

    def test_nested_fresh_literal_alias_mutation_not_stale(self):
        code=f'const b={{auth:{{password:{READ}}}}};const a=b.auth;a.password="literal";fetch("/api",{{method:"POST",body:JSON.stringify(b)}});'
        out=inspect_body('{"auth":{"password":"x"}}',code=code)
        self.assertEqual(relations(out),[])

    def test_declared_function_not_execution_claim(self):
        out=self.check('function neverCalled(){'+JSON_FLOW+'}')
        rendered=format_analysis(analysis_envelope({'task':{}},SCAN,None,out),verbose=True)
        self.assertIn('function declared only; runtime execution: not established',rendered)
        self.assertEqual(relations(out)[0]['flow_execution'],'not_established')


class PayloadPrivacyTests(unittest.TestCase):
    SECRETS=('hunter2','123456','4111111111111111','unknown-body-value','Bearer private-secret','cookie-secret','ghp_hiddenTokenValue','sk-hiddenTokenValue','eyJabc.def.ghi')

    def assert_private(self,out):
        serialized=json.dumps(out.to_dict())
        for verbose in (False,True):
            rendered=format_analysis(analysis_envelope({'task':{}},SCAN,None,out),verbose=verbose)
            for secret in self.SECRETS:
                self.assertNotIn(secret,rendered)
                self.assertNotIn(secret,serialized)
                self.assertNotIn(hashlib.sha256(secret.encode()).hexdigest(),serialized)
            for claim in ('same actor','same campaign','credential_theft','credential_exfiltration','phishing_confirmed','value_proven'):
                self.assertNotIn(claim,rendered)
                self.assertNotIn(claim,serialized)

    def test_json_values_and_headers_omitted(self):
        data=dict(zip(('password','otp','pan','other','authorization','cookie','token1','token2','token3'),self.SECRETS))
        entry=body_request(json.dumps(data));entry['request']['request']['headers'].update(Authorization=self.SECRETS[4],Cookie=self.SECRETS[5])
        self.assert_private(analyze(runtime(entry),SCAN))

    def test_form_values_omitted(self):
        self.assert_private(inspect_body('password=hunter2&otp=123456&cvv=123&pan=4111111111111111&other=unknown-body-value','application/x-www-form-urlencoded'))

    def test_malformed_errors_do_not_echo(self):
        for body in ('{"password":"hunter2",','password=hunter2&otp=%ZZ'):
            self.assert_private(inspect_body(body,'application/json' if body.startswith('{') else 'application/x-www-form-urlencoded'))

    def test_multipart_filename_and_bytes_omitted(self):
        self.assert_private(inspect_body(multipart([('password','hunter2','unknown-body-value')]),'multipart/form-data; boundary=bounded'))

    def test_token_like_field_names_omitted(self):
        out=inspect_body('{"ghp_hiddenTokenValue":"hunter2","sk-hiddenTokenValue":"123456","eyJabc.def.ghi":"unknown-body-value"}')
        self.assert_private(out)
        self.assertTrue(all(not f['structural_matchable'] for f in out.runtime_payloads[0]['fields']))

    def test_identifiers_do_not_depend_on_values(self):
        a=inspect_body('{"password":"hunter2"}',code=JSON_FLOW)
        b=inspect_body('{"password":"different-password"}',code=JSON_FLOW)
        self.assertEqual(a.runtime_payloads[0]['id'],b.runtime_payloads[0]['id'])
        self.assertEqual(a.runtime_payloads[0]['fields'][0]['id'],b.runtime_payloads[0]['fields'][0]['id'])
        self.assertEqual(relations(a)[0]['id'],relations(b)[0]['id'])

    def test_no_secret_hash_call(self):
        original=hashlib.sha256
        def guarded(value=b'',*args,**kwargs):
            self.assertNotIn(value,[s.encode() for s in (*self.SECRETS,'123')])
            return original(value,*args,**kwargs)
        with patch('hashlib.sha256',side_effect=guarded):
            out=inspect_body('{"password":"hunter2","otp":"123456","cvv":"123","pan":"4111111111111111"}')
        self.assert_private(out)

    def test_raw_result_deep_equal_and_passive(self):
        result=runtime(body_request('{"password":"hunter2"}'));before=deepcopy(result)
        with contextlib.ExitStack() as stack:
            for target in ('urllib.request.urlopen','urllib.request.OpenerDirector.open','socket.socket','socket.getaddrinfo','subprocess.Popen','subprocess.run','builtins.eval','builtins.exec','builtins.open','pathlib.Path.open'):
                stack.enter_context(patch(target,side_effect=AssertionError('passive boundary')))
            out=analyze(result,SCAN)
            envelope=analysis_envelope(result,SCAN,None,out)
        self.assertEqual(result,before)
        self.assertEqual(envelope['result'],before)
        self.assert_private(out)

    def test_renderer_truncation_and_verbose(self):
        out=inspect_body(json.dumps({f'field{i}':'hidden' for i in range(20)}))
        envelope=analysis_envelope({'task':{}},SCAN,None,out)
        normal=format_analysis(envelope);verbose=format_analysis(envelope,verbose=True)
        self.assertNotIn('$.field19',normal)
        self.assertIn('$.field19',verbose)
        self.assertNotIn('hidden',verbose)


    def test_cli_analysis_only_values_omitted_raw_preserved(self):
        import test_analysis_cli as cli_tests
        result=runtime(body_request('{"password":"hunter2","otp":"123456"}'))
        for flags in (['--analyze'],['--analyze','--verbose'],['--analyze','--json']):
            code,out,err,_,_=cli_tests.AnalysisCliTests().invoke(result,HTML.encode(),flags)
            self.assertEqual(code,0,err)
            if '--json' in flags:
                data=json.loads(out)
                self.assertEqual(data['result'],result)
                self.assertNotIn('hunter2',json.dumps(data['analysis']))
                self.assertNotIn('123456',json.dumps(data['analysis']))
            else:
                self.assertNotIn('hunter2',out)
                self.assertNotIn('123456',out)

    def test_legitimate_auth_and_payment_names_no_verdict(self):
        for body in ('{"login":"private","passwd":"hunter2","flowToken":"unknown-body-value","canary":"unknown-body-value","ctx":"unknown-body-value"}',
                     '{"pan":"4111111111111111","cvv":"123"}'):
            out=inspect_body(body)
            self.assertEqual(out.findings,[])
            self.assertEqual(out.javascript['flows'],[])
            self.assert_private(out)

    def test_content_type_with_token_semantics_not_echoed(self):
        out=inspect_body('{"password":"hunter2"}','application/sk-hiddenTokenValue')
        self.assert_private(out)
        self.assertIsNone(out.runtime_payloads[0]['media_type'])


if __name__=='__main__': unittest.main()
