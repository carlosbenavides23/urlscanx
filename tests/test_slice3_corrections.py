"""Known context rejection, preserved load identity and exact inline coordinates."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from urlscanx.analysis import analyze
from urlscanx.analysis.javascript import Scripts
from urlscanx.analysis.render import javascript_lines
from urlscanx.analysis import correlation as joins
from test_javascript import HTML, SCAN, inspect, sensitive
import test_static_paths as previous
from test_static_paths import FLOW, observed, runtime, script_load

URL = 'https://e.test/a.js'
DOC = 'https://e.test/page/index.html'
INITIATOR = {'type':'script', 'stack':{'callFrames':[{'url':URL}]}}


def preserved(post, loads=None, archive=False, dom=HTML):
    loads = loads if loads is not None else [script_load(body=None if archive else FLOW)]
    result = runtime(*loads,*post)
    before = deepcopy(result)
    bodies = [{'url':URL,'document_url':DOC,'body':FLOW}] if archive else []
    output = analyze(result,SCAN,dom.encode(),archived_scripts=bodies)
    assert before == result
    previous.PathTests().integrity(output)
    return output


class ContextMismatchTests(unittest.TestCase):
    def test_exact_frame_document_and_initiator(self):
        o = preserved([observed(initiator=INITIATOR)])
        c = o.javascript['runtime_correlations'][0]
        self.assertEqual(c['state'],'endpoint_method_initiator_match')
        self.assertEqual(c['requests'][0]['context_relationship'],'matched')
        self.assertEqual(c['selected_request_refs'],['/data/requests/1'])
        self.assertEqual(c['flow_execution'],'not_established')
        self.assertEqual(c['payload_relationship'],'unresolved')

    def test_absent_context_is_weak_not_mismatch(self):
        post = observed()
        post['request'].pop('frameId')
        post['request'].pop('documentURL')
        o = preserved([post])
        c = o.javascript['runtime_correlations'][0]
        self.assertEqual(c['state'],'endpoint_method_match')
        self.assertEqual(c['requests'][0]['context_relationship'],'unresolved')
        self.assertEqual(c['reasons'],[])

    def test_document_mismatch_without_initiator_rejected(self):
        o = preserved([observed(document='https://other.test/page')])
        c = o.javascript['runtime_correlations'][0]
        self.assertEqual(c['state'],'unresolved')
        self.assertEqual(c['selected_request_refs'],[])
        self.assertEqual(c['reasons'],['document_frame_context_mismatch'])
        self.assertEqual(c['compatible_request_count'],1)
        self.assertEqual(c['exact_request_count'],1)

    def test_document_mismatch_with_exact_initiator_rejected(self):
        c = preserved([observed(initiator=INITIATOR,document='https://other.test/page')]).javascript['runtime_correlations'][0]
        self.assertEqual(c['state'],'unresolved')
        self.assertEqual(c['requests'][0]['initiator_relationship'],'context_mismatch')

    def test_frame_mismatch_without_initiator_rejected(self):
        post = observed(); post['request']['frameId'] = 'other-frame'
        c = preserved([post]).javascript['runtime_correlations'][0]
        self.assertEqual(c['state'],'unresolved')
        self.assertEqual(c['selected_request_refs'],[])

    def test_frame_mismatch_with_exact_initiator_rejected(self):
        post = observed(initiator=INITIATOR); post['request']['frameId'] = 'other-frame'
        c = preserved([post]).javascript['runtime_correlations'][0]
        self.assertEqual(c['state'],'unresolved')
        self.assertEqual(c['requests'][0]['initiator_relationship'],'context_mismatch')

    def test_mismatch_plus_unknown_selects_unknown_only(self):
        bad = observed(document='https://other.test/')
        unknown = observed(); unknown['request'].pop('frameId'); unknown['request'].pop('documentURL')
        c = preserved([bad,unknown]).javascript['runtime_correlations'][0]
        self.assertEqual(c['state'],'endpoint_method_match')
        self.assertEqual(c['compatible_request_count'],2)
        self.assertEqual(c['selected_request_refs'],['/data/requests/2'])
        self.assertEqual(c['context_mismatch_request_refs'],['/data/requests/1'])

    def test_all_candidates_mismatch(self):
        c = preserved([observed(document='https://other.test/'),observed(document='https://other.test/')]).javascript['runtime_correlations'][0]
        self.assertEqual(c['state'],'unresolved')
        self.assertEqual(c['selected_request_refs'],[])
        self.assertEqual(len(c['context_mismatch_request_refs']),2)

    def test_normal_renderer_exposes_mismatch(self):
        o = preserved([observed(document='https://other.test/')])
        text = '\n'.join(javascript_lines(o.javascript))
        self.assertIn('runtime correlation: unresolved',text)
        self.assertIn('document/frame context mismatch',text)
        self.assertNotIn('runtime correlation: endpoint_method_match',text)

    def test_verbose_retains_rejected_provenance(self):
        o = preserved([observed(initiator=INITIATOR,document='https://other.test/')])
        text = '\n'.join(javascript_lines(o.javascript,verbose=True))
        self.assertIn('Request /data/requests/1:',text)
        self.assertIn('initiator context_mismatch',text)
        self.assertTrue(o.javascript['runtime_correlations'][0]['requests'][0]['evidence_refs'])

    def test_other_sink_normal_renderer_exposes_mismatch(self):
        load = script_load(body='fetch("https://e.test/api",{method:"POST"});')
        o = preserved([observed(document='https://other.test/')],[load])
        self.assertEqual(sensitive(o),[])
        self.assertIn('runtime correlation: unresolved; document/frame context mismatch','\n'.join(javascript_lines(o.javascript)))

    def test_mismatch_beyond_context_budget_remains_visible(self):
        with patch.object(joins,'MAX_REQUEST_CONTEXTS_PER_SINK',0):
            o = preserved([observed(document='https://other.test/')])
        c = o.javascript['runtime_correlations'][0]
        self.assertEqual(c['state'],'unresolved')
        self.assertEqual(c['context_mismatch_request_count'],1)
        self.assertIn('document/frame context mismatch','\n'.join(javascript_lines(o.javascript)))


class ExternalLoadIdentityTests(unittest.TestCase):
    def test_single_result_load_with_attached_body(self):
        c = preserved([observed(initiator=INITIATOR)]).javascript['runtime_correlations'][0]
        self.assertEqual(c['state'],'endpoint_method_initiator_match')
        self.assertEqual(c['script_load_ref'],'/data/requests/0')

    def test_single_result_load_with_single_archive(self):
        c = preserved([observed(initiator=INITIATOR)],archive=True).javascript['runtime_correlations'][0]
        self.assertEqual(c['state'],'endpoint_method_initiator_match')
        self.assertEqual(c['script_load_ref'],'/data/requests/0')

    def test_two_bodyless_loads_one_archive(self):
        c = preserved([observed(initiator=INITIATOR)],[script_load(),script_load()],archive=True).javascript['runtime_correlations'][0]
        self.assertEqual(c['state'],'endpoint_method_match')
        self.assertEqual(c['requests'][0]['initiator_relationship'],'unresolved')
        self.assertIsNone(c['script_load_ref'])

    def test_body_count_not_proxy_for_load_count(self):
        c = preserved([observed(initiator=INITIATOR)],[script_load(body=FLOW),script_load()]).javascript['runtime_correlations'][0]
        self.assertEqual(c['state'],'endpoint_method_match')

    def test_unknown_frames_do_not_disambiguate(self):
        c = preserved([observed(initiator=INITIATOR)],[script_load(body=FLOW,frame=None),script_load(frame=None)]).javascript['runtime_correlations'][0]
        self.assertEqual(c['state'],'endpoint_method_match')

    def test_exact_source_load_frame_disambiguates(self):
        loads = [script_load(body=FLOW,frame='frame-1'),script_load(body=FLOW,frame='frame-2')]
        o = preserved([observed(initiator=INITIATOR)],loads)
        a,b = o.javascript['runtime_correlations']
        self.assertEqual(a['state'],'endpoint_method_initiator_match')
        self.assertEqual(b['state'],'unresolved')
        self.assertEqual(b['selected_request_refs'],[])

    def test_missing_request_frame_cannot_disambiguate_duplicate_loads(self):
        post = observed(initiator=INITIATOR); post['request'].pop('frameId')
        loads = [script_load(body=FLOW,frame='frame-1'),script_load(body=FLOW,frame='frame-2')]
        o = preserved([post],loads)
        # Each body has exact load identity, but URL-only initiator cannot locate
        # this request in either of the duplicate frames.
        self.assertTrue(all(c['state']!='endpoint_method_initiator_match' for c in o.javascript['runtime_correlations']))

    def test_archive_cannot_choose_between_duplicate_frames(self):
        c = preserved([observed(initiator=INITIATOR)],[script_load(frame='frame-1'),script_load(frame='frame-2')],archive=True).javascript['runtime_correlations'][0]
        self.assertEqual(c['state'],'endpoint_method_match')

    def test_duplicate_load_order_does_not_choose_bodyless_load(self):
        loads = [script_load(frame='frame-1'),script_load(frame='frame-2')]
        for ordered in (loads,list(reversed(loads))):
            c = preserved([observed(initiator=INITIATOR)],ordered,archive=True).javascript['runtime_correlations'][0]
            self.assertEqual(c['state'],'endpoint_method_match')
            self.assertIsNone(c['script_load_ref'])

    def test_duplicate_document_references_prevent_uniqueness(self):
        dom = HTML+'<script src="/a.js"></script><script src="https://e.test/a.js"></script>'
        c = preserved([observed(initiator=INITIATOR)],archive=True,dom=dom).javascript['runtime_correlations'][0]
        self.assertEqual(c['state'],'endpoint_method_match')

    def test_one_document_reference_and_one_load_are_not_double_counted(self):
        c = preserved([observed(initiator=INITIATOR)],archive=True,dom=HTML+'<script src="/a.js"></script>').javascript['runtime_correlations'][0]
        self.assertEqual(c['state'],'endpoint_method_initiator_match')

    def test_archive_body_alone_is_not_a_unique_load(self):
        c = preserved([observed(initiator=INITIATOR)],loads=[],archive=True).javascript['runtime_correlations'][0]
        self.assertEqual(c['state'],'endpoint_method_match')

    def test_unresolved_document_reference_cannot_prove_uniqueness(self):
        dom = HTML+'<base href="https://other.test/"><script src="/a.js"></script>'
        load = script_load(body=FLOW.replace('"/api"','"https://e.test/api"'))
        c = preserved([observed(initiator=INITIATOR)],[load],dom=dom).javascript['runtime_correlations'][0]
        self.assertEqual(c['state'],'endpoint_method_match')


class InlineCoordinatesTests(unittest.TestCase):
    def check_location(self, tag, body, prefix='', line_ending='\n'):
        html = (prefix+tag+body+'</script>').replace('\n',line_ending)
        extractor = Scripts(); extractor.feed(html); extractor.close()
        start = html.index('>')+1
        before = html[:start]
        self.assertEqual(extractor.entries[0]['body_location'],{'line':before.count('\n')+1,'column':len(before.rsplit('\n',1)[-1])})
        o = analyze(runtime(),SCAN,html.encode())
        loc = o.javascript['sinks'][0]['location']
        position = html.index('fetch')
        actual = html[:position]
        self.assertEqual((loc['dom_line'],loc['dom_column']),(actual.count('\n')+1,len(actual.rsplit('\n',1)[-1])))
        event = observed(method='GET',initiator={'type':'script','stack':{'callFrames':[{
            'url':DOC,'lineNumber':loc['dom_line']-1,'columnNumber':loc['dom_column']}]}})
        matched = analyze(runtime(event),SCAN,html.encode())
        c = matched.javascript['runtime_correlations'][0]
        self.assertEqual(c['state'],'endpoint_method_initiator_match')
        return html,loc

    def test_single_line_tag(self):
        self.check_location('<script>','fetch("/api");')

    def test_multiline_tag(self):
        self.check_location('<script\n  type="text/javascript">','\nfetch("/api");\n')

    def test_multiline_attributes_and_body_indentation(self):
        self.check_location('<script\n  nonce="abc"\n  type="text/javascript">','\n\n    fetch("/api");\n',prefix='\n'*9+'   ')

    def test_crlf_tag_and_body(self):
        self.check_location('<script\n  type="text/javascript">','\n    fetch("/api");\n',line_ending='\r\n')

    def test_body_on_tag_closing_line(self):
        self.check_location('<script\n  type="text/javascript">','    fetch("/api");')

    def test_two_multiline_scripts_only_exact_callsite_strengthens(self):
        html = '<script\n type="text/javascript">\nfetch("/api");</script>\n<script\n nonce="abc">\n  fetch("/api");</script>'
        o = analyze(runtime(),SCAN,html.encode())
        loc = o.javascript['sinks'][1]['location']
        event = observed(method='GET',initiator={'type':'script','stack':{'callFrames':[{
            'url':DOC,'lineNumber':loc['dom_line']-1,'columnNumber':loc['dom_column']}]}})
        a,b = analyze(runtime(event),SCAN,html.encode()).javascript['runtime_correlations']
        self.assertEqual(a['state'],'endpoint_method_match')
        self.assertEqual(b['state'],'endpoint_method_initiator_match')

    def test_wrong_or_missing_coordinates_never_strengthen(self):
        html,loc = self.check_location('<script\n type="text/javascript">','\n    fetch("/api");')
        for line,column in ((loc['dom_line'],loc['dom_column']),(loc['dom_line']-1,loc['dom_column']+1),(None,loc['dom_column'])):
            event = observed(method='GET',initiator={'type':'script','stack':{'callFrames':[{
                'url':DOC,'lineNumber':line,'columnNumber':column}]}})
            c = analyze(runtime(event),SCAN,html.encode()).javascript['runtime_correlations'][0]
            self.assertEqual(c['state'],'endpoint_method_match')
