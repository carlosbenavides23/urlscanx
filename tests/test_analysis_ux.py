"""Final presentation contracts; facts come from the existing bounded layers."""
import contextlib
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from urlscanx.analysis import analyze, analysis_envelope, findings, interaction, javascript
from urlscanx.analysis.render import format_analysis, finding_lines, summary_lines, input_lines, truncated_subsystems, OUTPUT_WIDTH
from urlscanx.api import ScanError, fetch_result
from urlscanx.cli import main, save_scan
import test_analysis_cli as cli_helpers
from test_analysis import fixture, SCAN, FIXTURES
from test_findings import example, FLOW, HELPER, READ
from test_interaction import model, ONE, MULTI, MULTI_CODE as STAGE_FLOW
from test_payloads import body_request
from test_static_paths import runtime
from replay_slice5 import guard

GOLDEN = FIXTURES / 'golden'


def preserved_case(number):
    result, scan, dom = fixture(number)
    # Explicit sanitized script projections; never analyst labels or ground truth.
    if number in (1, 3):
        code = (FIXTURES / 'javascript' / f'F{number:03}.js').read_bytes()
        dom += b'<script>' + code + b'</script>'
    return result, scan, dom


def envelope(output, result=None, dom=None):
    return analysis_envelope(result or {'task': {}}, SCAN, dom, output, analyzed_at='fixed-test-time')


def semantic_projection(output):
    """Golden JSON covers meaningful states, not implementation-sized inventories."""
    data = output.to_dict()
    return {'schema_version': '1.0', 'findings': [
        {k: f[k] for k in ('kind', 'source_roles', 'sink', 'static_path_state', 'runtime_support', 'payload_support',
                           'evidence_state', 'flow_execution', 'value_relationship')}
        for f in data['findings']],
        'coverage': {k: {n: c[n] for n in ('availability', 'inspection', 'count')}
                     for k, c in data['evidence_coverage'].items()}}


def json_cases():
    return {'static-only': example(), 'runtime-endpoint': example(body=''),
            'payload-support': example(body='{"secret":"private-value"}'),
            'interaction-support': example(code=HELPER+'send('+READ+');', body='{"secret":"private-value"}'),
            'unavailable': analyze({'task': {}}, SCAN),
            'truncation': example(code=' '.join(f'fetch("/api/{i}",{{body:{READ}}});' for i in range(70)))}


class SummaryTests(unittest.TestCase):
    def test_synthesized_or_unavailable_script_records_are_not_called_preserved(self):
        out = example(html=ONE+'<script src="https://e.test/missing.js"></script>')
        text = format_analysis(envelope(out))
        self.assertIn('2 script records', text)
        self.assertIn('1 composed findings', text)
        self.assertIn('1 stage candidates', text)
        self.assertNotIn('javascript: partial; 2 preserved', text)
        self.assertNotIn('findings: partial; 1 preserved', text)

    def test_unavailable_is_not_zero_observed(self):
        text = '\n'.join(summary_lines(analyze({'task': {}}, SCAN).to_dict()))
        self.assertIn('Runtime request support: unavailable', text)
        self.assertIn('Sensitive static request findings: unavailable', text)
        self.assertNotIn('Runtime-supported findings: 0 observed', text)

    def test_empty_preserved_requests_are_zero_observed(self):
        text = '\n'.join(summary_lines(example().to_dict()))
        self.assertIn('Runtime-supported findings: 0 observed', text)
        self.assertIn('Runtime payload structure support: 0 structurally compatible', text)

    def test_payload_support_is_structural(self):
        text = format_analysis(envelope(example(body='{"secret":"private-value"}')))
        self.assertIn('1 structurally compatible', text)
        self.assertIn('does not establish source value equality', text)
        self.assertNotIn('private-value', text)

    def test_partial_body_coverage_is_explicit(self):
        out = example(body='{"secret":"private-value"}')
        out.evidence_coverage['request_bodies'].inspection = 'partial'
        self.assertIn('body coverage partial', '\n'.join(summary_lines(out.to_dict())))

    def test_summary_counts_findings_not_duplicate_flows(self):
        out = example(code=HELPER+'send('+READ+');send('+READ+');')
        self.assertEqual(len(out.findings), 1)
        self.assertIn('Sensitive static request findings: 1', '\n'.join(summary_lines(out.to_dict())))


class PresentationTests(unittest.TestCase):
    def test_section_order_and_default_inventory_dedup(self):
        text = format_analysis(envelope(example()))
        headings = ('Analysis summary', 'Analyst findings', 'Input / interaction overview',
                    'Request / payload evidence summary', 'Notable static JavaScript evidence',
                    'Runtime observations', 'Coverage / limitations')
        positions = [text.index(h) for h in headings]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn('Supported static flows', text)
        self.assertNotIn('evidence_refs:', text)
        self.assertIn('runtime request: not observed', text)
        self.assertIn('runtime payload structure: unavailable', text)

    def test_width_is_bounded_full_verbose_provenance_remains(self):
        out = example()
        out.findings[0]['sink']['target'] = 'https://e.test/' + 'segment/' * 130
        text = format_analysis(envelope(out), verbose=True)
        self.assertLessEqual(max(map(len, text.splitlines())), OUTPUT_WIDTH)
        compact = ''.join(text.split())
        self.assertIn(out.findings[0]['sink']['target'], compact)
        for ref in out.findings[0]['evidence_refs']:
            self.assertIn(ref, compact)

    def test_no_color_in_plain_piped_or_json_output(self):
        out = example()
        with patch('sys.stdout.isatty', return_value=False):
            for verbose in (False, True): self.assertNotIn('\x1b', format_analysis(envelope(out), verbose=verbose))
        self.assertNotIn('\u001b', json.dumps(out.to_dict()))

    def test_verbose_has_typed_refs_variants_and_coverage(self):
        out = example(body='{"secret":"private-value"}')
        text = format_analysis(envelope(out), verbose=True)
        for term in ('source_refs:', 'static_flow_refs:', 'runtime_correlation_refs:', 'payload_correlation_refs:',
                     'stage_refs:', 'path variant:', 'transforms:', 'limitations:', 'availability=', 'Evidence index'):
            self.assertIn(term, text)

    def test_default_limit_explains_hiding_and_verbose_is_complete(self):
        out = example(code=' '.join(f'fetch("/api/{i}",{{body:{READ}}});' for i in range(12)))
        normal = '\n'.join(finding_lines(out.to_dict()))
        self.assertIn('8 of 12 primary findings shown', normal)
        self.assertIn('Use --verbose to inspect all primary findings', normal)
        verbose = '\n'.join(finding_lines(out.to_dict(), verbose=True))
        for f in out.findings: self.assertIn(f['id'], verbose)

    def test_presentation_order_uses_supported_structure_then_endpoint(self):
        records = [deepcopy(example(body='{"secret":"private-value"}').findings[0]),
                   deepcopy(example(body='').findings[0]), deepcopy(example().findings[0]),
                   deepcopy(example(code='fetch(config.target,{body:'+READ+'});').findings[0])]
        for i, f in enumerate(records): f['sink']['target'] = 'https://e.test/order-' + str(i)
        analysis = example().to_dict(); analysis['findings'] = list(reversed(records))
        text = '\n'.join(finding_lines(analysis))
        positions = [text.index('https://e.test/order-' + str(i)) for i in range(4)]
        self.assertEqual(positions, sorted(positions))

    def test_contradictory_and_dead_evidence_is_separate(self):
        out = example(code='if(false){'+FLOW+'}', body='{"secret":"private-value"}')
        text = format_analysis(envelope(out))
        self.assertIn('Contradictory / unreachable / truncated evidence', text)
        self.assertIn('static path: statically unreachable', text)
        self.assertIn('runtime request: contradictory', text)
        self.assertIn('Sensitive static request findings: 0', text)

    def test_declared_function_and_handler_vs_top_level(self):
        cases = (('function neverCalled(){'+FLOW+'}', 'function declared only'),
                 ('document.getElementById("login").addEventListener("submit",()=>{'+FLOW+'});', 'handler declared only'),
                 (FLOW, 'top-level static code'))
        for code, context in cases:
            with self.subTest(context=context):
                text = format_analysis(envelope(example(code=code)))
                self.assertIn('execution context: '+context, text)
                self.assertIn('flow execution: not established', text)

    def test_stage_candidates_do_not_imply_order(self):
        text = format_analysis(envelope(model('', MULTI)))
        self.assertIn('ordering and runtime interaction not established', text)
        self.assertNotIn('identifier -> password', text.lower())
        out = model(STAGE_FLOW, MULTI)
        self.assertTrue(out.interaction['transitions'])
        self.assertIn('Static transitions:', format_analysis(envelope(out)))
        self.assertIn('ordering and runtime interaction not established', format_analysis(envelope(out)))

    def test_body_unavailable_empty_malformed_and_unsupported_are_distinct(self):
        for body, expected in ((None, 'no preserved requests to inspect'), ('', '1 empty'), ('{broken', '1 malformed')):
            with self.subTest(body=body):
                text = format_analysis(envelope(example(body=body)))
                self.assertIn(expected, text)
        out = model(FLOW, result=runtime(body_request('private-body', media='application/x-custom')))
        self.assertIn('1 unsupported', format_analysis(envelope(out)))
        out = model(FLOW, result=runtime(body_request()))
        self.assertIn('Request bodies: unavailable', format_analysis(envelope(out)))

    def test_all_budget_categories_visible_without_verbose(self):
        out = example()
        out.javascript['interprocedural']['truncated'] = True
        out.javascript['path_analysis']['truncated'] = True
        out.interaction['coverage']['truncated'] = True
        out.evidence_coverage['findings'].details['truncated'] = True
        out.evidence_coverage['request_bodies'].details['truncated'] = 1
        text = format_analysis(envelope(out))
        for term in ('TRUNCATED:', 'findings', 'request bodies', 'JavaScript interprocedural', 'JavaScript path analysis', 'interaction'):
            self.assertIn(term, text)

    def test_body_display_grouping_preserves_structured_records(self):
        out = model(FLOW, result=runtime(body_request('{"secret":"first"}'), body_request('{"secret":"second"}')))
        before = deepcopy(out.to_dict())
        text = format_analysis(envelope(out))
        self.assertIn('2 body records with the same protected URL / format / field structure', text)
        self.assertEqual(out.to_dict(), before)
        self.assertEqual(len(out.runtime_payloads), 2)
        self.assertIn(out.runtime_payloads[-1]['request_ref'], format_analysis(envelope(out), verbose=True))


class StabilityTests(unittest.TestCase):
    def test_full_json_cli_envelope_has_no_generated_clock(self):
        cli = cli_helpers.AnalysisCliTests()
        first = cli.invoke({'task': {}}, None, ['--analyze', '--json'])[1]
        second = cli.invoke({'task': {}}, None, ['--analyze', '--json', '--verbose'])[1]
        self.assertEqual(first, second)
        self.assertIsNone(json.loads(first)['metadata']['analyzed_at'])
        self.assertEqual(envelope(example())['metadata']['analyzed_at'], 'fixed-test-time')

    def test_same_static_id_at_all_runtime_support_levels(self):
        out = [example(body=b) for b in (None, '', '{"secret":"private-value"}')]
        self.assertEqual(len({o.findings[0]['id'] for o in out}), 1)

    def test_corpus_deterministic_json_and_renderer_no_mutation(self):
        for number in range(1, 12):
            result, scan, dom = preserved_case(number); before = deepcopy(result)
            outputs = [analyze(result, scan, dom) for _ in range(2)]
            self.assertEqual(outputs[0].to_dict(), outputs[1].to_dict())
            for verbose in (False, True):
                texts = [format_analysis(analysis_envelope(result, scan, dom, o, analyzed_at='fixed'), verbose=verbose) for o in outputs]
                self.assertEqual(*texts)
            self.assertEqual(result, before)

    def test_renderer_never_reanalyzes_or_performs_io(self):
        out = example(body='{"secret":"private-value"}'); before = deepcopy(out.to_dict())
        env = envelope(out)
        with contextlib.ExitStack() as stack:
            guard(stack)
            stack.enter_context(patch('urlscanx.analysis.analyze', side_effect=AssertionError('analysis repeated')))
            for verbose in (False, True): format_analysis(env, verbose=verbose)
            json.dumps(env)
        self.assertEqual(out.to_dict(), before)

    def test_findings_observer_disabled_preserves_lower_layers(self):
        for number in range(1, 12):
            result, scan, dom = preserved_case(number)
            actual = analyze(result, scan, dom).to_dict()
            with patch('urlscanx.analysis.findings_build', return_value=None): baseline = analyze(result, scan, dom).to_dict()
            for d in (actual, baseline): d.pop('findings'); d['evidence_coverage'].pop('findings', None)
            self.assertEqual(actual, baseline)

    def test_golden_normal_corpus(self):
        for number in (1, 3, 6, 9, 10):
            result, scan, dom = preserved_case(number)
            actual = format_analysis(analysis_envelope(result, scan, dom, analyze(result, scan, dom))) + '\n'
            self.assertEqual(actual, (GOLDEN/f'F{number:03}.txt').read_text(encoding='utf-8'))

    def test_golden_verbose_provenance(self):
        for number in (1, 3):
            result, scan, dom = preserved_case(number)
            actual = format_analysis(analysis_envelope(result, scan, dom, analyze(result, scan, dom)), verbose=True)+'\n'
            self.assertEqual(actual, (GOLDEN/f'F{number:03}-verbose.txt').read_text(encoding='utf-8'))

    def test_golden_json_semantics(self):
        actual = {name: semantic_projection(out) for name, out in json_cases().items()}
        self.assertEqual(actual, json.loads((GOLDEN/'semantics.json').read_text(encoding='utf-8')))

    def test_privacy_and_neutral_hard_negatives(self):
        forbidden = ('steals', 'exfiltrates', 'fake login', 'victim', 'credential theft', 'MFA bypass', 'same actor', 'same campaign')
        for number in range(1, 12):
            result, scan, dom = preserved_case(number)
            out = analyze(result, scan, dom)
            for verbose in (False, True):
                text = format_analysis(analysis_envelope(result, scan, dom, out), verbose=verbose)
                for word in forbidden: self.assertNotIn(word.lower(), text.lower())

    def test_all_derived_views_protect_values_and_low_entropy_hashes(self):
        secrets = ('hunter2', '123456', '4111111111111111', 'ghp_'+'a'*36, 'sk-'+'b'*32, 'private@example.test')
        out = example(body=json.dumps(dict(zip(('password','otp','pan','token','key','email'), secrets))))
        for text in (json.dumps(out.to_dict()), format_analysis(envelope(out)), format_analysis(envelope(out), verbose=True)):
            for secret in secrets:
                self.assertNotIn(secret, text)
                self.assertNotIn(hashlib.sha256(secret.encode()).hexdigest(), text)


class OptionalArtifactTests(unittest.TestCase):
    def test_malformed_dom_degrades_coverage_without_crash(self):
        for dom in (b'\xff',):
            with self.subTest(dom=dom):
                result = {'task': {}, 'data': {'requests': []}}
                with contextlib.ExitStack() as stack:
                    guard(stack); out = analyze(result, SCAN, dom)
                self.assertIsNone(out.dom_inventory)
                self.assertEqual(out.evidence_coverage['dom'].availability, 'invalid')
                text = format_analysis(envelope(out))
                self.assertIn('invalid artifact', text)
                self.assertNotIn('secret-password', text)

    def test_optional_parser_rejection_withholds_both_dom_inventories(self):
        with patch('urlscanx.analysis.MarkupInventory.feed', side_effect=AssertionError('secret-password')), \
             patch('urlscanx.analysis.javascript.Scripts.feed', side_effect=AssertionError('secret-password')):
            out = analyze({'task': {}, 'data': {'requests': []}}, SCAN, b'<![malformed]>')
        self.assertIsNone(out.dom_inventory)
        self.assertEqual(out.evidence_coverage['dom'].availability, 'invalid')
        self.assertNotIn('secret-password', format_analysis(envelope(out), verbose=True))

    def test_bad_optional_scripts_leave_network_usable(self):
        for code in ('const = privateValue;', ' ' * (javascript.MAX_SCRIPT_BYTES+1)):
            with self.subTest(code_length=len(code)):
                out = example(code=code)
                text = format_analysis(envelope(out))
                self.assertTrue(out.evidence_coverage['javascript'].inspection != 'complete')
                self.assertNotIn('privateValue', text)

    def test_missing_external_script_unsupported_type_and_sections(self):
        dom = b'<script src="https://e.test/missing.js"></script><script type="text/unknown">secret</script>'
        out = analyze({'task': {}}, SCAN, dom)
        self.assertEqual(out.findings, [])
        self.assertIn('unavailable', format_analysis(envelope(out)))
        self.assertNotIn('secret', json.dumps(out.to_dict()))

    def test_interaction_and_findings_exhaustion_is_partial(self):
        with patch.object(interaction, 'MAX_STAGE_CONTROLS', 1):
            out = example()
            self.assertTrue(out.interaction['coverage']['truncated'])
            self.assertIn('TRUNCATED', format_analysis(envelope(out)))
        with patch.object(findings, 'MAX_FINDINGS', 0):
            out = example()
            self.assertIn('Synthesis truncated', format_analysis(envelope(out)))

    def test_primary_malformed_json_error_never_echoes_source(self):
        with patch('urlscanx.api._get', return_value=b'{"password":"hunter2" broken'):
            with self.assertRaises(ScanError) as error: fetch_result(SCAN, 'offline')
        self.assertNotIn('hunter2', str(error.exception))

    def test_json_cli_skips_human_renderer(self):
        with patch('urlscanx.cli.format_analysis', side_effect=AssertionError('unneeded renderer')):
            self.assertEqual(cli_helpers.AnalysisCliTests().invoke({'task': {}}, None, ['--analyze', '--json'])[0], 0)

    def test_screenshot_failure_does_not_fail_analysis_save(self):
        with tempfile.TemporaryDirectory() as directory:
            before = os.getcwd(); os.chdir(directory)
            try:
                with patch('urlscanx.cli.api_key', return_value='key'), patch('urlscanx.cli.fetch_result', return_value={'task': {}}), \
                     patch('urlscanx.cli.fetch_asset', side_effect=[None, ScanError('secret-token')]), \
                     contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(main([SCAN, '--analyze', '--save']), 0)
                self.assertIn('screenshot unavailable', err.getvalue())
                self.assertNotIn('secret-token', err.getvalue())
                self.assertTrue((Path('urlscanx-output')/SCAN/'analysis.json').exists())
            finally: os.chdir(before)

    def test_saved_invalid_utf8_dom_preserves_original_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            before = os.getcwd(); os.chdir(directory)
            try:
                target, warnings = save_scan(SCAN, {'task': {}}, '', b'\xffraw-dom', None,
                                             analysis_document={'analysis': {}}, analysis_text='')
                self.assertEqual((target/'dom.html').read_bytes(), b'\xffraw-dom')
                self.assertTrue(any('original bytes saved unchanged' in w for w in warnings))
            finally: os.chdir(before)

    def test_help_describes_preserved_evidence(self):
        with contextlib.redirect_stdout(io.StringIO()) as out, self.assertRaises(SystemExit) as error:
            main(['--help'])
        self.assertEqual(error.exception.code, 0)
        self.assertIn('payload structure', out.getvalue())
        self.assertNotIn('detect phishing', out.getvalue())


class CorrectionPresentationTests(unittest.TestCase):
    def interaction_text(self, prefills=(), navigations=()):
        data = example().to_dict()
        data['interaction']['prefills'] = list(prefills)
        data['interaction']['navigations'] = list(navigations)
        before = deepcopy(data)
        text = '\n'.join(input_lines(data))
        self.assertEqual(data, before)
        return text

    def prefill(self, kind='unresolved', key=None):
        return {'source_kind': kind, 'key_name': key, 'path_state': 'unresolved',
                'execution_context': 'declared'}

    def navigation(self, relation='ordering_unresolved', target=None):
        return {'target': target, 'relation_to_submit': relation, 'target_state': 'unresolved',
                'path_state': 'unresolved', 'execution_context': 'declared', 'deferred': False}

    def test_truncation_categories_unique_ordered_and_readable(self):
        data = example().to_dict()
        for key in ('findings', 'interaction', 'request_bodies', 'javascript'):
            data['evidence_coverage'][key]['details']['truncated'] = True
        data['javascript']['interprocedural']['truncated'] = True
        data['javascript']['path_analysis']['truncated'] = True
        data['javascript']['runtime_correlations'] = [{'requests_truncated': True}]
        data['interaction']['coverage']['truncated'] = True
        expected = ['JavaScript', 'JavaScript interprocedural', 'JavaScript path analysis',
                    'runtime request correlation', 'request bodies', 'interaction', 'findings']
        before = deepcopy(data)
        self.assertEqual(truncated_subsystems(data), expected)
        data['evidence_coverage'] = dict(reversed(list(data['evidence_coverage'].items())))
        self.assertEqual(truncated_subsystems(data), expected)
        self.assertEqual(data, before)

    def test_repeated_unresolved_prefills_grouped(self):
        text = self.interaction_text([self.prefill() for _ in range(3)])
        self.assertEqual(text.count('  Prefill:'), 1)
        self.assertIn('unresolved; 3 records', text)
        self.assertIn('final submitted values unresolved', text)
        self.assertNotIn('more prefill', text)

    def test_repeated_existing_dom_prefills_grouped(self):
        text = self.interaction_text([self.prefill('existing_dom_value') for _ in range(6)])
        self.assertEqual(text.count('  Prefill:'), 1)
        self.assertIn('existing dom value; 6 records', text)

    def test_distinct_prefill_kinds_and_protected_keys_remain_distinct(self):
        for records in ([self.prefill(), self.prefill('existing_dom_value')],
                        [self.prefill('url_query', 'email'), self.prefill('url_query', 'username')]):
            with self.subTest(records=records):
                text = self.interaction_text(records)
                self.assertEqual(text.count('  Prefill:'), 2)
                self.assertNotIn('2 records', text)

    def test_repeated_unresolved_navigation_grouped(self):
        text = self.interaction_text(navigations=[self.navigation(), self.navigation()])
        self.assertEqual(text.count('  Navigation declared:'), 1)
        self.assertIn('2 static declarations with this protected target representation', text)
        self.assertIn('runtime navigation not established', text)

    def test_protected_navigation_group_does_not_claim_hidden_value_equality(self):
        records = [self.navigation(target='https://e.test/?otp=111111'),
                   self.navigation(target='https://e.test/?otp=222222')]
        text = self.interaction_text(navigations=records)
        self.assertEqual(text.count('  Navigation declared:'), 1)
        self.assertIn('with this protected target representation', text)
        self.assertNotIn('111111', text)
        self.assertNotIn('222222', text)
        self.assertNotIn('same value', text)

    def test_distinct_navigation_relations_and_states_remain_distinct(self):
        first = self.navigation()
        for key, value in [('relation_to_submit', 'static_after_request'), ('path_state', 'statically_unreachable'),
                           ('target', 'https://e.test/other'), ('deferred', True)]:
            second = deepcopy(first); second[key] = value
            with self.subTest(key=key):
                text = self.interaction_text(navigations=[first, second])
                self.assertEqual(text.count('  Navigation declared:'), 2)
                self.assertNotIn('2 static declarations', text)

    def test_verbose_individual_refs_and_envelope_unchanged(self):
        html = '<form>' + ''.join(f'<input id="field{i}" value="private-value">' for i in range(6)) + '</form>'
        out = model('location.href=config.one;location.href=config.two;', html)
        document = envelope(out)
        before = deepcopy(document)
        self.assertEqual(len(out.interaction['prefills']), 6)
        self.assertEqual(len(out.interaction['navigations']), 2)
        normal = format_analysis(document)
        verbose = format_analysis(document, verbose=True)
        self.assertIn('6 records', normal)
        for category in ('prefills', 'navigations'):
            for record in out.interaction[category]:
                self.assertIn(record['id'], ''.join(verbose.split()))
                for ref in record['evidence_refs']:
                    self.assertIn(ref, ''.join(verbose.split()))
        self.assertEqual(document, before)
        self.assertEqual(out.to_dict(), document['analysis'])

    def test_primary_limit_and_excluded_numbering_are_separate(self):
        out = example(code=' '.join(f'fetch("/api/{i}",{{body:{READ}}});' for i in range(12)))
        excluded = deepcopy(out.findings[0])
        excluded['id'] = 'excluded-test-finding'
        excluded['static_path_state'] = 'statically_unreachable'
        out.findings.append(excluded)
        document = envelope(out); before = deepcopy(document)
        normal = '\n'.join(finding_lines(document['analysis']))
        heading = 'Contradictory / unreachable / truncated evidence'
        self.assertIn('8 of 12 primary findings shown', normal)
        self.assertLess(normal.index('8 of 12 primary findings shown'), normal.index(heading))
        separate = normal.split(heading)[1]
        self.assertIn('  - password-semantic input: static request flow', separate)
        self.assertNotRegex(separate, r'(?m)^  \d+\.')
        verbose = '\n'.join(finding_lines(document['analysis'], verbose=True))
        for finding in out.findings:
            self.assertIn('ID: ' + finding['id'], verbose)
        self.assertEqual(document, before)

    def test_preserved_fixtures_render_without_mutating_any_facts(self):
        for number in (1, 3, 10):
            result, scan, dom = preserved_case(number)
            out = analyze(result, scan, dom)
            document = analysis_envelope(result, scan, dom, out)
            before = deepcopy(document)
            for verbose in (False, True):
                self.assertEqual(format_analysis(document, verbose=verbose), format_analysis(document, verbose=verbose))
            self.assertEqual(document, before)
            self.assertEqual(out.to_dict(), document['analysis'])
            if number == 10:
                self.assertLessEqual(truncated_subsystems(out.to_dict()).count('interaction'), 1)
