"""Bounded structural UI declarations, observed during the existing AST traversal.

This layer never evaluates paths, JS, CSS, values, responses or browser state.
Private selector/alias syntax is discarded; only sanitized structural facts escape.
"""
from collections import defaultdict
import re
from urllib.parse import urlsplit

from .adapters import label, safe_url
from .javascript import target_url
from .jsflow import FUNCTIONS, key
from .model import EvidenceCoverage
from .paths import PathFlowEngine
from ..display import is_sensitive_name

MAX_STAGES = 32
MAX_STAGE_CONTROLS = 32
MAX_TRANSITIONS = 64
MAX_PREFILLS = 64
MAX_RETRY_PATHS = 32
MAX_NAVIGATIONS = 64
MAX_OBSERVATIONS = 512
MAX_ALIAS_DEPTH = 8
CONTEXT_BUILTINS = frozenset({'location', 'localStorage', 'sessionStorage', 'document', 'window', 'URLSearchParams'})


def position(node):
    return tuple(node.get('range', ())[:2])


def loc_key(location):
    return (location.get('line'), location.get('column'))


def visibility(attrs):
    if 'hidden' in attrs or attrs.get('type', '').lower() == 'hidden':
        return 'hidden_candidate'
    declarations = dict(re.findall(r'(display|visibility)\s*:\s*([^;]+)', attrs.get('style', '').lower()))
    if declarations.get('display', '').strip() == 'none' or declarations.get('visibility', '').strip() == 'hidden':
        return 'hidden_candidate'
    if declarations.get('display', '').strip() in {'block', 'inline', 'inline-block', 'flex', 'grid'} or declarations.get('visibility', '').strip() == 'visible':
        return 'visible_candidate'
    return 'unresolved'


def roles(controls):
    result = set()
    for control in controls:
        role = control['semantic_role']
        if role in {'email', 'username'}: result.add('identifier')
        elif role == 'password': result.add('password')
        elif role == 'otp_candidate': result.add('otp_candidate')
        elif role.startswith('payment_'): result.add('payment')
        elif role in {'person_name', 'phone', 'contact_data', 'company', 'postal_code'}: result.add('personal_information')
        elif role == 'captcha_or_challenge': result.add('verification')
    return sorted(result) or ['generic_form']


def correlation_supports_stage_runtime(correlation):
    """Trust only the final lower-layer selection, never candidate requests."""
    return (correlation.get('state') in {'endpoint_method_match', 'endpoint_method_initiator_match'}
            and correlation.get('relationship') not in {'contradictory_evidence', 'context_mismatch', 'ambiguous_multiple_requests'}
            and correlation.get('static_path_state') not in {'statically_unreachable', 'truncated'}
            and not correlation.get('requests_truncated')
            and len(correlation.get('selected_request_refs', [])) == 1)


def path_relationship(left, right, predicates):
    """Compare existing exact predicate facts; unknown expressions stay unknown."""
    if any(r.get('static_path_state', r.get('path_state')) not in {'conditional', 'unconditional'} for r in (left, right)):
        return 'unresolved'
    a = [predicates[p] for p in left['path_condition_refs']]
    b = [predicates[p] for p in right['path_condition_refs']]
    if any(x.get('binding_ref') and x['binding_ref'] == y.get('binding_ref') and
           x['binding_polarity'] != y['binding_polarity'] for x in a for y in b):
        return 'mutually_exclusive'
    def exact(items):
        return all(p.get('binding_ref') or p['resolution'] != 'unresolved' for p in items)
    if left['path_condition_refs'] == right['path_condition_refs'] or (exact(a) and exact(b)):
        return 'compatible'
    return 'unresolved'


class InteractionInventory:
    def __init__(self, parser, registry, document_url):
        self.parser, self.registry, self.document_url = parser, registry, document_url
        self.output = registry.analysis
        self.raw = []
        self.reasons = []
        self.elements = {loc_key(e['location']): e for e in parser.interaction_elements
                         if e['markup_context'] == 'document_markup'} if parser else {}
        self.ids = {e['attrs']['id']: k for k, e in self.elements.items()
                    if e['attrs'].get('id') and parser.id_counts.get(e['attrs']['id']) == 1}
        self.control_elements = {loc_key(c['location']): c for c in (self.output.dom_inventory or {}).get('controls', [])
                                 if c['markup_context'] == 'document_markup'}
        self.dom_refs = {}
        if parser and parser.interaction_truncated: self.truncate('interaction DOM element budget')

    def truncate(self, reason):
        if reason not in self.reasons: self.reasons.append(reason)

    def element_ref(self, element):
        if element not in self.dom_refs:
            e = self.elements[element]
            ref = self.registry.add('dom', 'dom_markup', 'observed', e['location'],
                                    'Interaction element markup preserved; runtime visibility unresolved',
                                    details={'tag': e['tag'], 'element_id': label(e['attrs'].get('id'))})
            self.dom_refs[element] = ref
        return self.dom_refs[element]

    def add(self, engine, node, fact_kind, **details):
        if engine.parser is None and fact_kind not in {'navigation', 'request', 'counter', 'handler'}:
            return None  # No cross-document selector guessing.
        if len(self.raw) >= MAX_OBSERVATIONS:
            self.truncate('interaction observation budget'); return None
        loc = engine.script['location'] | engine.location(node)
        refs = [ref for p in engine.js['path_conditions'] if p['id'] in engine.predicates for ref in p['evidence_refs']]
        refs += [ref for edge in engine.active_calls for ref in edge['evidence_refs']]
        ref = self.registry.add(engine.artifact, 'static_code', 'declared', loc | {'interaction_kind': fact_kind},
                                'Static interaction declaration; runtime execution not established')
        context = engine.interaction_context
        record = {'id': self.registry.identifier('interaction-' + fact_kind, [ref, context, engine.predicates, details]),
                  'state': 'declared', 'path_state': engine.path_state,
                  'path_condition_refs': list(engine.predicates), 'execution_context': engine.execution_context,
                  'runtime_execution': 'not_established', 'script_ref': engine.script['id'],
                  'scope_ref': engine.script['id'] + ':' + engine.scope,
                  'call_edge_refs': [e['id'] for e in engine.active_calls],
                  'evidence_refs': list(dict.fromkeys([ref, *refs])), **details}
        # Private lane identity binds ordering to one traversal and path. It is
        # removed during finalization, as are element selectors and source syntax.
        record['_lane'] = (record['scope_ref'], tuple(record['call_edge_refs']), tuple(engine.predicates), engine.path_state,
                           context.get('id'), engine.lexical_block(node))
        record['_context'] = context.copy()
        record['_offset'] = node.get('range', [0])[0]
        record['_blocks'] = engine.block_ancestry(node)
        record['_kind'] = fact_kind
        record['_function_ref'] = engine.current_function
        record['_epoch'] = engine.interaction_epoch
        self.raw.append(record)
        return record

    def descendants(self, element):
        return [c for k, c in self.control_elements.items() if k == element or
                element in [loc_key(a) for a in self.elements.get(k, {}).get('ancestors', [])]]

    def finalize(self):
        interaction = self.output.interaction
        callbacks = defaultdict(list)
        for record in self.raw:
            if record.get('_callback_function_ref'):
                callbacks[record['_callback_function_ref']].append(record)
        # A uniquely registered named callback may have been inventoried before
        # its registration. Associate declaration context, never assert invocation.
        for record in self.raw:
            handlers = callbacks.get(record['_function_ref'], [])
            if len(handlers) == 1 and not record['_context'].get('id') and not record['_context'].get('trigger') and not record['call_edge_refs']:
                handler = handlers[0]
                record['_context'] = {'id': handler['id'], 'element': handler.get('element'), 'trigger': handler['trigger'], 'deferred': handler.get('deferred', False)}
                if record.get('element') is None: record['element'] = handler.get('element')
                record['handler_ref'] = handler['id']
                if record['_kind'] == 'navigation':
                    record['deferred'] = handler.get('deferred', False)
                    record['callback_relationship'] = handler['trigger']
                lane = record['_lane']; record['_lane'] = (*lane[:4], handler['id'], lane[-1])
        candidates = {loc_key(f['location']) for f in (self.output.dom_inventory or {}).get('forms', [])
                      if f['markup_context'] == 'document_markup' and loc_key(f['location']) in self.elements}
        candidates.update(k for k, e in self.elements.items() if k not in self.control_elements and
                          visibility(e['attrs']) != 'unresolved' and self.descendants(k))
        candidates.update(r['element'] for r in self.raw if r.get('element') in self.elements and
                          r['_kind'] in {'visibility', 'availability', 'handler', 'class_mutation', 'content_replacement'} and self.descendants(r['element']) and
                          r['element'] not in self.control_elements)
        grouped = defaultdict(list)
        for k, control in self.control_elements.items():
            ancestors = [loc_key(a) for a in self.elements.get(k, {}).get('ancestors', [])] + [k]
            owner = next((a for a in reversed(ancestors) if a in candidates), None)
            if owner is None or control['form_association'] == 'explicit':
                form = next((f for f in (self.output.dom_inventory or {}).get('forms', []) if f['index'] == control['form_index']), None)
                if form and loc_key(form['location']) in candidates: owner = loc_key(form['location'])
            if owner is not None: grouped[owner].append(control)
        stage_map, control_stage = {}, {}
        for element, controls in sorted(grouped.items()):
            if len(interaction['stages']) >= MAX_STAGES:
                self.truncate('stage budget'); break
            if len(controls) > MAX_STAGE_CONTROLS: self.truncate('controls per stage budget')
            shown = controls[:MAX_STAGE_CONTROLS]
            e = self.elements[element]
            refs = [self.element_ref(element), *[ref for c in shown for ref in c['evidence_refs']]]
            refs += [ref for r in self.raw if r.get('element') == element for ref in r['evidence_refs']]
            ancestry = [self.elements[loc_key(a)] for a in e['ancestors'] if loc_key(a) in self.elements] + [e]
            hints = [visibility(a['attrs']) for a in ancestry]
            state = 'hidden_candidate' if 'hidden_candidate' in hints else visibility(e['attrs'])
            form = next((f for f in (self.output.dom_inventory or {}).get('forms', []) if loc_key(f['location']) == element), None)
            submits = (form or {}).get('submit_controls', [])
            if form is None:
                submits = [s for f in (self.output.dom_inventory or {}).get('forms', []) for s in f['submit_controls']
                           if element in [loc_key(a) for a in self.elements.get(loc_key(s['location']), {}).get('ancestors', [])]]
            stage = {'id': self.registry.identifier('stage', [self.element_ref(element), [c['id'] for c in shown]]),
                     'state': 'inferred', 'semantic_roles': roles(shown), 'control_refs': [c['id'] for c in shown],
                     'container_refs': [self.element_ref(element)], 'container_label': label(e['attrs'].get('id')),
                     'submit_control_refs': [s['id'] for s in submits], 'error_ui_refs': [],
                     'static_visibility': state, 'path_state': 'unresolved', 'evidence_refs': list(dict.fromkeys(refs)),
                     'runtime_execution': 'not_established', 'submission_handler_declared': False,
                     'static_flow_refs': [], 'sink_refs': [], 'runtime_correlation_refs': [],
                     'payload_correlation_refs': [], 'runtime_payload_refs': [], 'runtime_support': 'not_established'}
            interaction['stages'].append(stage); stage_map[element] = stage
            for c in shown: control_stage[c['id']] = stage

        def owner(element):
            if element in stage_map: return stage_map[element]
            ancestors = [loc_key(a) for a in self.elements.get(element, {}).get('ancestors', [])]
            return next((stage_map[a] for a in reversed(ancestors) if a in stage_map), None)

        def publish(record, category, limit):
            if len(interaction[category]) >= limit:
                self.truncate(category + ' budget'); return None
            public = {k: v for k, v in record.items() if not k.startswith('_') and k not in {'element', 'source_element'}}
            element = record.get('element')
            stage = owner(element)
            association = 'element_ancestry'
            if stage is None:
                stage = owner(record['_context'].get('element'))
                association = 'handler_context' if stage else 'unresolved'
            public['stage_ref'] = stage['id'] if stage else None
            public['stage_association'] = association
            if element in self.elements:
                dom_ref = self.element_ref(element)
                public['element_ref'] = dom_ref
                public['evidence_refs'] = list(dict.fromkeys([*public['evidence_refs'], dom_ref]))
            interaction[category].append(public)
            return public

        markup_handler_limit = max(0, MAX_OBSERVATIONS - sum(r['_kind'] == 'handler' for r in self.raw))
        for element, e in self.elements.items():
            trigger = 'submit' if 'onsubmit' in e['attrs'] else 'click' if 'onclick' in e['attrs'] else None
            stage = owner(element)
            if trigger is None or stage is None: continue
            if len(interaction['handlers']) >= markup_handler_limit:
                self.truncate('handlers budget'); break
            ref = self.element_ref(element)
            interaction['handlers'].append({'id': self.registry.identifier('markup-handler', [ref, trigger]),
                'state': 'declared', 'kind': 'markup_handler', 'trigger': trigger, 'stage_ref': stage['id'],
                'element_ref': ref, 'path_state': 'unresolved', 'path_condition_refs': [],
                'execution_context': 'markup_handler_declared', 'runtime_execution': 'not_established',
                'callback_body': 'not_analyzed', 'deferred': False, 'evidence_refs': [ref]})
            if trigger == 'submit': stage['submission_handler_declared'] = True

        for form in (self.output.dom_inventory or {}).get('forms', []):
            if form['markup_context'] != 'document_markup' or form['markup_method'] == 'DIALOG': continue
            element = loc_key(form['location'])
            raw_action = self.elements.get(element, {}).get('attrs', {}).get('action')
            if not raw_action: continue
            if len(interaction['navigations']) >= MAX_NAVIGATIONS:
                self.truncate('navigations budget'); break
            stage = owner(element)
            target = form['resolved_markup_target']
            interaction['navigations'].append({'id': self.registry.identifier('markup-navigation', [form['id']]),
                'state': 'declared', 'kind': 'form_markup_target', 'stage_ref': stage['id'] if stage else None,
                'form_ref': form['id'], 'target': target,
                'target_state': 'exact_static_url' if target and urlsplit(raw_action).scheme else 'relative_static_url' if target else 'unresolved',
                'relation_to_stage': 'form_markup', 'relation_to_submit': 'markup_submission_target', 'request_sink_refs': [],
                'path_state': 'unresolved', 'path_condition_refs': [], 'execution_context': 'markup_declared',
                'runtime_execution': 'not_established', 'runtime_navigation': 'not_established', 'deferred': False,
                'network_completion': 'unresolved', 'runtime_support': 'not_established', 'evidence_refs': form['evidence_refs']})

        # Static markup initialization is independent of script availability.
        for element, control in self.control_elements.items():
            if control['value_present_in_markup']:
                if len(interaction['prefills']) >= MAX_PREFILLS:
                    self.truncate('prefills budget'); break
                refs = control['evidence_refs']
                interaction['prefills'].append({'id': self.registry.identifier('prefill', [refs, 'markup_initialization']),
                    'state': 'declared', 'target_control_ref': control['id'],
                    'stage_ref': control_stage.get(control['id'], {}).get('id'), 'source_kind': 'existing_dom_value',
                    'source_ref': refs[0], 'source_control_ref': None, 'key_name': None, 'transform_refs': [],
                    'path_state': 'unresolved', 'path_condition_refs': [], 'execution_context': 'markup_declared',
                    'runtime_execution': 'not_established', 'final_submitted_value_provenance': 'unresolved',
                    'values': '[omitted]', 'evidence_refs': refs})

        lanes = defaultdict(list)
        requests = defaultdict(list)
        valid_sinks = {s['id']: s for s in self.output.javascript['sinks']}
        supported_edges = {edge['id'] for edge in self.output.javascript['call_edges'] if edge['propagation'] == 'supported'}
        for record in self.raw:
            if any(e not in supported_edges for e in record['call_edge_refs']):
                continue  # Withhold interaction facts from incomplete helper invocations.
            kind = record['_kind']; stage = owner(record.get('element'))
            if kind == 'request':
                if record['sink_ref'] not in valid_sinks: continue
                requests[(record['scope_ref'], tuple(record['call_edge_refs']), record['_context'].get('id'))].append(record)
                associated = {c['id']: c for c in self.output.javascript['sources']}
                stages = {control_stage[associated[f['source_id']]['control_id']]['id']
                          for f in self.output.javascript['flows'] if f['sink_id'] == record['sink_ref'] and
                          associated[f['source_id']].get('control_id') in control_stage}
                if stage: stages.add(stage['id'])
                for s in interaction['stages']:
                    if s['id'] not in stages: continue
                    s['sink_refs'].append(record['sink_ref'])
                    s['static_flow_refs'] += [f['id'] for f in self.output.javascript['flows'] if f['sink_id'] == record['sink_ref']]
                    correlations = [c for c in self.output.javascript['runtime_correlations'] if c['sink_id'] == record['sink_ref']]
                    s['runtime_correlation_refs'] += [c['id'] for c in correlations]
                    pc = [c for c in self.output.javascript['payload_correlations'] if c['static_sink_id'] == record['sink_ref']]
                    s['payload_correlation_refs'] += [c['id'] for c in pc]
                    s['runtime_payload_refs'] += [c['runtime_payload_id'] for c in pc if c.get('runtime_payload_id')]
                    selected = {ref for c in correlations for ref in c['selected_request_refs']}
                    s['runtime_payload_refs'] += [p['id'] for p in self.output.runtime_payloads if p['request_ref'] in selected]
                    supported = [c for c in correlations if correlation_supports_stage_runtime(c)]
                    if supported:
                        s['runtime_support'] = 'related_request_only'
                        s.pop('runtime_support_reason', None)
                        s.setdefault('runtime_request_refs', []).extend(ref for c in supported for ref in c['selected_request_refs'])
                        s['evidence_refs'] = list(dict.fromkeys(s['evidence_refs'] + [ref for c in supported for ref in c['evidence_refs']]))
                    elif any(c['state'] != 'none' for c in correlations) and s['runtime_support'] != 'related_request_only':
                        s['runtime_support'] = 'unresolved'
                        s['runtime_support_reason'] = ('lower_layer_correlation_contradictory' if any(c['relationship'] == 'contradictory_evidence' for c in correlations) else 'lower_layer_correlation_unresolved')
                continue
            if kind == 'default_cancel':
                continue  # Consumed below through its exact handler/path evidence.
            if kind == 'handler':
                handler = publish(record, 'handlers', MAX_OBSERVATIONS)
                if stage and handler and record['trigger'] == 'submit': stage['submission_handler_declared'] = True
            elif kind == 'prefill': publish(record, 'prefills', MAX_PREFILLS)
            elif kind == 'counter': publish(record, 'attempt_counters', MAX_OBSERVATIONS)
            elif kind == 'navigation':
                lane = (record['scope_ref'], tuple(record['call_edge_refs']), record['_context'].get('id'))
                predecessors = [r for r in requests[lane] if r['_offset'] < record['_offset'] and
                                r['path_state'] in {'unconditional', 'conditional'} and
                                record['path_condition_refs'][:len(r['path_condition_refs'])] == r['path_condition_refs'] and
                                r['_lane'][-1] in record['_blocks']]
                record['request_sink_refs'] = [r['sink_ref'] for r in predecessors]
                record['relation_to_submit'] = ('static_after_request' if predecessors else 'ordering_unresolved')
                record['relation_to_stage'] = 'handler_context' if stage else 'unresolved'
                record['network_completion'] = 'unresolved'
                record['runtime_navigation'] = 'not_established'
                record['runtime_support'] = 'not_established'
                record['evidence_refs'] += [e for r in predecessors for e in r['evidence_refs']]
                publish(record, 'navigations', MAX_NAVIGATIONS)
            else:
                mutation = publish(record, 'mutations', MAX_OBSERVATIONS)
                if stage and mutation and record.get('error_ui_candidate'):
                    stage['error_ui_refs'].append(mutation['id'])
                if kind in {'visibility', 'availability'}: lanes[record['_lane']].append(record)

        for records in lanes.values():
            for a, b in zip(records, records[1:]):
                if a['_epoch'] != b['_epoch']: continue
                if a.get('direction') == 'hide' and b.get('direction') == 'show': source, destination = a, b
                elif a.get('direction') == 'show' and b.get('direction') == 'hide': source, destination = b, a
                else: continue
                left, right = owner(source['element']), owner(destination['element'])
                # Direction needs exact container/group targets, never arbitrary
                # individual-control mutations inside a mixed-role form.
                if not left or not right or left == right or source['element'] not in stage_map or destination['element'] not in stage_map: continue
                if len(interaction['transitions']) >= MAX_TRANSITIONS:
                    self.truncate('transition budget'); break
                refs = list(dict.fromkeys([*a['evidence_refs'], *b['evidence_refs'], *left['evidence_refs'], *right['evidence_refs']]))
                lane = (a['scope_ref'], tuple(a['call_edge_refs']), a['_context'].get('id'))
                preceding = [r for r in requests[lane] if r['_offset'] < min(a['_offset'], b['_offset']) and
                             r['path_state'] in {'unconditional','conditional'} and
                             a['path_condition_refs'][:len(r['path_condition_refs'])] == r['path_condition_refs'] and
                             r['_lane'][-1] in a['_blocks']]
                interaction['transitions'].append({'id': self.registry.identifier('transition', [a['id'], b['id'], left['id'], right['id']]),
                    'state': 'static_transition_inferred', 'from_stage_ref': left['id'], 'to_stage_ref': right['id'],
                    'trigger': a['_context'].get('trigger', 'unresolved'), 'handler_ref': a['_context'].get('id'),
                    'path_state': a['path_state'], 'path_condition_refs': a['path_condition_refs'],
                    'execution_context': a['execution_context'], 'runtime_execution': 'not_established',
                    'runtime_support': 'not_established', 'mutation_refs': [a['id'], b['id']],
                    'request_sink_refs': [r['sink_ref'] for r in preceding],
                    'relation_to_request': 'static_after_request' if preceding else 'ordering_unresolved',
                    'network_completion': 'unresolved', 'evidence_refs': list(dict.fromkeys(refs + [ref for r in preceding for ref in r['evidence_refs']]))})

        predicates = {p['id']: p for p in self.output.javascript['path_conditions']}
        for handler in interaction['handlers']:
            handler['default_submit_cancelled'] = 'unresolved'
            handler['retry_relationship'] = 'unresolved'
            if handler['trigger'] != 'submit' or not handler['stage_ref']: continue
            if handler['kind'] == 'markup_handler': continue  # Attribute presence does not establish its callback path.
            stage = next(s for s in interaction['stages'] if s['id'] == handler['stage_ref'])
            if not stage['submit_control_refs'] or stage['static_visibility'] == 'hidden_candidate':
                continue  # Retained activation is not supported by this snapshot.
            submit_locations = {loc_key(s['location']) for f in (self.output.dom_inventory or {}).get('forms', [])
                                for s in f['submit_controls'] if s['id'] in stage['submit_control_refs']}
            if submit_locations and all('disabled' in self.elements.get(k, {}).get('attrs', {}) for k in submit_locations):
                continue  # No claim that initially disabled activation is available.
            errors = [m for m in interaction['mutations'] if m.get('handler_ref') == handler['id'] and m.get('error_ui_candidate') and
                      (m.get('direction') == 'show' or m.get('error_content_state') == 'error_presented_candidate')]
            resets = [m for m in interaction['mutations'] if m.get('handler_ref') == handler['id'] and m['kind'] == 'field_reset']
            cancellations = [r for r in self.raw if r['_kind'] == 'default_cancel' and r.get('handler_ref') == handler['id']]
            if any(r['path_state'] == 'unconditional' for r in cancellations):
                handler['default_submit_cancelled'] = 'declared'
            for error in errors:
                cancel = next((r for r in cancellations if r['path_state'] in {'conditional', 'unconditional'} and
                               error['path_condition_refs'][:len(r['path_condition_refs'])] == r['path_condition_refs']), None)
                if cancel is None: continue
                handler['default_submit_cancelled'] = 'declared'
                blockers = [m for m in interaction['mutations'] if m.get('handler_ref') == handler['id'] and
                            m['stage_ref'] == handler['stage_ref'] and
                            (m.get('direction') == 'hide' or m.get('error_content_state') == 'error_cleared' or m['kind'] == 'content_replacement' and not m.get('error_ui_candidate'))]
                blockers += [n for n in interaction['navigations'] if n.get('handler_ref') == handler['id']]
                if any(path_relationship(error, m, predicates) != 'mutually_exclusive' for m in blockers): continue
                if error['path_state'] not in {'conditional', 'unconditional'}: continue
                handler['retry_relationship'] = 'declared'
                if len(interaction['retry_paths']) >= MAX_RETRY_PATHS:
                    self.truncate('retry_paths budget'); break
                refs = list(dict.fromkeys([*handler['evidence_refs'], *error['evidence_refs'], *cancel['evidence_refs']]))
                interaction['retry_paths'].append({'id': self.registry.identifier('retry', [handler['id'], error['id']]),
                    'state': 'retry_path_declared', 'stage_ref': handler['stage_ref'], 'handler_ref': handler['id'],
                    'error_mutation_refs': [error['id']], 'field_reset_refs': [m['id'] for m in resets if m['path_condition_refs'] == error['path_condition_refs']],
                    'path_state': error['path_state'], 'path_condition_refs': error['path_condition_refs'],
                    'execution_context': error['execution_context'], 'runtime_execution': 'not_established',
                    'retry_execution': 'not_established', 'resubmission': 'handler_remains_declared', 'evidence_refs': refs})
        request_contexts = {r['sink_ref']: r['_context'].get('id') for r in self.raw if r['_kind'] == 'request'}
        for stage in interaction['stages']:
            repeated = defaultdict(list)
            for sink_id in dict.fromkeys(stage['sink_refs']):
                sink = valid_sinks[sink_id]
                if not sink.get('call_edge_refs') and not sink['scope_ref'].endswith(':script') and not sink.get('loop_context'):
                    continue  # Declaration inventory plus one call is not two submissions.
                if not any(f['sink_id'] == sink_id for f in self.output.javascript['flows']): continue
                location = sink['location']
                repeated[(sink['script_ref'], location.get('script_line'), location.get('script_column'))].append(sink)
            for sinks in repeated.values():
                sinks = [s for s in sinks if s['static_path_state'] in {'conditional', 'unconditional'}]
                pairs = [path_relationship(a, b, predicates) if request_contexts.get(a['id']) == request_contexts.get(b['id']) else 'unresolved'
                         for i, a in enumerate(sinks) for b in sinks[i+1:]]
                if 'compatible' not in pairs and not any(s.get('loop_context') for s in sinks):
                    if pairs: stage['repeated_submission_relationship'] = 'mutually_exclusive' if all(p == 'mutually_exclusive' for p in pairs) else 'unresolved'
                    continue
                stage['repeated_submission_relationship'] = 'declared'
                if len(interaction['retry_paths']) >= MAX_RETRY_PATHS:
                    self.truncate('retry_paths budget'); break
                refs = list(dict.fromkeys(ref for sink in sinks for ref in sink['evidence_refs']))
                states = {s['static_path_state'] for s in sinks}
                state = next((s for s in ('statically_unreachable','truncated','unresolved','conditional') if s in states),'unconditional')
                interaction['retry_paths'].append({'id': self.registry.identifier('submission-repetition', [stage['id'], [s['id'] for s in sinks]]),
                    'kind': 'static_repeated_submission', 'state': 'repeated_submission_declared', 'stage_ref': stage['id'],
                    'handler_ref': None, 'sink_refs': [s['id'] for s in sinks], 'path_state': state,
                    'path_condition_refs': list(dict.fromkeys(p for s in sinks for p in s['path_condition_refs'])),
                    'execution_context': sinks[0]['execution_context'], 'runtime_execution': 'not_established',
                    'retry_execution': 'not_established', 'iteration_count': 'unresolved', 'evidence_refs': refs})
        for stage in interaction['stages']:
            if 'runtime_request_refs' in stage: stage['runtime_request_refs'] = list(dict.fromkeys(stage['runtime_request_refs']))
            for field in ('sink_refs', 'static_flow_refs', 'runtime_correlation_refs', 'payload_correlation_refs', 'runtime_payload_refs', 'error_ui_refs'):
                stage[field] = list(dict.fromkeys(stage[field]))
        dom_cov = self.output.evidence_coverage['dom']; js_cov = self.output.evidence_coverage['javascript']
        details = {'dom_controls_considered': len(self.control_elements), 'stage_candidates': len(interaction['stages']),
                   'transitions_inferred': len(interaction['transitions']), 'prefills': len(interaction['prefills']),
                   'retry_paths': len(interaction['retry_paths']), 'navigations': len(interaction['navigations']),
                   'truncated': bool(self.reasons), 'reasons': self.reasons,
                   'stage_grouping': 'available' if self.parser else 'unavailable',
                   'transition_analysis': 'available' if any(s['code_analyzed'] for s in self.output.javascript['scripts']) else 'unavailable',
                   'dom_coverage': dom_cov.availability, 'javascript_inspection': js_cov.inspection,
                   'budgets': {'stages': MAX_STAGES, 'controls_per_stage': MAX_STAGE_CONTROLS, 'transitions': MAX_TRANSITIONS,
                               'prefills': MAX_PREFILLS, 'retry_paths': MAX_RETRY_PATHS, 'navigations': MAX_NAVIGATIONS, 'observations': MAX_OBSERVATIONS}}
        interaction['coverage'] = details
        coverage = EvidenceCoverage('available' if self.parser else 'unavailable', 'partial' if self.reasons or not self.parser or js_cov.inspection != 'complete' else 'complete',
                                    len(interaction['stages']), 'Bounded static declarations; snapshot and network do not establish interaction execution', details=details)
        self.output.evidence_coverage['interaction'] = coverage
        self.registry.limit('INTERACTION_STATIC_ONLY', 'interaction', 'DOM order is not stage order; prefill is not submitted value provenance; requests do not establish stage execution.')


class InteractionFlowEngine(PathFlowEngine):
    """Observation hooks only; all transfer/path rules remain in the base engine."""
    def __init__(self, *args, interaction=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.interaction = interaction
        self.interaction_context = {}
        self.handler_contexts = {}
        self.interaction_epoch = 0
        self.node_scopes = {}; self.bindings = {}; self.scope_parent = {}; self.writes = set()
        self.counter_unsafe = set()

    def run(self, tree):
        self.index_bindings(tree)
        return super().run(tree)

    def index_bindings(self, tree):
        def walk(node, scope=(), function_scope=()):
            if not isinstance(node, dict): return
            kind = node.get('type')
            if kind in FUNCTIONS or kind == 'BlockStatement':
                new = position(node)
                self.scope_parent[new] = scope; scope = new
                if kind in FUNCTIONS:
                    function_scope = scope
                    for param in node.get('params', []):
                        if param.get('type') == 'Identifier': self.bindings[(scope, param['name'])] = None
            self.node_scopes[position(node)] = scope
            if kind == 'VariableDeclaration':
                for d in node['declarations']:
                    if d['id'].get('type') == 'Identifier':
                        marker = (function_scope if node.get('kind') == 'var' else scope, d['id']['name'])
                        self.bindings[marker] = d if marker not in self.bindings else None
            if kind in {'AssignmentExpression', 'UpdateExpression'}:
                target = node.get('left') or node.get('argument') or {}
                if target.get('type') == 'Identifier': self.writes.add(target['name'])
                if target.get('type') == 'Identifier' and kind == 'AssignmentExpression' and not (
                        node.get('operator') == '+=' and node.get('right', {}).get('type') == 'Literal' and node['right'].get('value') == 1):
                    self.counter_unsafe.add(target['name'])
            for k, v in node.items():
                if k in {'loc', 'range'}: continue
                for child in v if isinstance(v, list) else [v]:
                    if isinstance(child, dict): walk(child, scope, function_scope)
        walk(tree)

    def lexical_block(self, node): return self.node_scopes.get(position(node), ())

    def block_ancestry(self, node):
        scope = self.lexical_block(node); result = [scope]
        while scope:
            scope = self.scope_parent.get(scope, ())
            result.append(scope)
        return result

    def binding(self, node):
        scope = self.lexical_block(node); name = node.get('name')
        while True:
            marker = (scope, name)
            if marker in self.bindings: return self.bindings[marker]
            if not scope: return None
            scope = self.scope_parent.get(scope, ())

    def resolve(self, node, depth=0):
        """Small DOM alias/provenance syntax, no second dataflow or path evaluator."""
        if not node or depth > MAX_ALIAS_DEPTH: return None
        kind = node.get('type')
        if kind == 'Identifier':
            name = node['name']
            # Read private bindings without invoking another transfer/clone.
            value = next((env[name] for env in reversed(self.env) if name in env), None)
            if value and value.entity and value.entity[0] in {'control', 'form'} and self.parser:
                entries = self.parser.controls if value.entity[0] == 'control' else self.parser.forms
                return ('element', loc_key(entries[value.entity[1]]['location']))
            if name in CONTEXT_BUILTINS and value is not None and value.entity != ('builtin', name):
                return None
            declaration = self.binding(node)
            if declaration and name not in self.writes and declaration['range'][0] < node['range'][0]:
                if is_sensitive_name(name) and (declaration.get('init') or {}).get('type') == 'Literal': return None
                return self.resolve(declaration.get('init'), depth + 1)
            if declaration is None and name in CONTEXT_BUILTINS:
                # Distinguish missing binding from a shadowing parameter/duplicate.
                scope = self.lexical_block(node)
                while True:
                    if (scope, name) in self.bindings: return None
                    if not scope: break
                    scope = self.scope_parent.get(scope, ())
                if name not in self.writes: return ('builtin', name)
            return None
        if kind == 'Literal':
            value = node.get('value')
            return ('literal', value) if value is None or isinstance(value, (str, int, float, bool)) else None
        if kind == 'MemberExpression':
            parent = self.resolve(node.get('object'), depth + 1)
            prop = key(node.get('property', {})) if not node.get('computed') or node.get('property', {}).get('type') == 'Literal' else None
            if parent == ('builtin', 'window') and prop in {'location', 'localStorage', 'sessionStorage', 'document'}: return ('builtin', prop)
            if parent == ('builtin', 'location') and prop in {'search', 'hash', 'href'}: return ('context', prop)
            if parent and parent[0] == 'element' and prop == 'value': return ('dom_value', parent[1])
            if parent and prop: return ('member', parent, prop)
        if kind in {'NewExpression', 'CallExpression'}:
            callee = node.get('callee', {}); args = node.get('arguments', [])
            receiver = self.resolve(callee.get('object'), depth + 1)
            method = key(callee.get('property', {})) if not callee.get('computed') or callee.get('property', {}).get('type') == 'Literal' else None
            first = self.resolve(args[0], depth + 1) if args else None
            if kind == 'NewExpression' and callee.get('name') == 'URLSearchParams' and self.resolve(callee, depth + 1) == ('builtin', 'URLSearchParams'):
                return ('params', first) if first and first[0] == 'context' else None
            if receiver == ('builtin', 'document') and method in {'getElementById', 'querySelector'} and first and first[0] == 'literal' and isinstance(first[1], str):
                if self.parser is None: return None
                name = first[1] if method == 'getElementById' else first[1][1:] if re.fullmatch(r'#[A-Za-z_][\w-]*', first[1]) else None
                if name in self.interaction.ids: return ('element', self.interaction.ids[name])
            if receiver and receiver[0] == 'context' and receiver[1] == 'hash' and method in {'slice', 'substring'} and first == ('literal', 1):
                return receiver
            if receiver and receiver[0] == 'params' and method == 'get' and first and first[0] == 'literal' and isinstance(first[1], str):
                return ('parameter', receiver[1][1], label(first[1]))
            if receiver in (('builtin', 'localStorage'), ('builtin', 'sessionStorage')) and method == 'getItem' and first and first[0] == 'literal' and isinstance(first[1], str):
                return ('storage', receiver[1], label(first[1]))
            if method in {'trim', 'toLowerCase', 'toUpperCase'} and receiver: return receiver
        return None

    def function(self, node, handler=False):
        old = self.interaction_context
        self.interaction_context = self.handler_contexts.get(position(node), {})
        params = node.get('params', [])
        if params and params[0].get('type') == 'Identifier':
            self.interaction_context = dict(self.interaction_context, event_parameter=params[0]['name'], event_scope=self.lexical_block(params[0]), event_async=bool(node.get('async')))
        try: return super().function(node, handler)
        finally: self.interaction_context = old

    def handler(self, node, callback, target, trigger, deferred=False):
        if not callback: return
        definition = None
        if callback.get('type') == 'Identifier':
            value = next((env[callback['name']] for env in reversed(self.env) if callback['name'] in env), None)
            if value and value.entity and value.entity[0] == 'function' and callback['name'] not in self.unsafe_names:
                definition = self.definitions.get(value.entity[1])
            if definition is None: return
        elif callback.get('type') not in FUNCTIONS: return
        record = self.interaction.add(self, node, 'handler', element=target, trigger=trigger,
                                      kind='timer_callback' if deferred else 'event_handler', deferred=deferred)
        context = {'event_async': bool(callback.get('async')), 'event_parameter': (callback.get('params') or [{}])[0].get('name'), 'event_scope': self.lexical_block(callback.get('params', [{}])[0]) if callback.get('params') else None, 'id': record['id'] if record else None, 'element': target, 'trigger': trigger, 'deferred': deferred}
        if definition and record:
            record['_callback_function_ref'] = definition[1]['id']
            record['callback_function_ref'] = definition[1]['id']
        else:
            self.handler_contexts[position(callback)] = context

    def call(self, node):
        callee = node.get('callee', {}); args = node.get('arguments', [])
        method = key(callee.get('property', {})) if not callee.get('computed') or callee.get('property', {}).get('type') == 'Literal' else None
        if method == 'addEventListener' and len(args) > 1:
            target = self.resolve(callee.get('object')); trigger = self.resolve(args[0])
            if trigger and trigger[0] == 'literal' and trigger[1] in {'submit', 'click'}:
                self.handler(node, args[1], target[1] if target and target[0] == 'element' else None, trigger[1])
        elif callee.get('type') == 'Identifier' and callee.get('name') in {'setTimeout', 'setInterval'} and args:
            # Shadowed timer names cannot be treated as browser callbacks.
            if self.binding(callee) is None and not any(callee['name'] in env for env in self.env):
                self.handler(node, args[0], None, 'timer_declared', deferred=True)
        old = self.interaction_context
        receiver = callee.get('object', {})
        if method == 'preventDefault' and not old.get('event_async') and not args and receiver.get('type') == 'Identifier' and receiver.get('name') == old.get('event_parameter') and self.binding(receiver) is None and receiver.get('name') not in self.writes:
            scope = self.lexical_block(receiver)
            while scope and (scope, receiver['name']) not in self.bindings: scope = self.scope_parent.get(scope, ())
            if scope == old.get('event_scope'):
                self.interaction.add(self, node, 'default_cancel', handler_ref=old.get('id'))
        # Promise callbacks are declarations with unresolved async relationship.
        if method in {'then', 'catch'}:
            for arg in args:
                if arg.get('type') in FUNCTIONS: self.handler_contexts[position(arg)] = {'trigger': 'callback_relation_unresolved'}
        result = super().call(node)
        self.interaction_context = old
        if method in {'add', 'remove', 'toggle'}:
            receiver = self.resolve(callee.get('object'))
            if receiver and receiver[0] == 'member' and receiver[2] == 'classList' and receiver[1][0] == 'element':
                self.interaction.add(self, node, 'class_mutation', element=receiver[1][1], kind='class_mutation',
                                     operation=method, class_names=[label(a.get('value')) for a in args if a.get('type') == 'Literal'],
                                     visibility='unresolved', handler_ref=old.get('id'))
        return result

    def expression(self, node):
        kind = node.get('type'); left = node.get('left', {})
        target = self.resolve(left.get('object')) if kind == 'AssignmentExpression' else None
        prop = key(left.get('property', {})) if not left.get('computed') or left.get('property', {}).get('type') == 'Literal' else None
        rhs = node.get('right') or {}; provenance = self.resolve(rhs)
        if kind == 'AssignmentExpression' and target and target[0] == 'element' and prop in {'onsubmit', 'onclick'}:
            self.handler(node, rhs, target[1], prop[2:])
        navigation = kind == 'AssignmentExpression' and node.get('operator') == '=' and (
            target == ('builtin', 'location') and prop == 'href' or target == ('builtin', 'window') and prop == 'location' or
            left.get('type') == 'Identifier' and self.resolve(left) == ('builtin', 'location'))
        result = super().expression(node)
        if kind == 'AssignmentExpression' and node.get('operator') == '=' and target:
            element = target[1] if target[0] == 'element' else target[1][1] if target[0] == 'member' and target[2] == 'style' and target[1][0] == 'element' else None
            if element in self.interaction.elements:
                attrs = self.interaction.elements[element]['attrs']
                name = re.sub(r'([a-z])([A-Z])', r'\1 \2', attrs.get('id', ''))
                error = attrs.get('role') == 'alert' or bool(re.search(r'\berror\b', re.sub(r'[-_]+', ' ', name).lower()))
                details = {'element': element, 'handler_ref': self.interaction_context.get('id'), 'error_ui_candidate': error}
                if prop == 'value' and element in self.interaction.control_elements:
                    control = self.interaction.control_elements[element]
                    if provenance == ('literal', ''):
                        self.interaction.add(self, node, 'field_reset', kind='field_reset', target_control_ref=control['id'], **details)
                    else:
                        source_kind, source_control, name = 'unresolved', None, None
                        if provenance:
                            if provenance[0] == 'parameter': source_kind, name = ('url_query' if provenance[1] == 'search' else 'url_fragment'), provenance[2]
                            elif provenance[0] == 'storage': source_kind, name = provenance[1], provenance[2]
                            elif provenance[0] == 'literal': source_kind = 'static_literal'
                            elif provenance[0] == 'context': source_kind = 'browser_context'
                            elif provenance[0] == 'dom_value':
                                source_kind = 'dom_control'; source_control = self.interaction.control_elements.get(provenance[1], {}).get('id')
                        refs = list(result.traces)
                        source = next((s for s in self.js['sources'] if s['id'] in refs), None)
                        self.interaction.add(self, node, 'prefill', target_control_ref=control['id'], source_kind=source_kind,
                            source_ref=source['id'] if source else None, source_control_ref=source_control, key_name=name,
                            transform_refs=list(dict.fromkeys(t for chain in result.traces.values() for t in chain)), values='[omitted]',
                            final_submitted_value_provenance='unresolved', **details)
                elif prop in {'hidden', 'disabled', 'display', 'visibility'}:
                    literal = provenance[1] if provenance and provenance[0] == 'literal' else None
                    direction = ('hide' if literal is True else 'show' if literal is False else 'unresolved') if prop in {'hidden', 'disabled'} else (
                        'hide' if literal == ('none' if prop == 'display' else 'hidden') else 'show' if literal in (
                        {'block', 'inline', 'inline-block', 'flex', 'grid'} if prop == 'display' else {'visible'}) else 'unresolved')
                    if prop in {'display', 'visibility'} and target[0] != 'member': direction = 'unresolved'
                    if prop == 'disabled' and self.interaction.elements[element]['tag'] not in {'fieldset','input','select','textarea','button'}: direction = 'unresolved'
                    self.interaction.add(self, node, 'availability' if prop == 'disabled' else 'visibility',
                                         kind='availability_mutation' if prop == 'disabled' else 'visibility_mutation', property=prop,
                                         direction=direction, **details)
                elif prop in {'innerHTML', 'textContent', 'innerText'}:
                    self.interaction.add(self, node, 'content_replacement', kind='content_replacement', property=prop,
                                         message='content replacement declared; text omitted',
                                         error_content_state=('error_cleared' if provenance == ('literal', '') else 'error_presented_candidate' if provenance and provenance[0] == 'literal' and isinstance(provenance[1], str) and provenance[1] else 'error_content_mutated_unresolved') if error else None, **details)
        if navigation and not any(r['_kind'] == 'navigation' and r['_offset'] == node['range'][0] and r['scope_ref'].endswith(':'+self.scope) for r in self.interaction.raw):
            self.navigation(node, provenance[1] if provenance and provenance[0] == 'literal' else None)
        if kind == 'UpdateExpression' or kind == 'AssignmentExpression' and node.get('operator') == '+=':
            counter = node.get('argument') or left
            name = counter.get('name') if counter.get('type') == 'Identifier' else None
            declaration = self.binding(counter)
            init = (declaration or {}).get('init') or {}
            increment = kind == 'UpdateExpression' and node.get('operator') == '++' or rhs.get('type') == 'Literal' and rhs.get('value') == 1
            if name and name not in self.counter_unsafe and increment and re.fullmatch(r'(?:attempts?|attemptCount|retryCount|retries)', name) and init.get('type') == 'Literal' and isinstance(init.get('value'), (int, float)) and not isinstance(init['value'], bool):
                self.interaction.add(self, node, 'counter', kind='attempt_counter', binding=label(name), actual_attempts='unresolved', element=self.interaction_context.get('element'))
        return result

    def navigation(self, node, raw_target, sink_ref=None):
        target = target_url(raw_target, self.document_url, self.parser is None or self.parser.base_href_present)
        state = 'unresolved' if raw_target is None else 'exact_static_url' if target and urlsplit(raw_target).scheme else 'relative_static_url' if target else 'unresolved'
        self.interaction.add(self, node, 'navigation', kind='navigation', target=safe_url(target), target_state=state,
                             sink_ref=sink_ref, element=self.interaction_context.get('element'),
                             handler_ref=self.interaction_context.get('id'), deferred=self.interaction_context.get('deferred', False),
                             callback_relationship=self.interaction_context.get('trigger'))

    def sink(self, node, kind, target, body=None, *args, **kwargs):
        before = len(self.js['sinks'])
        result = super().sink(node, kind, target, body, *args, **kwargs)
        for sink in self.js['sinks'][before:]:
            if kind == 'navigation': self.navigation(node, target.const, sink['id'])
            elif kind in {'fetch', 'xmlhttprequest', 'send_beacon', 'form_submit', 'form_request_submit'}:
                self.interaction.add(self, node, 'request', sink_ref=sink['id'], element=self.interaction_context.get('element'))
        self.interaction_epoch += 1
        return result

    def unknown_call(self, node, value):
        self.interaction_epoch += 1
        return super().unknown_call(node, value)
