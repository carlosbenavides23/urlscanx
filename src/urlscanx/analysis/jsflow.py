"""Conservative AST transfer rules, local scopes only; no JS evaluation."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
import re

from .adapters import label, safe_url
from ..display import is_sensitive_name
from .javascript import (BudgetExceeded, MAX_FLOWS, MAX_NESTING, MAX_RECORDS,
                         MAX_STRING, MAX_TRANSFORMS, endpoint, target_url)

SENSITIVE = frozenset({'password', 'username', 'email', 'otp_candidate', 'payment_pan', 'payment_cvc', 'payment_expiry'})
BUILTINS = frozenset({'document', 'window', 'location', 'navigator', 'screen', 'localStorage',
                     'sessionStorage', 'fetch', 'XMLHttpRequest', 'URLSearchParams', 'FormData',
                     'JSON', 'encodeURIComponent', 'decodeURIComponent', 'btoa', 'atob'})
FUNCTIONS = frozenset({'FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'})
MAX_VALUE_NODES = 2_000
MAX_OPERATIONS = 40_000
MUTABLE = frozenset({'json_object', 'array', 'form_data', 'url_search_params'})


@dataclass
class Value:
    # Raw literals/selector names exist only in transient analysis memory.
    const: object = None
    traces: dict[str, tuple[str, ...]] = field(default_factory=dict)
    props: dict[str, Value] = field(default_factory=dict)
    entity: tuple | None = None
    encoding: str = 'unknown_expression'
    uncertain: bool = False
    symbols: tuple[str, ...] = ()
    own_transforms: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()  # private constant/configuration provenance
    immutable_binding: str | None = None  # private exact binding identity for path predicates
    static_boolean: bool | None = None  # pure literal/boolean syntax only, never function results
    possible_sources: tuple[str, ...] = ()  # structural producer alternatives, not propagation
    multiplicity: int | None = 1
    payload_candidates: dict = field(default_factory=dict)  # shape only after branch invalidation
    container_kind: str | None = None  # encoding before JSON serialization
    serialization_hazards: set[str] = field(default_factory=set)  # invalidation, never values
    serialization_shape: str | None = None


def serialization_hazards(value, active=None, depth=0):
    """Known local serialization hazards only; no prototype/toJSON evaluation."""
    active = active or set()
    if depth > MAX_NESTING or id(value) in active:
        return ('serialization_structure_unresolved',)
    active.add(id(value))
    reasons = set(value.serialization_hazards)
    properties = value.props or value.payload_candidates
    if 'toJSON' in properties:
        reasons.add('toJSON_possible')
    if '__proto__' in properties:
        reasons.add('prototype_mutation')
    for child in properties.values():
        reasons.update(serialization_hazards(child, active, depth + 1))
    active.remove(id(value))
    return tuple(sorted(reasons))


def joined(values, *, encoding='unknown_expression'):
    traces = {}
    uncertain = False
    for value in values:
        uncertain |= value.uncertain
        for source, chain in value.traces.items():
            traces[source] = tuple(dict.fromkeys((*traces.get(source, ()), *chain)))
    symbols = tuple(dict.fromkeys(s for v in values for s in v.symbols))
    return Value(traces=traces, encoding=encoding, uncertain=uncertain, symbols=symbols,
                 evidence=tuple(dict.fromkeys(ref for v in values for ref in v.evidence)))


def key(node):
    if node.get('type') == 'Identifier':
        return node.get('name')
    if node.get('type') == 'Literal' and isinstance(node.get('value'), (str, int)):
        return str(node['value'])
    return None


class FlowEngine:
    def __init__(self, js, registry, script, artifact, parser, document_url, events):
        self.js, self.registry, self.script, self.artifact = js, registry, script, artifact
        self.parser, self.document_url, self.events = parser, document_url, events
        self.env = [{}]
        self.scope = 'script'
        self.execution_context = 'declared'
        self.depth = 0
        self.visited_functions = set()
        self.refs = {}
        self.source_records = {s['id']: s for s in js['sources']}
        self.record_count = 0
        self.operations = 0

    def step(self):
        self.operations += 1
        if self.operations > MAX_OPERATIONS:
            raise BudgetExceeded('abstract operation budget')

    def clone(self, value):
        # Protect against repeated binary object construction expanding the
        # abstract graph exponentially even when the JS AST itself is small.
        pending, seen = [(value, 0)], set()
        while pending:
            item, depth = pending.pop()
            self.step()
            if id(item) in seen:
                continue
            seen.add(id(item))
            if len(seen) > MAX_VALUE_NODES or depth > MAX_NESTING:
                raise BudgetExceeded('abstract value graph budget')
            children = item.props.values() if isinstance(item, Value) else item.values() if isinstance(item, dict) else item if isinstance(item, list) else ()
            pending.extend((v, depth + 1) for v in children)
        return deepcopy(value)

    def location(self, node):
        start = node.get('loc', {}).get('start', {})
        loc = {'script_line': start.get('line'), 'script_column': start.get('column')}
        base = self.script.get('body_location')
        if base and start.get('line') is not None:
            loc.update(dom_line=base['line'] + start['line'] - 1,
                       dom_column=start.get('column', 0) + (base['column'] if start['line'] == 1 else 0))
        return loc

    def record(self, category, node, state, **details):
        self.record_count += 1
        if self.record_count > MAX_RECORDS or sum(len(self.js[k]) for k in ('sources', 'transforms', 'sinks', 'calls')) >= MAX_RECORDS:
            raise BudgetExceeded('static record budget')
        loc = self.location(node)
        marker = details.get('control_id') or details.get('field') or details.get('property') or details.get('key_name')
        identity = (category, tuple(node.get('range', ())), state, details.get('kind'), marker)
        if identity not in self.refs:
            self.refs[identity] = self.registry.add(self.artifact, 'static_code', state,
                self.script['location'] | loc | {'category': category, 'kind': details.get('kind'), 'marker': marker},
                'Preserved JavaScript syntax; execution not established')
        ref = self.refs[identity]
        record = {'id': self.registry.identifier('js-' + category, [self.script['id'], ref, marker]),
                  'script_ref': self.script['id'], 'artifact_ref': self.script['artifact_ref'], 'location': loc,
                  'scope_ref': self.script['id'] + ':' + self.scope, 'evidence_refs': [ref], 'state': state,
                  'execution_context': self.execution_context, 'limitations': ['Static syntax only; execution unresolved.'], **details}
        existing = next((r for r in self.js[category] if r['id'] == record['id']), None)
        if existing is None:
            self.js[category].append(record)
        return existing or record

    def lookup(self, name):
        for env in reversed(self.env):
            if name in env:
                value = env[name]
                if value.uncertain and not value.symbols and value.const is None:
                    candidates = value.payload_candidates
                    hazards = value.serialization_hazards
                    value = self.clone(value)
                    value.payload_candidates = candidates
                    value.serialization_hazards = hazards
                    value.symbols = (label(name) or '[omitted]',)
                return value
        return Value(entity=('builtin', name)) if name in BUILTINS else Value(uncertain=True, symbols=(label(name) or '[omitted]',))

    def assign(self, name, value, declaration=False):
        if is_sensitive_name(name) and value.const is not None:
            value = self.clone(value)
            value.const = None  # semantic literal secrets cannot become displayed targets
        if declaration:
            self.env[-1][name] = value
        else:
            for env in reversed(self.env):
                if name in env:
                    env[name] = value
                    return
            if name in BUILTINS:
                self.env[-1][name] = Value(uncertain=True)
            # Undeclared global writes do not create trusted local aliases.

    def path(self, node):
        if node.get('type') == 'Identifier':
            name = node['name']
            value = self.lookup(name)
            return name if value.entity == ('builtin', name) else None
        if node.get('type') == 'MemberExpression' and not node.get('optional'):
            parent = self.path(node['object'])
            part = key(node['property']) if not node.get('computed') or node['property'].get('type') == 'Literal' else None
            return parent + '.' + part if parent and part is not None else None
        return None

    def source(self, node, source_kind, **details):
        record = self.record('sources', node, 'referenced', kind=source_kind, source_kind=source_kind, **details)
        if details.get('control_id'):
            record['evidence_refs'] = list(dict.fromkeys(record['evidence_refs'] + details.pop('control_evidence', [])))
            record.pop('control_evidence', None)
        self.source_records[record['id']] = record
        return Value(traces={record['id']: ()})

    def transform(self, node, kind, value, **details):
        if not value.traces:
            return value
        for chain in value.traces.values():
            if len(chain) >= MAX_TRANSFORMS:
                raise BudgetExceeded('transform chain budget')
        record = self.record('transforms', node, 'referenced', kind=kind,
                             input_source_refs=sorted(value.traces), input_transform_refs=sorted({c for cs in value.traces.values() for c in cs}), **details)
        value.traces = {source: (*chain, record['id']) for source, chain in value.traces.items()}
        value.own_transforms = (*value.own_transforms, record['id'])
        return value

    def refresh(self, value, active=None, depth=0):
        self.step()
        active = active or set()
        if depth > MAX_NESTING or id(value) in active:
            raise BudgetExceeded('cyclic or deep abstract payload')
        if value.encoding in MUTABLE and value.props:
            active.add(id(value))
            for child in value.props.values():
                self.refresh(child, active, depth + 1)
            active.remove(id(value))
            value.traces = {source: (*chain, *value.own_transforms) for source, chain in joined(value.props.values()).traces.items()}
        return value

    def control(self, name, *, by_name=False, form=None):
        if self.parser is None or not isinstance(name, str):
            return Value(uncertain=True)
        matches = []
        for index, c in enumerate(self.parser.controls):
            attrs = c['attrs']
            if attrs.get('name' if by_name else 'id') != name:
                continue
            public = self.registry.analysis.dom_inventory['controls'][index]
            if public['markup_context'] != 'document_markup' or form is not None and public['form_index'] != form:
                continue
            matches.append(index)
        if len(matches) != 1 or not by_name and self.parser.id_counts.get(name) != 1:
            return Value(uncertain=True)
        return Value(entity=('control', matches[0]))

    def element(self, name):
        found = self.control(name)
        if found.entity or self.parser is None or self.parser.id_counts.get(name) != 1:
            return found
        matches = [i for i, f in enumerate(self.parser.forms) if f['attrs'].get('id') == name and f['markup_context'] == 'document_markup']
        return Value(entity=('form', matches[0])) if len(matches) == 1 else Value(uncertain=True)

    def selector(self, selector):
        if not isinstance(selector, str):
            return Value(uncertain=True)
        # A deliberately small CSS subset; never guess dynamic/complex selectors.
        if re.fullmatch(r'#[A-Za-z_][\w-]*', selector):
            return self.element(selector[1:])
        match = re.fullmatch(r'(input|select|textarea)?\[name=[\"\']([\w-]+)[\"\']\]', selector)
        if match:
            result = self.control(match[2], by_name=True)
            if result.entity and match[1] and self.parser.controls[result.entity[1]]['tag'] != match[1]:
                return Value(uncertain=True)
            return result
        return Value(uncertain=True)

    def fields(self, value, *, object_shape=False):
        from .payloads import field_name, field_path, MAX_DEPTH
        fields = []
        if value.encoding == 'json' and value.serialization_shape != 'exact' and not object_shape:
            return fields
        if value.container_kind in {'form_data','url_search_params'}:
            return fields  # JSON.stringify does not serialize these entries
        def walk(parent, path='$', depth=0, matchable=True):
            if depth > MAX_DEPTH:
                return
            for name, child in (parent.props or parent.payload_candidates).items():
                if len(fields) >= MAX_RECORDS:
                    return
                safe, exact = field_name(name)
                child_path = field_path(path, safe, parent.encoding == 'array' or parent.container_kind == 'array')
                fields.append({'name': safe, 'path': child_path, 'source_refs': sorted(child.traces),
                    'possible_source_refs': sorted(set(child.traces) | set(child.possible_sources)),
                    'multiplicity': child.multiplicity, 'unresolved': child.uncertain,
                    'structural_matchable': matchable and exact and not child.uncertain,
                    'producer_candidate': bool(parent.payload_candidates),
                    'container': bool(child.props or child.payload_candidates),
                    'producer_transform_refs': sorted({t for chain in child.traces.values() for t in chain}),
                    'unresolved_references': list(child.symbols),
                    'semantic_roles': sorted({self.source_records[s].get('semantic_role', 'contextual') for s in child.traces})})
                walk(child,child_path,depth+1,matchable and exact)
        walk(value)
        return fields

    def sink(self, node, kind, target, body=None, method=None, *, key_name=None, form=None, headers=None):
        body = body or Value()
        self.refresh(body)
        # Without a trustworthy DOM inventory, absence of <base> is unproved.
        raw_url = target_url(target.const, self.document_url, self.parser is None or self.parser.base_href_present) if kind not in {'browser_storage_write'} else None
        record = self.record('sinks', node, 'declared', kind=kind, sink_kind=kind,
                             target=safe_url(raw_url or target.const) if isinstance(target.const, str) and kind != 'browser_storage_write' else None,
                             target_resolution='resolved' if raw_url else 'unresolved', method=method,
                             target_expression={'references': list(target.symbols), 'value': '[omitted]' if raw_url is None else 'sanitized target'},
                             payload={'encoding': body.encoding, 'fields': self.fields(body), 'values': '[omitted]',
                                      'serialization_shape': body.serialization_shape,
                                      'serialization_shape_reasons': sorted(body.serialization_hazards),
                                      'object_fields': self.fields(body, object_shape=True) if body.encoding == 'json' and body.serialization_shape != 'exact' else [],
                                      'relationship': 'static_expression', 'has_unresolved_inputs': body.uncertain},
                             headers=headers or [], key_name=label(key_name), form_ref=form,
                             runtime_endpoint='not_observed' if raw_url else 'unresolved', payload_relationship='unresolved')
        traces_by_channel = [('body', body.traces), ('target', target.traces)]
        for channel, traces in traces_by_channel:
            for source, chain in traces.items():
                if len(self.js['flows']) >= MAX_FLOWS:
                    raise BudgetExceeded('flow budget')
                source_record = self.source_records[source]
                refs = list(dict.fromkeys(source_record['evidence_refs'] + record['evidence_refs'] +
                    [ref for t in self.js['transforms'] if t['id'] in chain for ref in t['evidence_refs']]))
                flow = {'id': self.registry.identifier('js-flow', [source, chain, record['id'], channel]),
                        'script_ref': self.script['id'], 'artifact_ref': self.script['artifact_ref'],
                        'location': record['location'], 'evidence_refs': refs, 'state': 'static_flow_inferred',
                        'source_id': source, 'transform_ids': list(chain), 'sink_id': record['id'],
                        'channel': channel, 'semantic_role': source_record.get('semantic_role'),
                        'sensitive': source_record.get('semantic_role') in SENSITIVE,
                        'limitations': ['Static expression dependency only; execution, submission and receipt unresolved.']}
                if not any(f['id'] == flow['id'] for f in self.js['flows']):
                    self.js['flows'].append(flow)
        if raw_url and kind in {'fetch', 'xmlhttprequest', 'send_beacon', 'navigation', 'form_submit', 'form_request_submit'}:
            for event in self.events:
                if endpoint(event.raw_url) != endpoint(raw_url) or method and event.method != method:
                    continue
                ref = self.registry.add('result', 'network_request', 'runtime_observed', {'json_pointer': event.request_pointer},
                                        'Compatible endpoint request captured; static payload relationship unresolved')
                self.js['runtime_joins'].append({'id': self.registry.identifier('js-join', [record['id'], ref]),
                    'script_ref': self.script['id'], 'artifact_ref': record['artifact_ref'], 'location': record['location'],
                    'sink_id': record['id'], 'request_ref': event.pointer,
                    'evidence_refs': [*record['evidence_refs'], ref], 'state': 'endpoint_observed',
                    'payload_relationship': 'unresolved', 'limitations': ['Endpoint and method only; no execution or body equality claim.']})
                record['runtime_endpoint'] = 'endpoint_observed'
        return Value(uncertain=True)

    def eval(self, node):
        self.step()
        if not isinstance(node, dict):
            return Value(uncertain=True)
        self.depth += 1
        if self.depth > MAX_NESTING:
            raise BudgetExceeded('flow depth budget')
        try:
            return self.expression(node)
        finally:
            self.depth -= 1

    def expression(self, node):
        kind = node.get('type')
        if kind == 'Literal':
            val = node.get('value')
            return Value(const=val if not isinstance(val, str) or len(val) <= MAX_STRING else None,
                         encoding='raw_string' if isinstance(val, str) else 'literal')
        if kind == 'Identifier':
            return self.lookup(node['name'])
        if kind in FUNCTIONS:
            self.function(node)
            return Value(entity=('function', tuple(node.get('range', ()))))
        if kind == 'MemberExpression':
            obj = self.eval(node['object'])
            prop = key(node['property']) if not node.get('computed') else self.eval(node['property']).const
            if not isinstance(prop, (str, int)):
                return Value(uncertain=True)
            prop = str(prop)
            if obj.entity and obj.entity[0] == 'control' and prop == 'value':
                c = self.registry.analysis.dom_inventory['controls'][obj.entity[1]]
                return self.source(node, 'dom_control', semantic_role=c['semantic_role'], control_id=c['id'],
                                   control_evidence=c['evidence_refs'], control_label=c['element_id'] or c['name'])
            if obj.entity and obj.entity[0] == 'form' and prop == 'elements':
                return Value(entity=('form_elements', obj.entity[1]))
            if obj.entity and obj.entity[0] == 'form_elements':
                return self.control(prop, by_name=True, form=obj.entity[1])
            path = self.path(node)
            if path in {'location.search', 'location.hash', 'location.href', 'window.location.search', 'window.location.hash', 'window.location.href',
                        'navigator.userAgent', 'navigator.language', 'document.referrer', 'screen.width', 'screen.height'}:
                return self.source(node, 'browser_context', property=path, semantic_role=None)
            value = obj.props.get(prop, Value(uncertain=True, symbols=tuple((s + '.' + (label(prop) or '[omitted]'))[:MAX_STRING] for s in obj.symbols)))
            value.evidence = tuple(dict.fromkeys((*value.evidence, *obj.evidence)))
            return value
        if kind == 'ObjectExpression':
            props = {}
            for prop in node.get('properties', []):
                special = key(prop.get('key', {})) == 'toJSON'
                if prop.get('type') != 'Property' or not special and (prop.get('kind') != 'init' or prop.get('method') or prop.get('computed')):
                    return Value(uncertain=True)  # getters/spreads/dynamic keys are not plain objects
                name = key(prop['key'])
                if name is None:
                    return Value(uncertain=True)
                candidate = self.eval(prop['value'])
                # Nested mutable object aliases need heap tracking. Withhold them
                # rather than freeze a snapshot that later mutations invalidate.
                field_value = Value(uncertain=True) if candidate.encoding in MUTABLE else self.clone(candidate)
                if name == 'body' and candidate.encoding in MUTABLE:
                    # Fetch options retain the receiver identity until the sink;
                    # never freeze a mutable body into a historical snapshot.
                    props[name] = candidate
                    continue
                if is_sensitive_name(name):
                    field_value.const = None
                props[name] = self.transform(prop, 'object_property', field_value, field=label(name))
            val = joined(props.values(), encoding='json_object')
            val.props = props
            return self.transform(node, 'object_construction', val)
        if kind == 'ArrayExpression':
            elements = node.get('elements', [])
            vals = [self.eval(n) for n in elements]
            vals = [Value(uncertain=True) if v.encoding in MUTABLE and (n or {}).get('type') not in {'ObjectExpression','ArrayExpression'} else v for n,v in zip(elements,vals)]
            val = joined(vals, encoding='array')
            val.props = {str(i): v for i, v in enumerate(vals)}
            return self.transform(node, 'array_insertion', val)
        if kind in {'BinaryExpression', 'TemplateLiteral'}:
            if kind == 'BinaryExpression' and node.get('operator') != '+':
                self.eval(node['left']); self.eval(node['right'])
                return Value(uncertain=True)
            if kind == 'TemplateLiteral':
                vals = []
                for i, q in enumerate(node.get('quasis', [])):
                    vals.append(Value(const=q.get('value', {}).get('cooked'), encoding='raw_string'))
                    if i < len(node.get('expressions', [])):
                        vals.append(self.eval(node['expressions'][i]))
            else:
                vals = [self.eval(node['left']), self.eval(node['right'])]
            val = joined(vals, encoding='raw_string')
            if all(isinstance(v.const, str) for v in vals):
                text = ''.join(v.const for v in vals)
                val.const = text if len(text) <= MAX_STRING else None
            return self.transform(node, 'template_interpolation' if kind == 'TemplateLiteral' else 'string_concatenation', val)
        if kind == 'AssignmentExpression':
            left = node['left']
            handler = left.get('type') == 'MemberExpression' and (key(left.get('property', {})) or '').startswith('on')
            if handler and node['right'].get('type') in FUNCTIONS:
                self.function(node['right'], handler=True)
                right = Value()
            else:
                right = self.eval(node['right'])
            if self.path(left) in {'location.href', 'window.location.href'}:
                return self.sink(node, 'navigation', right)
            if left.get('type') == 'Identifier':
                val = self.clone(right) if not right.entity and not right.props else right
                if node.get('operator') != '=':
                    val = Value(uncertain=True)
                else:
                    val = self.transform(node, 'direct_assignment', val)
                self.assign(left['name'], val)
                return val
            if left.get('type') == 'MemberExpression':
                path = self.path(left)
                if path and path.split('.')[0] in BUILTINS:
                    # Replaced builtins must not retain trusted intrinsic behavior.
                    self.assign(path.split('.')[0], Value(uncertain=True), declaration=True)
                obj = self.eval(left['object'])
                prop = key(left['property']) if not left.get('computed') else self.eval(left['property']).const
                if isinstance(prop,str) and prop in {'toJSON','__proto__'}:
                    obj.serialization_hazards.add('toJSON_possible' if prop == 'toJSON' else 'prototype_mutation')
                if obj.entity and obj.entity[0] == 'control':
                    return Value(uncertain=True)  # DOM writes do not reclassify captured source
                if isinstance(prop, str) and node.get('operator') == '=' and obj.encoding in {'json_object', 'array', 'form_data', 'url_search_params'}:
                    field_value = Value(uncertain=True) if right.encoding in MUTABLE else self.clone(right)
                    if getattr(self, 'path_state', None) in {'conditional','unresolved','truncated'}:
                        prior = obj.props.get(prop, Value())
                        field_value.possible_sources = tuple(sorted(set(prior.traces) | set(prior.possible_sources) | set(field_value.traces)))
                    if is_sensitive_name(prop):
                        field_value.const = None
                    obj.props[prop] = self.transform(node, 'property_assignment', field_value, field=label(prop))
                    obj.traces = joined(obj.props.values()).traces
                elif obj.payload_candidates and isinstance(prop,str) and node.get('operator') == '=' and right.encoding not in MUTABLE:
                    candidate = self.transform(node, 'property_assignment', self.clone(right), field=label(prop))
                    previous = obj.payload_candidates.get(prop)
                    obj.payload_candidates[prop] = joined([previous,candidate]) if previous else candidate
                else:
                    obj.props.clear(); obj.payload_candidates.clear(); obj.traces.clear(); obj.const = None; obj.uncertain = True
            return right
        if kind in {'CallExpression', 'NewExpression'}:
            return self.call(node)
        if kind == 'AwaitExpression':
            return self.eval(node.get('argument'))
        if kind == 'SequenceExpression':
            val = Value()
            for expr in node['expressions']:
                val = self.eval(expr)
            return val
        if kind in {'ConditionalExpression', 'LogicalExpression'}:
            # Expressions in branches may contain sinks, but ambiguous return
            # dependencies never propagate beyond this expression.
            self.eval(node['test'] if kind == 'ConditionalExpression' else node['left'])
            for k in ('consequent', 'alternate') if kind == 'ConditionalExpression' else ('right',):
                self.branch({'type': 'ExpressionStatement', 'expression': node[k]})
            return Value(uncertain=True)
        if kind in {'UnaryExpression', 'UpdateExpression'}:
            argument = node.get('argument', {})
            if kind == 'UnaryExpression' and node.get('operator') == 'delete' and argument.get('type') == 'MemberExpression':
                obj = self.eval(argument['object'])
                prop = key(argument['property']) if not argument.get('computed') else self.eval(argument['property']).const
                if obj.encoding in {'json_object','array'} and isinstance(prop, (str,int)):
                    if getattr(self, 'path_state', 'unconditional') != 'unconditional' or getattr(self, 'conditional', 0):
                        obj.serialization_hazards.add('conditional_delete')
                    if obj.encoding == 'array':
                        obj.serialization_hazards.add('array_delete_unresolved')
                    obj.props.pop(str(prop), None)
                    obj.traces = joined(obj.props.values()).traces
                elif obj.props or obj.payload_candidates:
                    obj.serialization_hazards.add('dynamic_or_ambiguous_delete')
                return Value(uncertain=True)
            self.eval(node.get('argument'))
            if node.get('argument', {}).get('type') == 'Identifier' and kind == 'UpdateExpression':
                self.assign(node['argument']['name'], Value(uncertain=True))
            return Value(uncertain=True)
        return Value(uncertain=True)

    def call(self, node):
        callee = node.get('callee', {})
        path = self.path(callee)
        args = []
        is_handler = callee.get('type') == 'MemberExpression' and key(callee.get('property', {})) == 'addEventListener'
        for i, arg in enumerate(node.get('arguments', [])):
            if is_handler and i == 1 and arg.get('type') in FUNCTIONS:
                self.function(arg, handler=True)
                args.append(Value())
            else:
                args.append(self.eval(arg))
        receiver = self.eval(callee['object']) if callee.get('type') == 'MemberExpression' else Value()
        method = key(callee.get('property', {})) if not callee.get('computed') else None
        if path == 'document.getElementById' and args:
            return self.element(args[0].const)
        if path == 'document.querySelector' and args:
            return self.selector(args[0].const)
        if path in {'localStorage.getItem', 'sessionStorage.getItem'} and args and isinstance(args[0].const, str):
            return self.source(node, 'storage_read', storage=path.split('.')[0], key_name=label(args[0].const), semantic_role=None)
        if path in {'URLSearchParams', 'FormData'} and node['type'] == 'NewExpression':
            val = joined(args, encoding='url_search_params' if path == 'URLSearchParams' else 'form_data')
            val.entity = (val.encoding,)
            if path == 'FormData' and args and args[0].entity and args[0].entity[0] == 'form':
                form = args[0].entity[1]
                for c in self.registry.analysis.dom_inventory['controls']:
                    if c['form_index'] != form or c['disabled'] or c['markup_context'] != 'document_markup' or c['html_type'] in {'checkbox', 'radio', 'file', 'button', 'reset', 'submit', 'image'}:
                        continue
                    name = self.parser.controls[c['index']]['attrs'].get('name')
                    if name and name not in val.props:
                        val.props[name] = self.source(node | {'loc': node['loc'], 'range': [node['range'][0], c['index']]}, 'dom_control',
                            semantic_role=c['semantic_role'], control_id=c['id'], control_evidence=c['evidence_refs'], control_label=c['name'])
                val.traces = joined(val.props.values()).traces
            elif args and args[0].props:
                val.props = self.clone(args[0].props)
            return self.transform(node, path + '_construction', val)
        if receiver.entity and receiver.entity[0] == 'url_search_params' and method == 'get' and args and isinstance(args[0].const, str):
            if any(self.source_records[s]['source_kind'] == 'browser_context' and self.source_records[s].get('property', '').endswith(('.search', '.hash')) for s in receiver.traces):
                return self.source(node, 'url_parameter', parameter_name=label(args[0].const), semantic_role=None)
            return receiver.props.get(args[0].const, Value(uncertain=True))
        if receiver.entity and receiver.entity[0] in {'form_data', 'url_search_params'} and method in {'append', 'set'}:
            if len(args) >= 2 and isinstance(args[0].const, str):
                value = Value(uncertain=True) if args[1].encoding in MUTABLE else self.clone(args[1])
                if method == 'append' and args[0].const in receiver.props:
                    prior = receiver.props[args[0].const]
                    value = joined([receiver.props[args[0].const], value])
                    value.multiplicity = prior.multiplicity + 1 if prior.multiplicity is not None else None
                receiver.props[args[0].const] = self.transform(node, method, value, field=label(args[0].const))
                receiver.traces = joined(receiver.props.values()).traces
            else:
                receiver.props.clear(); receiver.traces.clear(); receiver.uncertain = True
            return Value()
        if path == 'JSON.stringify' and args:
            val = self.clone(self.refresh(args[0]))
            reasons = set(serialization_hazards(val))
            raw_args = node.get('arguments', [])
            no_replacer = len(raw_args) < 2 or raw_args[1].get('type') == 'Literal' and raw_args[1].get('raw') == 'null'
            if not no_replacer:
                reasons.add('replacer_unresolved')
            val.serialization_hazards = reasons
            val.serialization_shape = 'unresolved' if reasons else 'exact'
            val.container_kind = val.encoding; val.encoding = 'json'; val.const = None
            return self.transform(node, 'JSON.stringify', val)
        prototype_method = method or (key(callee.get('property', {})) if callee.get('property', {}).get('type') == 'Literal' else None)
        if callee.get('type') == 'MemberExpression' and prototype_method == 'setPrototypeOf' and args:
            obj = args[0]
            if obj.props or obj.payload_candidates:
                obj.serialization_hazards.add('prototype_mutation')
                self.unknown_call(node, joined(args))
                return Value(uncertain=True)
        if path in {'encodeURIComponent', 'decodeURIComponent', 'btoa', 'atob'} and args:
            val = self.clone(args[0]); val.const = None
            return self.transform(node, path, val)
        if method in {'trim', 'toLowerCase', 'toUpperCase', 'toString'} and not args:
            val = self.clone(receiver); val.const = None
            return self.transform(node, method, val)
        if path == 'XMLHttpRequest' and node['type'] == 'NewExpression':
            return Value(entity=('xhr', tuple(node.get('range', ()))), props={})
        if receiver.entity and receiver.entity[0] == 'xhr' and method == 'open':
            receiver.props.clear()
            if len(args) >= 2:
                receiver.props.update(method=args[0], target=args[1])
            return Value()
        if receiver.entity and receiver.entity[0] == 'xhr' and method == 'send':
            verb = receiver.props.get('method', Value()).const
            return self.sink(node, 'xmlhttprequest', receiver.props.get('target', Value()), args[0] if args else None,
                             verb.upper() if isinstance(verb, str) and re.fullmatch('[A-Za-z]{1,16}', verb) else None)
        if path == 'fetch' and args:
            opts = args[1] if len(args) > 1 else Value()
            method_value = opts.props.get('method', Value()).const
            verb = method_value.upper() if isinstance(method_value, str) and re.fullmatch('[A-Za-z]{1,16}', method_value) else 'GET' if len(args) == 1 or opts.encoding == 'json_object' and 'method' not in opts.props else None
            headers = opts.props.get('headers', Value()).props
            return self.sink(node, 'fetch', args[0], opts.props.get('body'), verb,
                             headers=[{'name': label(k), 'value': '[omitted]'} for k, v in headers.items() if isinstance(v.const, str)])
        if path == 'navigator.sendBeacon' and args:
            return self.sink(node, 'send_beacon', args[0], args[1] if len(args) > 1 else None, 'POST')
        if path in {'localStorage.setItem', 'sessionStorage.setItem'} and len(args) >= 2:
            return self.sink(node, 'browser_storage_write', args[0], args[1], key_name=args[0].const)
        if path in {'location.assign', 'location.replace', 'window.location.assign', 'window.location.replace'} and args:
            return self.sink(node, 'navigation', args[0])
        if receiver.entity and receiver.entity[0] == 'form' and method in {'submit', 'requestSubmit'}:
            form = self.registry.analysis.dom_inventory['forms'][receiver.entity[1]]
            # Form action is known markup, never assumed effective at runtime.
            return self.sink(node, 'form_submit' if method == 'submit' else 'form_request_submit', Value(const=form['resolved_markup_target']),
                             method=form['markup_method'], form=form['id'])
        if callee.get('type') in FUNCTIONS:
            self.function(callee)  # body analyzed independently; arguments are not bound
        known = joined(args)
        self.unknown_call(node, known)
        # Unknown calls can mutate objects. They cannot preserve a trusted payload
        # shape or XHR identity past an escape. Scalars have no mutable identity.
        for arg in args:
            if arg.props or arg.payload_candidates or arg.entity and arg.entity[0] in {'xhr', 'form_data', 'url_search_params'}:
                self.escape(arg)
            elif arg.entity and arg.entity[0] == 'builtin':
                self.assign(arg.entity[1], Value(uncertain=True), declaration=True)
        if receiver.props or receiver.payload_candidates or receiver.entity and receiver.entity[0] == 'xhr':
            self.escape(receiver)
        if callee.get('type') == 'Identifier' and callee.get('name') in {'eval', 'Function'}:
            for env in self.env:
                for name in env:
                    env[name] = Value(uncertain=True)
        return Value(uncertain=True)

    def escape(self, value):
        value.props.clear(); value.traces.clear(); value.entity = None; value.uncertain = True

    def unknown_call(self, node, value):
        if value.traces:
            self.record('calls', node, 'unresolved', kind='unsupported_call', source_refs=sorted(value.traces), callee_flow='unresolved')

    def function(self, node, handler=False):
        identity = tuple(node.get('range', ()))
        if identity in self.visited_functions:
            return
        self.visited_functions.add(identity)
        old = self.env, self.scope, self.execution_context
        self.env = [{name: Value(uncertain=True) for env in self.env for name in env if name in BUILTINS}]
        self.scope = 'function:' + str(node.get('range', [0])[0])
        self.execution_context = 'handler_declared' if handler else 'declared'
        for param in node.get('params', []):
            self.bind_unknown(param)
        body = node.get('body', {})
        self.hoist(body)
        if body.get('type') == 'BlockStatement':
            self.block(body.get('body', []), fresh=False)
        else:
            self.eval(body)
        self.env, self.scope, self.execution_context = old

    def bind_unknown(self, node):
        if node.get('type') == 'Identifier':
            self.assign(node['name'], Value(uncertain=True, symbols=(label(node['name']) or '[omitted]',)), declaration=True)
        else:
            for value in node.values():
                if isinstance(value, dict):
                    self.bind_unknown(value)
                elif isinstance(value, list):
                    for entry in value:
                        if isinstance(entry, dict):
                            self.bind_unknown(entry)

    def block(self, statements, fresh=True):
        if fresh:
            self.env.append({})
        # Predeclare bindings so shadowed globals and TDZ reads do not turn into
        # builtins or outer values. Hoisted var bindings are predeclared per function.
        for statement in statements:
            if statement.get('type') == 'VariableDeclaration' and statement.get('kind') != 'var':
                for d in statement['declarations']:
                    self.bind_unknown(d['id'])
            if statement.get('type') in {'FunctionDeclaration', 'ClassDeclaration', 'ImportDeclaration'}:
                if statement.get('id'):
                    self.bind_unknown(statement['id'])
                for spec in statement.get('specifiers', []):
                    self.bind_unknown(spec['local'])
        for statement in statements:
            if self.statement(statement):
                break
        if fresh:
            self.env.pop()

    def branch(self, node):
        # Analyze a branch in isolation, then invalidate every changed binding.
        before = self.clone(self.env)
        self.statement(node)
        after = self.env
        changed = [(i, name) for i, env in enumerate(before) for name, val in env.items() if name not in after[i] or val != after[i][name]]
        self.env = before
        for i, name in changed:
            candidates = {}
            hazards = set()
            for original in (before[i].get(name), after[i].get(name)):
                if original is not None:
                    hazards.update(original.serialization_hazards)
                    for field_name, child in (original.props or original.payload_candidates).items():
                        if field_name in candidates:
                            previous = candidates[field_name]
                            child = joined([previous,child])
                            child.possible_sources = tuple(sorted(child.traces))
                        candidates[field_name] = child
            # Do not restore propagation or receiver identity. The retained shape
            # is an alternative producer inventory only.
            self.env[i][name] = Value(uncertain=True, payload_candidates=candidates, serialization_hazards=hazards)

    def statement(self, node):
        self.step()
        kind = node.get('type')
        if kind == 'BlockStatement':
            self.block(node.get('body', []))
        elif kind == 'VariableDeclaration':
            for decl in node.get('declarations', []):
                val = self.eval(decl.get('init'))
                if decl['id'].get('type') == 'Identifier':
                    if val.traces and not val.props and not val.entity:
                        val = self.transform(decl, 'variable_alias', self.clone(val))
                    self.assign(decl['id']['name'], val, declaration=node.get('kind') != 'var')
                else:
                    self.bind_unknown(decl['id'])
        elif kind == 'ExpressionStatement':
            self.eval(node['expression'])
        elif kind == 'FunctionDeclaration':
            self.function(node)
        elif kind == 'IfStatement':
            self.eval(node['test'])
            self.branch(node['consequent'])
            if node.get('alternate'):
                self.branch(node['alternate'])
        elif kind == 'TryStatement':
            # Normal try body is an explicit lexical path. Catch is isolated;
            # no attempt to prove thrown/returned states or asynchronous success.
            self.statement(node['block'])
            if node.get('handler'):
                handler = node['handler']
                self.env.append({})
                self.bind_unknown(handler.get('param') or {})
                self.branch(handler['body'])
                self.env.pop()
            if node.get('finalizer'):
                self.statement(node['finalizer'])
        elif kind in {'ForStatement', 'WhileStatement', 'DoWhileStatement', 'ForOfStatement', 'ForInStatement'}:
            self.env.append({})
            if node.get('init'):
                self.statement(node['init']) if node['init'].get('type') == 'VariableDeclaration' else self.eval(node['init'])
            for name in ('test', 'right', 'update'):
                if node.get(name):
                    self.eval(node[name])
            if node.get('left'):
                self.statement(node['left']) if node['left'].get('type') == 'VariableDeclaration' else self.bind_unknown(node['left'])
            self.branch(node['body'])
            self.env.pop()
        elif kind in {'ReturnStatement', 'ThrowStatement'}:
            self.eval(node.get('argument'))
            return True
        elif kind == 'ImportDeclaration':
            self.record('calls', node, 'unresolved', kind='import_unfollowed', source_refs=[], callee_flow='unresolved')
        elif kind not in {'EmptyStatement', 'BreakStatement', 'ContinueStatement'}:
            # A statement we cannot transfer may overwrite any local value.
            for env in self.env:
                for name in env:
                    env[name] = Value(uncertain=True)
        # Classes, switches, with and unknown statements withhold inference.
        return False

    def run(self, tree):
        self.hoist(tree)
        self.block(tree.get('body', []), fresh=False)

    def hoist(self, node):
        if not isinstance(node, dict) or node.get('type') in FUNCTIONS:
            return
        if node.get('type') == 'VariableDeclaration' and node.get('kind') == 'var':
            for decl in node['declarations']:
                if decl['id'].get('type') == 'Identifier':
                    self.env[0][decl['id']['name']] = Value(uncertain=True)
        for v in node.values():
            if isinstance(v, dict):
                self.hoist(v)
            elif isinstance(v, list):
                for item in v:
                    self.hoist(item)
