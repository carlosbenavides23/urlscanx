"""Bounded local call transfer; no execution, dispatch guessing or module loader."""
from .jsflow import FlowEngine, Value, FUNCTIONS, MUTABLE, BUILTINS, joined, key
from .adapters import label
from .javascript import BudgetExceeded

MAX_CALL_DEPTH = 3
MAX_CALL_EDGES = 256
MAX_INVOCATIONS = 64
MAX_ARGUMENT_MAPPINGS = 256
MAX_RETURNS = 128
MAX_CROSS_STEPS = 8
MAX_STATIC_PROPERTY_DEPTH = 4


class InterproceduralLimit(Exception):
    """Withhold this invocation; safe local analysis can continue."""


class BoundedFlowEngine(FlowEngine):
    def __init__(self, *args, globals_in=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.env[0].update(globals_in or {})
        self.definitions = {}
        self.active_calls = []
        self.return_value = None
        self.return_ambiguous = False
        self.conditional = 0
        self.unsafe_names = set()
        self.failed_calls = set()
        self.current_function = None
        self.global_shadows = set()

    def soft_limit(self, reason):
        self.js['truncated'] = True
        coverage = self.js['interprocedural']
        coverage['truncated'] = True
        coverage.setdefault('reasons', [])
        if reason not in coverage['reasons']:
            coverage['reasons'].append(reason)
        self.script['interprocedural_truncated'] = True
        reasons = self.script.setdefault('interprocedural_reasons', [])
        if reason not in reasons:
            reasons.append(reason)
        self.failed_calls.update(e['id'] for e in self.active_calls)

    def lookup(self, name):
        if self.scope == 'script' and name in self.global_shadows and not any(name in env for env in self.env[1:]):
            return Value(uncertain=True)
        return super().lookup(name)

    def path(self, node):
        if node.get('type') == 'MemberExpression' and node.get('object', {}).get('type') == 'Identifier' and node['object']['name'] == 'window':
            prop = key(node['property']) if not node.get('computed') or node['property'].get('type') == 'Literal' else None
            if prop in BUILTINS and self.lookup(prop).entity != ('builtin', prop):
                return None
        return super().path(node)

    def record(self, category, node, state, **details):
        # Same syntax with different argument provenance must never reuse a sink
        # or transform from a declaration-only or another call-site traversal.
        context = ':call:' + ':'.join(e['id'] for e in self.active_calls) if self.active_calls else ''
        original = self.script
        if self.active_calls:
            node = dict(node, range=[*node.get('range', ()), context])
        if category == 'transforms' and details.get('call_edge_ref'):
            tag = [details['call_edge_ref'], details.get('argument_index'), details.get('parameter_name'), details.get('input_source_refs')]
            node = dict(node, range=[*node.get('range', ()), self.registry.identifier('step', tag)], _step_context=tag)
        if context:
            self.script = dict(original, id=original['id'] + context)
        try:
            count = self.record_count
            if category in {'functions', 'call_edges'}:
                self.record_count = 0  # graph budgets do not consume local record allowance
            record = super().record(category, node, state, **details)
        finally:
            if category in {'functions', 'call_edges'}:
                self.record_count = count
            self.script = original
        record['script_ref'] = original['id']
        if self.active_calls:
            record['call_edge_refs'] = [e['id'] for e in self.active_calls]
            record['evidence_refs'] = list(dict.fromkeys(record['evidence_refs'] +
                [ref for e in self.active_calls for ref in e['evidence_refs']]))
        return record

    def location(self, node):
        loc = super().location(node)
        if self.active_calls:
            loc['static_call_context'] = [e['id'] for e in self.active_calls]
        if node.get('_step_context'):
            loc['boundary_context'] = node['_step_context']
        return loc

    def index(self, node, name=None):
        identity = tuple(node.get('range', ()))
        if identity not in self.definitions:
            if len(self.js['functions']) >= MAX_CALL_EDGES:
                self.soft_limit('function index budget')
                return Value(uncertain=True)
            name = name or key(node.get('id') or {})
            record = self.record('functions', node, 'declared', kind='local_function',
                                 name=label(name), parameters=[label(key(p)) for p in node.get('params', [])],
                                 return_relationship='unresolved')
            # Lexical environment references are private, never serialized. Only
            # immutable constants and deterministic functions can cross it.
            self.definitions[identity] = (node, record, list(self.env))
        return Value(entity=('function', identity))

    def static_value(self, value, depth=0):
        return (depth <= MAX_STATIC_PROPERTY_DEPTH and not value.traces and not value.uncertain and
                (value.entity is None or value.entity[0] == 'function') and
                (value.const is not None or value.encoding == 'json_object' or value.entity is not None) and
                all(self.static_value(v, depth + 1) for v in value.props.values()))

    def lexical(self, frames):
        visible = {name: value for env in frames for name, value in env.items()}
        return {name: (self.clone(value) if self.static_value(value) and name not in self.unsafe_names
                       else Value(uncertain=True)) for name, value in visible.items()}

    def block(self, statements, fresh=True):
        if fresh:
            self.env.append({})
        counts = {}
        for statement in statements:
            if statement.get('type') == 'VariableDeclaration' and statement.get('kind') != 'var':
                for d in statement['declarations']:
                    self.bind_unknown(d['id'])
                    if d['id'].get('type') == 'Identifier':
                        counts[d['id']['name']] = counts.get(d['id']['name'], 0) + 1
            if statement.get('type') in {'FunctionDeclaration', 'ClassDeclaration', 'ImportDeclaration'}:
                if statement.get('id'):
                    self.bind_unknown(statement['id'])
                    name = statement['id']['name']
                    counts[name] = counts.get(name, 0) + 1
                for spec in statement.get('specifiers', []):
                    self.bind_unknown(spec['local'])
        for statement in statements:
            if statement.get('type') == 'FunctionDeclaration':
                name = key(statement.get('id') or {})
                value = self.index(statement, name)
                if counts.get(name) == 1:
                    self.assign(name, value, declaration=True)
        duplicates = {name for name, count in counts.items() if count > 1}
        self.unsafe_names.update(duplicates)
        self.process_statements(statements)
        if fresh:
            self.env.pop()

    def process_statements(self, statements):
        for statement in statements:
            if self.statement(statement):
                break

    def function(self, node, handler=False):
        self.index(node)
        identity = tuple(node.get('range', ()))
        if identity in self.visited_functions:
            return
        self.visited_functions.add(identity)
        old = self.env, self.scope, self.execution_context, self.return_value, self.return_ambiguous, self.current_function, self.active_calls
        # Retain Slice 1's declaration-only body analysis; never import caller
        # taint. Safe lexical constants/helpers are the only added outer inputs.
        definition = self.definitions.get(identity)
        frames = definition[2] if definition else list(self.env)
        self.env = [self.lexical(frames), {}]
        self.scope = 'function:' + str(node.get('range', [0])[0])
        self.execution_context = 'handler_declared' if handler else 'declared'
        self.current_function = definition[1]['id'] if definition else None
        self.active_calls = []
        self.return_value = None
        self.return_ambiguous = False
        for param in node.get('params', []):
            self.bind_unknown(param)
        self.hoist(node.get('body', {}))
        try:
            body = node.get('body', {})
            if body.get('type') == 'BlockStatement':
                self.block(body.get('body', []), fresh=False)
            else:
                self.eval(body)
        finally:
            self.env, self.scope, self.execution_context, self.return_value, self.return_ambiguous, self.current_function, self.active_calls = old

    def expression(self, node):
        if node.get('type') == 'AssignmentExpression':
            left = node.get('left', {})
            if left.get('type') == 'MemberExpression' and left.get('object', {}).get('type') == 'Identifier':
                alias = left['object']['name']
                prop = key(left['property']) if not left.get('computed') or left['property'].get('type') == 'Literal' else None
                canonical = (alias == 'window' and self.lookup(alias).entity == ('builtin', 'window') or
                             alias in {'globalThis', 'self'} and not any(alias in env for env in self.env))
                if canonical and prop in BUILTINS:
                    right = self.eval(node.get('right'))
                    self.env[0][prop] = Value(uncertain=True)
                    if self.scope == 'script':
                        self.global_shadows.add(prop)
                    return right
            elif left.get('type') == 'Identifier' and left['name'] in BUILTINS and self.scope == 'script':
                name = left['name']
                if not any(name in env for env in self.env[1:]):
                    self.global_shadows.add(name)
        if node.get('type') in FUNCTIONS:
            self.function(node)
            return self.index(node)
        if node.get('type') == 'ObjectExpression':
            # Nested plain constant config only. Preserve actual receiver aliases
            # so later mutations cannot leave stale copied endpoint properties.
            properties = node.get('properties', [])
            if any(p.get('type') != 'Property' or key(p.get('key',{})) != 'toJSON' and (p.get('computed') or p.get('method') or p.get('kind') != 'init') for p in properties):
                return super().expression(node)
            props = {}
            for p in properties:
                v = self.eval(p['value'])
                name = key(p['key'])
                if name is None or name == '__proto__':
                    return Value(uncertain=True)
                if v.encoding in MUTABLE and self.static_value(v):
                    props[name] = v
                else:
                    # Keep the existing payload mutation/alias rules.
                    from ..display import is_sensitive_name
                    # Fresh nested literals have no escaping aliases. Keep their
                    # shape; nested receiver aliases retain the existing boundary.
                    fresh = bool(v.traces) and p['value'].get('type') in {'ObjectExpression', 'ArrayExpression'}
                    field = Value(uncertain=True) if v.encoding in MUTABLE and not fresh else self.clone(v)
                    if name == 'body' and v.encoding in MUTABLE:
                        props[name] = v
                        continue
                    if is_sensitive_name(name):
                        field.const = None
                    props[name] = self.transform(p, 'object_property', field, field=label(name))
            value = joined(props.values(), encoding='json_object')
            value.props = props
            return self.transform(node, 'object_construction', value)
        if node.get('type') == 'AwaitExpression' and self.active_calls:
            self.eval(node.get('argument'))
            self.return_ambiguous = True
            return Value(uncertain=True)
        return super().expression(node)

    def edge(self, node, definition=None, reason=None):
        if len(self.js['call_edges']) >= MAX_CALL_EDGES:
            self.soft_limit('call edge budget')
            return None
        callee = definition[1] if definition else None
        edge = self.record('call_edges', node, 'referenced' if callee else 'unresolved', kind='static_call',
                           property=callee['id'] if callee else 'unresolved',
                           caller_scope=self.script['id'] + ':' + self.scope,
                           caller_function_id=self.current_function,
                           callee_function_id=callee['id'] if callee else None,
                           callee_name=callee['name'] if callee else None,
                           callee_script_ref=callee['script_ref'] if callee else None,
                           callee_definition_location=callee['location'] if callee else None,
                           call_location=self.location(node), call_resolution='resolved' if callee else 'unresolved',
                           propagation='pending' if callee else 'unresolved', reason=reason,
                           path_condition='conditional' if self.conditional else 'unresolved',
                           argument_mappings=[], runtime_execution='not_established')
        if callee:
            edge['evidence_refs'] = list(dict.fromkeys(edge['evidence_refs'] + callee['evidence_refs']))
        return edge

    def boundary(self, value, node, kind, **details):
        value = self.clone(self.refresh(value))
        if value.props:
            # Put containing-object transforms before the new boundary on each
            # field, rather than re-appending an old construction after a call.
            for child in value.props.values():
                child.traces = {source: tuple(dict.fromkeys((*chain, *value.own_transforms))) for source, chain in child.traces.items()}
            value.props = {name: self.boundary(child, node, kind, **details) for name, child in value.props.items()}
            value.traces = joined(value.props.values()).traces
            value.own_transforms = ()
            return value
        for chain in value.traces.values():
            transforms = {t['id']: t for t in self.js['transforms']}
            if sum(transforms[i]['kind'] in {'call_argument', 'function_parameter', 'function_return', 'function_alias'} for i in chain) >= MAX_CROSS_STEPS:
                raise InterproceduralLimit('cross-scope transform budget')
        value = self.transform(node, kind, value, **details)
        return value

    def sink(self, node, kind, target, body=None, *args, **kwargs):
        extra = [*target.evidence, *(body.evidence if body else ())]
        sizes = {k: len(self.js[k]) for k in ('sinks', 'flows', 'runtime_joins')}
        result = super().sink(node, kind, target, body, *args, **kwargs)
        for category, size in sizes.items():
            for record in self.js[category][size:]:
                record['evidence_refs'] = list(dict.fromkeys(record['evidence_refs'] + extra))
                if category == 'flows':
                    boundary_edges = [t.get('call_edge_ref') for t in self.js['transforms'] if t['id'] in record['transform_ids'] and t.get('call_edge_ref')]
                    record['call_edge_refs'] = list(dict.fromkeys([e['id'] for e in self.active_calls] + boundary_edges))
                    record['support_scope'] = 'interprocedural' if self.active_calls or any(
                        t['id'] in record['transform_ids'] and t['kind'] == 'function_return' for t in self.js['transforms']) else 'intraprocedural'
        return result

    def call(self, node):
        callee_node = node.get('callee', {})
        if node.get('type') == 'CallExpression' and callee_node.get('type') == 'Identifier':
            value = self.lookup(callee_node['name'])
            if value.entity and value.entity[0] == 'function' and callee_node['name'] not in self.unsafe_names:
                definition = self.definitions.get(value.entity[1])
                if definition:
                    args = [self.eval(a) for a in node.get('arguments', [])]
                    return self.invoke(node, definition, args)
        # Existing intrinsics retain their exact transfer and runtime-join rules.
        return super().call(node)

    def unknown_call(self, node, value):
        super().unknown_call(node, value)
        self.edge(node, reason='unsupported or ambiguous callee identity')

    def invoke(self, node, definition, args):
        categories = ('sources', 'transforms', 'sinks', 'flows', 'runtime_joins', 'runtime_correlations', 'calls')
        sizes = {k: len(self.js[k]) for k in categories}
        edge_size = len(self.js['call_edges'])
        state = (self.env, self.scope, self.execution_context, self.return_value,
                 self.return_ambiguous, self.current_function, self.conditional, list(self.active_calls))
        try:
            return self._invoke(node, definition, args)
        except InterproceduralLimit as exc:
            self.env, self.scope, self.execution_context, self.return_value, self.return_ambiguous, self.current_function, self.conditional, self.active_calls = state
            self.soft_limit(str(exc))
            for category, size in sizes.items():
                del self.js[category][size:]
            valid_sources = {s['id'] for s in self.js['sources']}
            for edge in self.js['call_edges'][edge_size:]:
                edge.update(call_resolution='unresolved', propagation='truncated', reason=str(exc))
                edge['argument_mappings'] = []
            for edge in self.js['call_edges']:
                for mapping in edge['argument_mappings']:
                    mapping['source_refs'] = [s for s in mapping['source_refs'] if s in valid_sources]
            self.invalidate(args, self.outer_writes(definition[0]), definition[2])
            return Value(uncertain=True)

    def _invoke(self, node, definition, args):
        body, function, frames = definition
        writes = self.outer_writes(body)
        counters = self.js['interprocedural']
        if counters['resolved_invocations'] >= MAX_INVOCATIONS:
            raise InterproceduralLimit('resolved invocation budget')
        edge = self.edge(node, definition)
        if edge is None:
            raise InterproceduralLimit('call edge budget')
        counters['resolved_invocations'] += 1
        if function['id'] in [e['callee_function_id'] for e in self.active_calls]:
            edge.update(call_resolution='unresolved', propagation='truncated', reason='interprocedural_cycle_detected')
            counters['cycles_truncated'] += 1
            self.failed_calls.update(e['id'] for e in self.active_calls)
            self.soft_limit('interprocedural_cycle_detected')
            self.invalidate(args, writes, frames)
            return Value(uncertain=True)
        if len(self.active_calls) >= MAX_CALL_DEPTH:
            edge.update(propagation='truncated', reason='interprocedural_depth_limit')
            self.failed_calls.update(e['id'] for e in self.active_calls)
            self.soft_limit('interprocedural_depth_limit')
            self.invalidate(args, writes, frames)
            return Value(uncertain=True)
        pending = [body.get('body', {})]
        complex_control = False
        while pending:
            item = pending.pop()
            if isinstance(item, dict):
                if item.get('type') in FUNCTIONS:
                    continue
                complex_control |= item.get('type') in {'TryStatement', 'SwitchStatement', 'WithStatement'}
                pending.extend(v for k, v in item.items() if k not in {'loc', 'range'})
            elif isinstance(item, list):
                pending.extend(item)
        if (complex_control or body.get('generator') or body.get('async') or any(p.get('type') != 'Identifier' for p in body.get('params', []))
                or any(a.get('type') == 'SpreadElement' for a in node.get('arguments', []))):
            edge.update(propagation='unresolved', reason='complex control, async, generator, spread or non-positional parameters unsupported')
            self.invalidate(args, writes, frames)
            return Value(uncertain=True)
        sizes = {k: len(self.js[k]) for k in ('sources', 'transforms', 'sinks', 'flows', 'runtime_joins', 'runtime_correlations', 'calls')}
        old = self.env, self.scope, self.execution_context, self.return_value, self.return_ambiguous, self.current_function, self.conditional
        mapped = []
        for i, arg in enumerate(args[:len(body.get('params', []))]):
            if counters['parameter_propagations'] >= MAX_ARGUMENT_MAPPINGS:
                raise InterproceduralLimit('argument mapping budget')
            counters['parameter_propagations'] += 1
            details = {'call_edge_ref': edge['id'], 'argument_index': i,
                       'parameter_name': label(body['params'][i]['name']),
                       'callee_function_id': function['id'], 'callee_definition_location': function['location'],
                       'caller_script_ref': self.script['id'], 'call_location': self.location(node)}
            value = self.boundary(arg, node, 'call_argument', **details)
            if callee_name := key(node.get('callee', {})):
                if callee_name != function['name']:
                    value = self.boundary(value, node, 'function_alias', alias=label(callee_name), **details)
            mapped.append((value, details))
            edge['argument_mappings'].append({'argument_index': i, 'parameter_name': details['parameter_name'],
                'source_refs': sorted(value.traces), 'value': '[omitted]'})
        self.active_calls.append(edge)
        self.env = [self.lexical(frames), {}]
        self.scope = 'function:' + str(body['range'][0])
        self.execution_context = 'statically_reachable_from_call'
        self.current_function = function['id']
        self.return_value = None
        self.return_ambiguous = False
        self.conditional = 0
        for i, param in enumerate(body.get('params', [])):
            value, details = mapped[i] if i < len(mapped) else (Value(uncertain=True), {})
            if value.entity and value.entity[0] in {'builtin', 'function'}:
                value = Value(uncertain=True)
            value = self.boundary(value, param, 'function_parameter', **details)
            value.immutable_binding = None  # a parameter is a new mutable binding
            self.assign(param['name'], value, declaration=True)
        self.hoist(body.get('body', {}))
        try:
            statements = body.get('body', {})
            if statements.get('type') == 'BlockStatement':
                self.block(statements.get('body', []), fresh=False)
            else:
                self.return_value = self.return_expression(statements, self.eval(statements))
            result = self.return_value if self.return_value is not None and not self.return_ambiguous else Value(uncertain=True)
            if edge['id'] in self.failed_calls:
                for category, size in sizes.items():
                    del self.js[category][size:]
                valid_sources = {s['id'] for s in self.js['sources']}
                for pending in self.js['call_edges']:
                    for mapping in pending['argument_mappings']:
                        mapping['source_refs'] = [s for s in mapping['source_refs'] if s in valid_sources]
                edge.update(propagation='truncated', reason=edge['reason'] or 'dependent propagation incomplete')
                result = Value(uncertain=True)
            else:
                edge['propagation'] = 'supported'
        finally:
            self.active_calls.pop()
            self.env, self.scope, self.execution_context, self.return_value, self.return_ambiguous, self.current_function, self.conditional = old
        # Mutable arguments may have changed in the callee. Withhold heap effects
        # in the caller; no stale snapshot or arbitrary mutable heap propagation.
        self.invalidate(args, writes, frames)
        if result.traces or result.props or result.const is not None:
            if counters['return_propagations'] >= MAX_RETURNS:
                raise InterproceduralLimit('return propagation budget')
            counters['return_propagations'] += 1
            result = self.boundary(result, node, 'function_return', call_edge_ref=edge['id'],
                                   callee_function_id=function['id'], callee_definition_location=function['location'],
                                   caller_script_ref=self.script['id'], call_location=self.location(node))
        return result

    def outer_writes(self, function):
        locals_ = {p['name'] for p in function.get('params', []) if p.get('type') == 'Identifier'}
        writes = set()
        pending = [function.get('body', {})]
        while pending:
            node = pending.pop()
            if isinstance(node, dict):
                if node.get('type') in FUNCTIONS:
                    if node.get('id'):
                        locals_.add(node['id']['name'])
                    continue
                if node.get('type') == 'VariableDeclaration':
                    locals_.update(d['id']['name'] for d in node['declarations'] if d['id'].get('type') == 'Identifier')
                if node.get('type') in {'AssignmentExpression', 'UpdateExpression'}:
                    left = node.get('left') or node.get('argument') or {}
                    while left.get('type') == 'MemberExpression':
                        left = left['object']
                    if left.get('type') == 'Identifier':
                        writes.add(left['name'])
                pending.extend(v for k,v in node.items() if k not in {'loc','range'})
            elif isinstance(node, list):
                pending.extend(node)
        return writes - locals_

    def invalidate(self, args, writes, frames):
        for arg in args:
            if arg.encoding in MUTABLE or arg.payload_candidates:
                self.invalidate_value(arg)
        # A helper may write a lexical binding. This slice does not transfer
        # outer heap effects; invalidate potentially written caller bindings.
        for name in writes:
            for i in range(len(frames)-1, -1, -1):
                if name in frames[i]:
                    if frames[i][name].encoding in MUTABLE:
                        self.invalidate_value(frames[i][name])
                    frames[i][name] = Value(uncertain=True)
                    if i < len(self.env) and name in self.env[i]:
                        self.env[i][name] = Value(uncertain=True)
                    break

    def mutable_children(self, value):
        seen, result, pending = set(), [], list(value.props.values())
        while pending:
            child = pending.pop()
            self.step()
            if id(child) in seen:
                continue
            seen.add(id(child))
            if child.encoding in MUTABLE:
                result.append(child)
                pending.extend(child.props.values())
        return result

    def invalidate_value(self, value):
        for child in self.mutable_children(value):
            child.props.clear(); child.traces.clear(); child.const = None; child.entity = None; child.uncertain = True
        value.props.clear(); value.payload_candidates.clear(); value.traces.clear(); value.const = None; value.entity = None; value.uncertain = True

    def escape(self, value):
        self.invalidate_value(value)

    def return_expression(self, node, value):
        edge = self.active_calls[-1]
        support = self.record('calls', node, 'referenced', kind='function_return_expression',
                              source_refs=sorted(value.traces), callee_flow='static_expression',
                              callee_function_id=self.current_function, call_edge_ref=edge['id'])
        value = self.clone(self.refresh(value))
        value.evidence = tuple(dict.fromkeys((*value.evidence, *support['evidence_refs'])))
        # Also attach callee return syntax to each source chain. Constants retain
        # evidence privately until a later resolved sink consumes them.
        return self.boundary(value, node, 'function_return', call_edge_ref=edge['id'],
                             callee_function_id=self.current_function,
                             callee_definition_location=edge['callee_definition_location'],
                             return_location=self.location(node), caller_script_ref=edge['script_ref'],
                             call_location=edge['call_location'])

    def branch(self, node):
        self.conditional += 1
        try:
            super().branch(node)
        finally:
            self.conditional -= 1

    def statement(self, node):
        kind = node.get('type')
        if kind == 'ReturnStatement' and self.active_calls:
            value = self.eval(node.get('argument'))
            if self.conditional:
                self.return_ambiguous = True
            else:
                self.return_value = self.return_expression(node, value)
            return True
        if kind == 'ThrowStatement' and self.active_calls:
            self.return_ambiguous = True
        if kind == 'FunctionDeclaration':
            name = key(node.get('id') or {})
            if self.scope == 'script' and len(self.env) > 1 and name in BUILTINS and self.script.get('script_type') != 'module':
                # Annex B block functions in classic code have ambiguous global
                # availability; never assume the browser builtin after the block.
                self.global_shadows.add(name)
                self.env[0][name] = Value(uncertain=True)
            self.function(node)
            return False
        if kind == 'VariableDeclaration':
            for declaration in node.get('declarations', []):
                if (declaration.get('init') or {}).get('type') in FUNCTIONS and declaration['id'].get('type') == 'Identifier':
                    self.index(declaration['init'], declaration['id']['name'])
        return super().statement(node)

    def run(self, tree):
        # Writes anywhere make lexical captures/exported constants unsafe, even
        # when their enclosing declaration-only helper has not been invoked.
        pending = [tree]
        while pending:
            item = pending.pop()
            if isinstance(item, dict):
                if item.get('type') in {'AssignmentExpression', 'UpdateExpression'}:
                    left = item.get('left') or item.get('argument') or {}
                    while left.get('type') == 'MemberExpression':
                        left = left['object']
                    if left.get('type') == 'Identifier':
                        self.unsafe_names.add(left['name'])
                pending.extend(v for k, v in item.items() if k not in {'loc', 'range'})
            elif isinstance(item, list):
                pending.extend(item)
        super().run(tree)
        for name in self.global_shadows:
            self.env[0][name] = Value(uncertain=True)
