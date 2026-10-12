"""Bounded static predicates, independent of runtime and payload evidence."""
from contextlib import contextmanager
from copy import copy
from .interprocedural import BoundedFlowEngine
from .jsflow import Value, key, FUNCTIONS
from .adapters import label
from .javascript import target_url
from .correlation import correlate

MAX_PREDICATES = 8
MAX_BRANCH_DEPTH = 8
MAX_VARIANTS_SCOPE = 16
MAX_VARIANTS_TOTAL = 256


def expression_summary(node, depth=0):
    """Small structured syntax only. Literal strings/numbers never survive."""
    kind = node.get('type')
    if depth >= 4:
        return {'kind':'bounded_expression'}
    if kind == 'Identifier':
        return {'kind':'identifier', 'binding':label(node.get('name'))}
    if kind == 'Literal':
        value = node.get('value')
        return {'kind':'literal', 'value':value if isinstance(value,bool) else '[omitted]'}
    if kind == 'UnaryExpression' and node.get('operator') == '!':
        return {'kind':'not', 'operand':expression_summary(node['argument'],depth+1)}
    if kind in {'LogicalExpression','BinaryExpression'} and node.get('operator') in {'&&','||','===','!==','==','!=','<','>','<=','>='}:
        return {'kind':'binary', 'operator':node['operator'],
                'left':expression_summary(node['left'],depth+1), 'right':expression_summary(node['right'],depth+1)}
    return {'kind':kind or 'bounded_expression', 'values':'[omitted]'}


class PathFlowEngine(BoundedFlowEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.predicates = []
        self.path_state = 'unconditional'
        self.branch_depth = 0
        self.loop_context = False
        self.scope_variants = {}

    def truncate_path(self, reason):
        coverage = self.js['path_analysis']
        coverage['truncated'] = True
        if reason not in coverage['reasons']:
            coverage['reasons'].append(reason)
        self.js['truncated'] = True
        self.script['path_analysis_truncated'] = True

    def condition(self, node):
        kind = node.get('type')
        if kind == 'Literal' and isinstance(node.get('value'), bool):
            return node['value']
        if kind == 'Identifier':
            v = self.lookup(node['name'])
            if v.immutable_binding and node['name'] not in self.unsafe_names:
                return v.static_boolean
        if kind == 'UnaryExpression' and node.get('operator') == '!':
            result = self.condition(node['argument'])
            return None if result is None else not result
        if kind == 'LogicalExpression' and node.get('operator') in {'&&', '||'}:
            a, b = self.condition(node['left']), self.condition(node['right'])
            if node['operator'] == '&&':
                return False if a is False or b is False else True if a is True and b is True else None
            return True if a is True or b is True else False if a is False and b is False else None
        return None

    def boolean_initializer(self, node):
        """Primitive booleans only; an unknown function result is not a const fact."""
        kind = node.get('type')
        if kind in {'Literal','Identifier'}:
            return self.condition(node)
        if kind == 'UnaryExpression' and node.get('operator') == '!':
            value = self.boolean_initializer(node['argument'])
            return None if value is None else not value
        if kind == 'LogicalExpression':
            left = self.boolean_initializer(node['left'])
            if left is None:
                return None
            if (node.get('operator') == '||' and left) or (node.get('operator') == '&&' and not left):
                return left
            return self.boolean_initializer(node['right'])
        return None

    def predicate(self, node, polarity, *, loop=False):
        coverage = self.js['path_analysis']
        scope = (self.scope, tuple(e['id'] for e in self.active_calls))
        if len(self.js['path_conditions']) >= MAX_VARIANTS_TOTAL or self.scope_variants.get(scope, 0) >= MAX_VARIANTS_SCOPE:
            self.truncate_path('path variant budget')
            return None
        if len(self.predicates) >= MAX_PREDICATES or self.branch_depth >= MAX_BRANCH_DEPTH:
            self.truncate_path('predicate or branch depth budget')
            return None
        resolution = None if loop else self.condition(node)
        binding_node, binding_polarity = node, polarity
        while binding_node.get('type') == 'UnaryExpression' and binding_node.get('operator') == '!':
            binding_node = binding_node['argument']; binding_polarity = not binding_polarity
        binding = (self.lookup(binding_node['name']).immutable_binding
                   if binding_node.get('type') == 'Identifier' and binding_node['name'] not in self.unsafe_names else None)
        support = self.registry.add(self.artifact, 'static_code', 'referenced',
                                    self.script['location'] | self.location(node) | {'category':'path_condition','polarity':polarity},
                                    'Static control predicate; satisfaction and execution not established')
        record = {'id':self.registry.identifier('js-predicate',[self.script['id'],support,list(self.predicates)]),
                  'script_ref':self.script['id'], 'location':self.location(node), 'evidence_refs':[support]+([binding] if binding else []),
                  'kind':'loop_condition' if loop else 'identifier_truthiness' if binding_node.get('type') == 'Identifier' else
                         'literal_boolean' if node.get('type') == 'Literal' and isinstance(node.get('value'),bool) else 'bounded_expression',
                  'binding':label(binding_node.get('name')) if binding_node.get('type') == 'Identifier' else None,
                  'binding_ref':binding, 'binding_polarity':binding_polarity,
                  'polarity':polarity,'resolution':'true' if resolution is True else 'false' if resolution is False else 'unresolved',
                  'expression_kind':node.get('type'),'literal_values':'[omitted]',
                  'expression':expression_summary(node),
                  'loop_context':loop,'iteration_count':'unresolved' if loop else None}
        if not any(p['id']==record['id'] for p in self.js['path_conditions']):
            self.js['path_conditions'].append(record)
            self.scope_variants[scope] = self.scope_variants.get(scope,0)+1
            coverage['branches_inspected'] += 1
            coverage['conditions_true' if resolution is True else 'conditions_false' if resolution is False else 'conditions_unresolved'] += 1
        return record

    @contextmanager
    def context(self, predicate, *, loop=False):
        old = list(self.predicates), self.path_state, self.branch_depth, self.loop_context
        self.branch_depth += 1
        self.loop_context |= loop
        if predicate is None:
            self.path_state = 'truncated'
        else:
            self.predicates.append(predicate['id'])
            if self.path_state not in {'statically_unreachable', 'truncated'}:
                truth = predicate['resolution']
                if truth != 'unresolved' and (truth == 'true') != predicate['polarity']:
                    self.path_state = 'statically_unreachable'
                elif predicate['binding_ref'] and any(p['binding_ref'] == predicate['binding_ref'] and p['binding_polarity'] != predicate['binding_polarity']
                                                       for p in self.js['path_conditions'] if p['id'] in old[0]):
                    self.path_state = 'statically_unreachable'
                elif truth == 'unresolved' and self.path_state == 'unconditional':
                    self.path_state = 'conditional'
        try:
            yield
        finally:
            self.predicates, self.path_state, self.branch_depth, self.loop_context = old

    def record(self, category, node, state, **details):
        # The same syntax can have different path provenance at separate static
        # traversals. Include only non-sensitive predicate identities in evidence.
        node = dict(node, range=[*node.get('range', ()), tuple(self.predicates), self.path_state],
                    _path_context=[list(self.predicates), self.path_state])
        record = super().record(category,node,state,**details)
        record.update(static_path_state=self.path_state, path_condition_refs=list(self.predicates),
                      loop_context=self.loop_context, iteration_count='unresolved' if self.loop_context else None)
        if category == 'call_edges':
            record['inherited_path_condition_refs'] = list(self.predicates)
        record['evidence_refs'] = list(dict.fromkeys(record['evidence_refs'] +
            [e for p in self.js['path_conditions'] if p['id'] in self.predicates for e in p['evidence_refs']]))
        return record

    def location(self, node):
        location = super().location(node)
        if node.get('_path_context'):
            location['static_path_context'] = node['_path_context']
        return location

    def lexical(self, frames):
        visible = {name:value for frame in frames for name,value in frame.items()}
        result = super().lexical(frames)
        for name, value in visible.items():
            if value.immutable_binding and name not in self.unsafe_names:
                result[name].immutable_binding = value.immutable_binding
                result[name].static_boolean = value.static_boolean
        return result

    def assign(self, name, value, declaration=False):
        # Copying a const value into a let/var/parameter does not copy the
        # immutability of its lexical binding. Const support is attached below.
        if value.immutable_binding or value.static_boolean is not None:
            value = copy(value)
            value.immutable_binding = None
            value.static_boolean = None
        super().assign(name,value,declaration)

    def sink(self, node, kind, target, body=None, *args, **kwargs):
        before = len(self.js['flows'])
        sink_before = len(self.js['sinks'])
        result = super().sink(node,kind,target,body,*args,**kwargs)
        raw_url = target_url(target.const,self.document_url,self.parser is None or self.parser.base_href_present)
        for sink in self.js['sinks'][sink_before:]:
            correlate(self.js,self.registry,sink,raw_url,self.events,
                      script_url=getattr(self,'script_url',None), document_url=self.document_url,
                      unique_script_url=getattr(self,'unique_script_url',False), frame_id=getattr(self,'script_frame_id',None))
        predicates = {p['id']:p for p in self.js['path_conditions']}
        for flow in self.js['flows'][before:]:
            records = [r for category in ('sources','transforms','sinks') for r in self.js[category]
                       if r['id'] in [flow['source_id'],flow['sink_id'],*flow['transform_ids']]]
            refs = list(dict.fromkeys(ref for r in records for ref in r.get('path_condition_refs',[])))
            states = {r.get('static_path_state','unresolved') for r in records}
            state = next((s for s in ('statically_unreachable','truncated','unresolved','conditional') if s in states),'unconditional')
            if len(refs) > MAX_PREDICATES:
                self.truncate_path('predicates per flow budget')
                refs = refs[:MAX_PREDICATES]
                state = 'truncated' if state != 'statically_unreachable' else state
            flow.update(static_path_state=state,path_condition_refs=refs,loop_context=any(r.get('loop_context') for r in records))
            flow['evidence_refs'] = list(dict.fromkeys(flow['evidence_refs']+[e for ref in refs for e in predicates[ref]['evidence_refs']]))
        return result

    def function(self, node, handler=False):
        old = self.predicates, self.path_state, self.branch_depth, self.loop_context
        self.predicates, self.path_state, self.branch_depth, self.loop_context = [], 'unconditional', 0, False
        try:
            return super().function(node,handler)
        finally:
            self.predicates, self.path_state, self.branch_depth, self.loop_context = old

    def invoke(self, *args, **kwargs):
        old = list(self.predicates), self.path_state, self.branch_depth, self.loop_context
        try:
            return super().invoke(*args,**kwargs)
        finally:
            self.predicates, self.path_state, self.branch_depth, self.loop_context = old

    def branch_with(self, node, predicate):
        with self.context(predicate):
            if self.path_state == 'statically_unreachable':
                # Inventory dead syntax without contaminating live bindings or
                # the callee's supported return value.
                old = self.env, self.return_value, self.return_ambiguous
                self.env = self.clone(self.env)
                try:
                    self.statement(node)
                finally:
                    self.env, self.return_value, self.return_ambiguous = old
            else:
                self.branch(node)

    def expression(self, node):
        kind = node.get('type')
        if kind == 'LogicalExpression':
            self.eval(node['left'])
            p = self.predicate(node['left'],node.get('operator') == '&&')
            self.branch_with({'type':'ExpressionStatement','expression':node['right']},p)
            return Value(uncertain=True)
        if kind == 'ConditionalExpression':
            self.eval(node['test'])
            for polarity,part in ((True,'consequent'),(False,'alternate')):
                self.branch_with({'type':'ExpressionStatement','expression':node[part]},self.predicate(node['test'],polarity))
            return Value(uncertain=True)
        return super().expression(node)

    def terminates(self, node):
        if node.get('type') in {'ReturnStatement','ThrowStatement'}:
            return True
        if node.get('type') == 'BlockStatement':
            for statement in node.get('body',[]):
                if statement.get('type') in {'ReturnStatement','ThrowStatement'}:
                    return True
                if statement.get('type') not in {'VariableDeclaration','ExpressionStatement','EmptyStatement'}:
                    return False
        return False

    def may_exit(self, node):
        if node.get('type') in FUNCTIONS:
            return False
        if node.get('type') in {'ReturnStatement','ThrowStatement'}:
            return True
        return any(self.may_exit(child) for value in node.values()
                   for child in (value if isinstance(value,list) else [value]) if isinstance(child,dict))

    def process_statements(self, statements):
        old = list(self.predicates), self.path_state, self.branch_depth, self.loop_context
        live = None
        try:
            for statement in statements:
                stopped = self.statement(statement)
                if stopped:
                    self.path_state = 'unresolved' if statement.get('type') in {'BreakStatement','ContinueStatement'} else 'statically_unreachable'
                    if live is None:
                        live = self.env, self.return_value, self.return_ambiguous
                        self.env = self.clone(self.env)
                if statement.get('type') == 'IfStatement':
                    then_exit = self.terminates(statement['consequent'])
                    else_exit = self.terminates(statement.get('alternate') or {})
                    if then_exit and else_exit:
                        self.path_state = 'statically_unreachable'
                    elif then_exit or else_exit:
                        p = self.predicate(statement['test'],not then_exit)
                        with self.context(p):
                            updated = list(self.predicates),self.path_state
                        self.predicates,self.path_state = updated
                    elif self.may_exit(statement) and self.path_state not in {'statically_unreachable','truncated'}:
                        self.path_state = 'unresolved'
                elif statement.get('type') == 'BlockStatement' and self.may_exit(statement) and not stopped and self.path_state not in {'statically_unreachable','truncated'}:
                    self.path_state = 'unresolved'
                elif statement.get('type') in {'TryStatement','SwitchStatement','ForStatement','WhileStatement','DoWhileStatement','ForInStatement','ForOfStatement'} and self.path_state not in {'statically_unreachable','truncated'}:
                    self.path_state = 'unresolved'
        finally:
            if live is not None:
                self.env, self.return_value, self.return_ambiguous = live
            self.predicates,self.path_state,self.branch_depth,self.loop_context = old

    def statement(self, node):
        kind = node.get('type')
        if kind == 'BlockStatement':
            super().statement(node)
            return self.terminates(node)
        if kind == 'IfStatement':
            self.eval(node['test'])
            self.branch_with(node['consequent'],self.predicate(node['test'],True))
            if node.get('alternate'):
                self.branch_with(node['alternate'],self.predicate(node['test'],False))
            return False
        if kind in {'ReturnStatement','ThrowStatement'} and self.path_state == 'statically_unreachable':
            self.eval(node.get('argument'))
            return True
        if kind in {'BreakStatement','ContinueStatement'}:
            return True
        if kind in {'ForStatement','WhileStatement','DoWhileStatement','ForOfStatement','ForInStatement'}:
            test = node.get('test') or node.get('right') or {'type':'loop_control'}
            with self.context(self.predicate(test,True,loop=True),loop=True):
                return super().statement(node)
        if kind == 'TryStatement':
            old = self.path_state
            if old not in {'statically_unreachable','truncated'}:
                self.path_state = 'unresolved'
            try:
                super().statement(node)
            finally:
                self.path_state = old
            return False
        result = super().statement(node)
        if kind == 'VariableDeclaration' and node.get('kind') == 'const':
            for declaration in node.get('declarations',[]):
                name = key(declaration['id'])
                if declaration['id'].get('type') != 'Identifier':
                    continue
                value = copy(self.lookup(name))  # metadata only; preserve existing heap semantics
                ref = self.registry.add(self.artifact,'static_code','referenced',self.script['location']|self.location(declaration)|{'binding':label(name)},
                                        'Immutable lexical binding used only as static predicate support')
                value.immutable_binding = ref
                value.static_boolean = self.boolean_initializer(declaration.get('init') or {})
                value.evidence = tuple(dict.fromkeys((*value.evidence,ref)))
                self.env[-1][name] = value
        return result
