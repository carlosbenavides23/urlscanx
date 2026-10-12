"""Offline JavaScript artifact inventory and bounded AST frontend.

No loader, evaluation, import following, or target access exists in this module.
"""
from __future__ import annotations

import hashlib
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import esprima

from .adapters import label, mapping, origin, safe_url
from .dom import MAX_DOM_BYTES, MAX_DEPTH as MAX_HTML_DEPTH, VOID_TAGS
from .model import EvidenceCoverage

MAX_SCRIPTS = 64
MAX_SCRIPT_BYTES = 128 * 1024
MAX_TOTAL_BYTES = 512 * 1024
MAX_AST_NODES = 20_000
MAX_TOKENS = 20_000
MAX_NESTING = 48
MAX_RECORDS = 2_000
MAX_FLOWS = 256
MAX_TRANSFORMS = 24
MAX_STRING = 256
JS_TYPES = frozenset({'', 'text/javascript', 'application/javascript', 'module'})


class BudgetExceeded(Exception):
    """Withhold an incomplete script rather than infer from a corrupt prefix."""


def advance_position(position, text):
    """HTMLParser counts LF once (including CRLF); columns are zero-based."""
    line, column = position
    newlines = text.count('\n')
    return {'line':line + newlines, 'column':len(text.rsplit('\n',1)[-1]) if newlines else column + len(text)}


class Scripts(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.stack = []
        self.entries = []
        self.current = None
        self.total = 0
        self.skipped = 0

    def handle_starttag(self, tag, attrs):
        if len(self.stack) >= MAX_HTML_DEPTH:
            raise BudgetExceeded('HTML depth budget')
        if tag == 'script':
            if len(self.entries) >= MAX_SCRIPTS:
                self.skipped += 1
                self.current = None
            else:
                values = dict(attrs)
                self.current = {'kind': 'inline', 'location': {'line': self.getpos()[0], 'column': self.getpos()[1]},
                                'body_location': advance_position(self.getpos(),self.get_starttag_text()),
                                'type': (values.get('type') or '').strip().lower(), 'src': values.get('src'),
                                'inert': any(t in {'template', 'noscript'} for t in self.stack),
                                'ordered': not values.get('src') and 'async' not in values and 'defer' not in values,
                                'body': '', 'budget': False}
                self.entries.append(self.current)
        if tag not in VOID_TAGS:
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if tag == 'script':
            self.current = None
        if tag in self.stack:
            del self.stack[len(self.stack) - 1 - self.stack[::-1].index(tag):]

    def handle_data(self, data):
        if self.current is None or self.current['budget'] or self.current['src']:
            return
        size = len(data.encode('utf-8'))
        self.total += size
        if len(self.current['body'].encode('utf-8')) + size > MAX_SCRIPT_BYTES or self.total > MAX_TOTAL_BYTES:
            self.current.update(body='', budget=True)
        else:
            self.current['body'] += data


def parse(body: str, module: bool) -> tuple[dict, int]:
    """Token/depth guard before parsing; node delegate aborts AST construction."""
    # Tokenization is lexical only. All semantic inference uses the AST.
    tokens = esprima.tokenize(body)
    if len(tokens) > MAX_TOKENS:
        raise BudgetExceeded('token budget')
    nesting = 0
    for token in tokens:
        if token.type == 'Punctuator':
            if token.value in {'(', '[', '{', '${'}:
                nesting += 1
                if nesting > MAX_NESTING:
                    raise BudgetExceeded('syntax nesting budget')
            elif token.value in {')', ']', '}'}:
                nesting = max(0, nesting - 1)
    count = 0

    def delegate(node, metadata):
        nonlocal count
        count += 1
        if count > MAX_AST_NODES:
            raise BudgetExceeded('AST node budget')

    tree = (esprima.parseModule if module else esprima.parseScript)(body, loc=True, range=True, delegate=delegate)
    # Refuse excessive expression depth even if its tokens have few brackets.
    pending = [(tree, 0)]
    while pending:
        value, depth = pending.pop()
        if depth > MAX_NESTING:
            raise BudgetExceeded('AST depth budget')
        if hasattr(value, '__dict__'):
            pending.extend((v, depth + 1) for k, v in vars(value).items() if k not in {'loc', 'range'})
        elif isinstance(value, list):
            pending.extend((v, depth) for v in value)
    return tree.toDict(), count


def target_url(value, document_url, base_present):
    if not isinstance(value, str) or len(value) > MAX_STRING or value != value.strip():
        return None
    try:
        parsed = urlsplit(value)
        if base_present and not parsed.scheme:
            return None
        resolved = urljoin(document_url or '', value)
        return resolved if origin(resolved) else None
    except ValueError:
        return None


def endpoint(value):
    parts = origin(value)
    if parts is None:
        return None
    return (*parts, urlsplit(value).path or '/')


def load_identity(entry, entries, events, document_url, parser, incomplete_references):
    """A supplied body is not a load. Resolve only deterministic preserved identity."""
    key = correlation.exact_target(entry.get('src'))
    frame = entry.get('frame_id')
    if key is None or incomplete_references:
        return False, frame, entry.get('load_request_ref')
    loads = [e for e in events if e.resource_type == 'Script' and correlation.exact_target(e.raw_url) == key
             and correlation.context_relation(e,entry.get('document_url'),frame) != 'context_mismatch']
    # A Result-attached body names its exact load. An archive body can map by
    # URL/document only when a single compatible preserved load exists.
    mapped = next((e for e in loads if e.pointer == entry.get('load_request_ref')),None)
    if mapped is None and entry['kind'] == 'archived' and len(loads) == 1:
        mapped = loads[0]
        frame = mapped.frame_id
    if mapped is None or len(loads) != 1:
        return False, frame, entry.get('load_request_ref')
    references = []
    if not entry.get('document_url') or correlation.exact_target(entry['document_url']) == correlation.exact_target(document_url):
        for reference in entries:
            if reference['kind'] != 'inline' or not reference.get('src'):
                continue
            reference_key = correlation.exact_target(reference['src'])
            if reference_key is None:
                reference_key = correlation.exact_target(target_url(reference['src'],document_url,parser is None or parser.base_href_present))
            if reference_key is None:
                return False, frame, mapped.pointer  # unresolved reference could be another load
            if reference_key == key:
                references.append(reference)
    if len(references) > 1:
        return False, frame, mapped.pointer
    # Competing supplied bodies also leave artifact-to-load identity unresolved.
    bodies = [e for e in entries if e.get('body') is not None and e['kind'] != 'inline'
              and correlation.exact_target(e.get('src')) == key
              and (not frame or not e.get('frame_id') or frame == e['frame_id'])]
    return len(bodies) == 1, frame, mapped.pointer


def inventory(result, dom, parser, events, document_url, registry, archived_scripts=(), interaction=None):
    output = registry.analysis
    js = output.javascript
    js['budgets'] = {'scripts': MAX_SCRIPTS, 'bytes_per_script': MAX_SCRIPT_BYTES, 'total_bytes': MAX_TOTAL_BYTES,
                     'ast_nodes_per_script': MAX_AST_NODES, 'tokens_per_script': MAX_TOKENS, 'nesting': MAX_NESTING,
                     'records': jsflow.MAX_RECORDS, 'flows': jsflow.MAX_FLOWS, 'transforms_per_flow': jsflow.MAX_TRANSFORMS,
                     'string_chars': MAX_STRING, 'abstract_value_nodes': jsflow.MAX_VALUE_NODES,
                     'operations_per_script': jsflow.MAX_OPERATIONS}
    js['budgets'].update(call_depth=interprocedural.MAX_CALL_DEPTH, call_edges=interprocedural.MAX_CALL_EDGES,
                         resolved_invocations=interprocedural.MAX_INVOCATIONS,
                         argument_mappings=interprocedural.MAX_ARGUMENT_MAPPINGS, return_propagations=interprocedural.MAX_RETURNS,
                         cross_scope_steps=interprocedural.MAX_CROSS_STEPS,
                         static_property_depth=interprocedural.MAX_STATIC_PROPERTY_DEPTH)
    js['budgets'].update(path_predicates_per_flow=paths.MAX_PREDICATES, branch_depth=paths.MAX_BRANCH_DEPTH,
                         path_variants_per_scope=paths.MAX_VARIANTS_SCOPE, path_variants_total=paths.MAX_VARIANTS_TOTAL)
    js['budgets'].update(initiator_frames=correlation.MAX_INITIATOR_FRAMES,
                         request_contexts_per_sink=correlation.MAX_REQUEST_CONTEXTS_PER_SINK,
                         request_contexts_total=correlation.MAX_REQUEST_CONTEXTS_TOTAL)
    entries = []
    extraction_failure = None
    if isinstance(dom, bytes) and len(dom) <= MAX_DOM_BYTES:
        try:
            extractor = Scripts()
            extractor.feed(dom.decode('utf-8'))
            extractor.close()
            if extractor.current is not None:
                extractor.current['budget'] = True
                extraction_failure = 'Unterminated script; incomplete source withheld'
            entries = extractor.entries
            js['skipped_scripts'] += extractor.skipped
        except (UnicodeDecodeError, BudgetExceeded, RecursionError, AssertionError, ValueError):
            extraction_failure = 'DOM script extraction invalid or exceeds integrity budget'
    # Result API normally supplies metadata, not script bytes. Accept only an
    # explicit response.body string for a Script resource; never decode guessing.
    requests = mapping(mapping(result).get('data')).get('requests')
    if isinstance(requests, list):
        for event in events:
            if event.resource_type != 'Script':
                continue
            entry = mapping(requests[event.index])
            response = mapping(entry.get('response'))
            body = response.get('body')
            if isinstance(body, str) and not response.get('base64Encoded'):
                entries.append({'kind': 'external_preserved', 'body': body, 'src': event.raw_url,
                                'document_url': event.document_url,
                                'frame_id': event.frame_id,
                                'load_request_ref': event.pointer,
                                'location': {'json_pointer': event.pointer + '/response/body'}, 'type': '',
                                'inert': False, 'budget': False})
            else:
                entries.append({'kind': 'external', 'body': None, 'src': event.raw_url,
                                'document_url': event.document_url,
                                'frame_id': event.frame_id, 'load_request_ref': event.pointer,
                                'location': {'json_pointer': event.pointer}, 'type': '', 'inert': False, 'budget': False})
    # Explicit caller-supplied archive bodies only; no filesystem loader or CLI
    # fetching capability. Classic/module type and document relation are explicit.
    for index, supplied in enumerate(archived_scripts):
        if index >= MAX_SCRIPTS:
            js['skipped_scripts'] += 1
            break
        if isinstance(supplied, dict) and isinstance(supplied.get('body'), str):
            entries.append({'kind': 'archived', 'body': supplied['body'], 'src': supplied.get('url'),
                            'document_url': supplied.get('document_url'),
                            'location': {'archive_index': index}, 'type': supplied.get('type') if isinstance(supplied.get('type'), str) else '',
                            'inert': False, 'budget': False})
    js['skipped_scripts'] += max(0, len(entries) - MAX_SCRIPTS)
    # Cross-script constants require an entirely known ordered classic inline
    # sequence. External, module and asynchronous boundaries disable sharing.
    ordered = bool(entries) and not extraction_failure and not js['skipped_scripts'] and all(
        e['kind'] == 'inline' and e.get('ordered') and e['type'] in JS_TYPES - {'module'} and not e['inert']
        and not e['budget'] for e in entries)
    prepared = {}
    declarations = {}
    if ordered:
        prepared_bytes = 0
        for i, e in enumerate(entries):
            try:
                if len(e['body']) > MAX_SCRIPT_BYTES:
                    ordered = False
                    break
                byte_count = len(e['body'].encode('utf8'))
                prepared_bytes += byte_count
                if byte_count > MAX_SCRIPT_BYTES or prepared_bytes > MAX_TOTAL_BYTES:
                    ordered = False
                    break
                prepared[i] = parse(e['body'], False)
                for statement in prepared[i][0].get('body', []):
                    names = [d['id'].get('name') for d in statement.get('declarations', [])]
                    if statement.get('id'):
                        names.append(statement['id'].get('name'))
                    for name in names:
                        if name:
                            declarations[name] = declarations.get(name, 0) + 1
            except (BudgetExceeded, esprima.Error, RecursionError, ValueError, TypeError, UnicodeEncodeError):
                ordered = False
                break
    globals_out = {}
    total = 0
    for index, entry in enumerate(entries[:MAX_SCRIPTS]):
        body = entry['body']
        external = bool(entry.get('src')) and entry['kind'] == 'inline' or entry['kind'] == 'external'
        unavailable = external or body is None
        body = None if unavailable else body
        invalid_encoding = False
        encoded = None
        oversized = body is not None and len(body) > MAX_SCRIPT_BYTES
        if body is not None and not oversized:
            try:
                encoded = body.encode('utf-8')
            except UnicodeEncodeError:
                invalid_encoding = True
        size = len(encoded) if encoded is not None else None
        total += size or 0
        truncated = entry['budget'] or oversized or size is not None and (size > MAX_SCRIPT_BYTES or total > MAX_TOTAL_BYTES)
        artifact_key = 'dom' if entry['kind'] == 'inline' else 'result'
        if entry['kind'] == 'archived':
            artifact_key = 'js_archive_' + str(index)
            registry.artifacts[artifact_key] = 'js:sha256:' + hashlib.sha256(encoded).hexdigest() if encoded is not None else 'js:uninspected:' + str(index)
        # Result provenance uses its own JSON pointer, independent of DOM scripts.
        loc = entry['location'] | ({'script_index': index} if entry['kind'] == 'inline' else {})
        ref = registry.add(artifact_key, 'static_code', 'artifact_unavailable' if unavailable else 'declared', loc,
                           'JavaScript artifact reference; execution not established')
        artifact_id = registry.identifier('js-artifact', [ref])
        js['artifacts'].append({'id': artifact_id, 'script_ref': None, 'artifact_ref': registry.artifacts[artifact_key],
                                'location': loc, 'evidence_refs': [ref], 'state': 'artifact_unavailable' if unavailable else 'declared',
                                'kind': 'external' if external else entry['kind'], 'url': safe_url(entry.get('src')),
                                'byte_count': size, 'limitations': ['Only supplied bytes; no script fetching.']})
        same_document = entry['kind'] == 'inline' or document_url is not None and entry.get('document_url') == document_url
        script = {'id': registry.identifier('js-script', [ref]), 'artifact_ref': artifact_id, 'location': loc,
                  'body_location': entry.get('body_location'), 'evidence_refs': [ref], 'state': 'declared',
                  'kind': 'external' if external else entry['kind'], 'document_relation': 'captured_document' if same_document else 'unresolved',
                  'artifact_hash': hashlib.sha256(encoded).hexdigest() if encoded is not None and not entry['budget'] else None,
                  'parser': 'esprima2-6.0.0', 'parser_status': 'unavailable' if unavailable else 'skipped',
                  'parse_error': None, 'truncated': bool(truncated), 'code_analyzed': False,
                  'budget_reason': 'Script bytes, total bytes or extraction integrity budget' if truncated else None,
                  'script_type': label(entry['type']), 'execution': 'not_performed', 'limitations': []}
        js['artifacts'][-1]['script_ref'] = script['id']
        js['scripts'].append(script)
        if unavailable:
            script['state'] = 'artifact_unavailable'
            continue
        if invalid_encoding:
            script.update(parser_status='failed', state='unresolved', parse_error='Invalid script Unicode; source omitted.')
            continue
        if entry['inert'] or entry['type'] not in JS_TYPES:
            script['limitations'].append('Inert markup or non-JavaScript data block; not analyzed.')
            continue
        if truncated:
            script.update(parser_status='budget_exceeded', state='unresolved')
            continue
        sizes = {k: len(js[k]) for k in ('sources', 'transforms', 'sinks', 'flows', 'runtime_joins', 'runtime_correlations', 'path_conditions', 'calls', 'functions', 'call_edges')}
        stats = dict(js['interprocedural'])
        path_stats = dict(js['path_analysis'], reasons=list(js['path_analysis']['reasons']))
        evidence_size = len(output.evidence)
        interaction_size = len(interaction.raw) if interaction else 0
        try:
            tree, count = prepared[index] if index in prepared else parse(body, entry['type'] == 'module')
            script.update(parser_status='parsed', ast_nodes=count)
            engine_type = interactions.InteractionFlowEngine if interaction else paths.PathFlowEngine
            engine = engine_type(js, registry, script, artifact_key, parser if same_document else None,
                                document_url if same_document else entry.get('document_url'), events,
                                globals_in=globals_out if ordered else None,
                                **({'interaction': interaction} if interaction else {}))
            engine.script_url = entry.get('src')
            engine.unique_script_url, engine.script_frame_id, script['load_request_ref'] = load_identity(
                entry, entries, events, document_url, parser, extraction_failure or js['skipped_scripts'])
            engine.run(tree)
            script['code_analyzed'] = True
            script['intraprocedural_analysis'] = 'complete'
            if ordered:
                # Only plain const configuration, never DOM taint or function
                # bodies, crosses scripts. Competing declarations stay unknown.
                exports = {}
                for statement in tree.get('body', []):
                    for d in statement.get('declarations', []):
                        name = d['id'].get('name')
                        if name:
                            exports[name] = jsflow.Value(uncertain=True)
                    if statement.get('id', {}).get('name'):
                        exports[statement['id']['name']] = jsflow.Value(uncertain=True)
                    if statement.get('type') == 'VariableDeclaration' and statement.get('kind') == 'const':
                        for d in statement['declarations']:
                            name = d['id'].get('name')
                            value = engine.lookup(name) if name else None
                            if name and declarations.get(name) == 1 and name not in engine.unsafe_names and engine.static_value(value) and value.entity is None:
                                support = engine.record('calls', d, 'referenced', kind='ordered_static_configuration',
                                                        binding=label(name), source_refs=[], callee_flow='not_applicable')
                                exports[name] = engine.clone(value)
                                exports[name].evidence = tuple(support['evidence_refs'])
                globals_out = {name: engine.lookup(name) if name not in engine.unsafe_names and engine.static_value(engine.lookup(name)) else jsflow.Value(uncertain=True)
                               for name in globals_out}
                globals_out.update(exports)
                # Explicit writes and hoisted var shadows are global state even
                # when no direct top-level declaration was exported above.
                for name in jsflow.BUILTINS:
                    if name in engine.env[0]:
                        globals_out[name] = jsflow.Value(uncertain=True)
        except BudgetExceeded as exc:
            script.update(parser_status='budget_exceeded', truncated=True, state='unresolved', budget_reason=str(exc))
        except (esprima.Error, RecursionError, ValueError, TypeError, OverflowError):
            # Parser exceptions can quote sensitive source text. Never echo them.
            script.update(parser_status='failed', state='unresolved', parse_error='Unsupported or malformed JavaScript; source omitted.')
        if not script['code_analyzed']:
            if interaction:
                del interaction.raw[interaction_size:]
            script['intraprocedural_analysis'] = 'withheld'
            for category, length in sizes.items():
                del js[category][length:]
            del output.evidence[evidence_size:]
            js['interprocedural'] = stats
            js['path_analysis'] = path_stats
            globals_out = {}
            ordered = False
    states = [s['parser_status'] for s in js['scripts']]
    # Repeated static contexts may join the same captured request. Its evidence
    # identity is intentionally shared; retain one record for each exact ID.
    output.evidence[:] = list({e.id: e for e in output.evidence}.values())
    source_records = {s['id']: s for s in js['sources']}
    sink_records = {s['id']: s for s in js['sinks']}
    for edge in js['call_edges']:
        supported_flows = [f for f in js['flows'] if edge['id'] in f.get('call_edge_refs', [])]
        edge['flow_refs'] = [f['id'] for f in supported_flows]
        edge['source_evidence_refs'] = sorted({ref for f in supported_flows for ref in source_records[f['source_id']]['evidence_refs']})
        edge['sink_evidence_refs'] = sorted({ref for f in supported_flows for ref in sink_records[f['sink_id']]['evidence_refs']})
    js['truncated'] = js['truncated'] or bool(js['skipped_scripts']) or any(s['truncated'] for s in js['scripts'])
    js['execution'] = 'not_performed'
    js['limitations'] = ['JavaScript not executed.', 'Unavailable external scripts not fetched.',
                         'Only bounded explicit local helpers; imported and mutable closure flows unsupported.',
                         'Static flow does not establish submission, receipt or payload equality.']
    output.evidence_coverage['javascript'] = EvidenceCoverage(
        'available' if entries else 'unavailable',
        'partial' if extraction_failure or js['truncated'] or any(s != 'parsed' for s in states) else 'complete' if states else 'not_run',
        len(states), reason=extraction_failure or 'Limited static syntax and local flow subset; execution not performed',
        skipped_count=js['skipped_scripts'],
        details={'parsed': states.count('parsed'), 'unparsed': states.count('failed'), 'unavailable': states.count('unavailable'),
                 'skipped': states.count('skipped'), 'budget_exceeded': states.count('budget_exceeded'),
                 'execution': 'not_performed', 'flow_scope': 'bounded local helpers and ordered inline constants',
                 'functions_indexed': len(js['functions']), 'call_sites': len(js['call_edges']),
                 'calls_resolved': sum(e['call_resolution'] == 'resolved' for e in js['call_edges']),
                 'calls_unresolved': sum(e['call_resolution'] == 'unresolved' for e in js['call_edges']),
                 'depth_limit': interprocedural.MAX_CALL_DEPTH, 'cycles_truncated': js['interprocedural']['cycles_truncated'],
                 'interprocedural_truncated': js['interprocedural'].get('truncated', False),
                 'interprocedural_reasons': js['interprocedural'].get('reasons', []),
                 'path_analysis': js['path_analysis'],
                 'runtime_correlation': {'contexts_retained':sum(len(c['requests']) for c in js['runtime_correlations']),
                                         'truncated_sinks':sum(c['requests_truncated'] for c in js['runtime_correlations'])},
                 'intraprocedural_analysis': 'complete' if states and all(s == 'parsed' for s in states) else 'partial',
                 'external_bodies': 'partial' if any(s['kind'] == 'external_preserved' for s in js['scripts']) else 'unavailable'})


# Load trusted Python code before entering the guarded no-I/O analysis boundary.
# jsflow imports the constants above; neither module loads supplied script files.
from . import jsflow  # noqa: E402
from . import interprocedural  # noqa: E402
from . import paths  # noqa: E402
from . import correlation  # noqa: E402
from . import interaction as interactions  # noqa: E402
FlowEngine = jsflow.FlowEngine
