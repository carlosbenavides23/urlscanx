# Understanding passive analysis

```sh
urlscanx <scan> --analyze
urlscanx <scan> --analyze --verbose
urlscanx <scan> --analyze --json
```

Analysis uses preserved Result metadata, DOM markup and script/body bytes available
in supported inputs. It never visits the target, resolves target DNS, fetches
external scripts, executes JavaScript, follows extracted links or submits values.
The CLI retrieves scan artifacts through urlscan.io; analysis itself is passive.
A script URL or hash alone is not source code.

## Reading the report

Normal output contains:

1. Analysis summary.
2. Primary analyst findings, with excluded contradictory/unreachable/truncated
   evidence presented separately.
3. Input and interaction overview.
4. Request and payload evidence summary.
5. Notable static JavaScript evidence.
6. Runtime observations.
7. Coverage and limitations.

Normal output shows up to eight primary findings with an explicit count. Verbose
retains all bounded findings, individual interaction records, typed references,
path variants and evidence locations. Display groups for repeated prefills,
navigation declarations or bodies do not merge structured records or prove
hidden-value equality. Coverage truncation remains visible in the summary.

Findings combine supported sensitive-semantic input flows with request sinks and
any supported runtime/interaction evidence. Ordering reflects evidence support,
not severity. Unknown targets remain unresolved. No phishing score, verdict or
attribution is produced.

## Keep the evidence boundaries separate

| Evidence | What it establishes | What it does not establish |
| --- | --- | --- |
| Static flow | Supported dependency in preserved code | Runtime execution or transmission |
| Declared function/handler | Code or handler declaration | Invocation or a user action |
| Compatible runtime request | Supported endpoint/method relationship | A particular source read or value |
| Payload correspondence | Compatible preserved field structure | Source-value equality or backend receipt |
| Stage association | Supported markup/static relationship | Stage execution or user sequence |
| Retry/navigation declaration | Supported static declaration | Actual retry, completed request or navigation |

Conditional, unconditional, unresolved, unreachable and truncated paths remain
separate. Runtime relationships can be unavailable, not observed, ambiguous or
contradictory. A positive relationship in one layer does not override a conflict
or missing evidence in another layer.

Preserved JSON, form-urlencoded and supported bounded multipart bodies can expose
field paths, types, name semantics and multiplicity. Values and file contents are
omitted. Parsed, empty, unavailable, unsupported, malformed and truncated bodies
are distinct states.

## Coverage

| State | Meaning |
| --- | --- |
| unavailable | Required preserved evidence is absent or unusable |
| not observed | Inspected evidence contains no supported observation |
| unresolved | Available facts cannot establish the relationship |
| ambiguous | Multiple supported candidates remain |
| contradictory | Supported static/runtime facts conflict |
| truncated | A declared inspection or synthesis budget was exhausted |

**Not observed does not mean nonexistent.** Counts describe the preserved or
inspected subset. Findings synthesis can finish within its own budget while
lower-layer inspection remains partial. Available empty collections and unavailable
inventories must not be interpreted as the same thing.

## JSON

`--analyze --json` returns these top-level fields:

| Field | Contents |
| --- | --- |
| `schema_version` | `1.0` |
| `metadata` | Scan identity, source time, package/ruleset and provenance metadata |
| `result` | Unchanged raw Result API data; may contain sensitive values |
| `analysis` | Full bounded derived inventories, coverage, evidence, flows, relationships and findings |

JSON keeps structured enums, IDs and refs; human wording and truncation do not
remove model facts. `*_refs` refer to lower evidence/object identities; request
refs use Result JSON pointers. Finding IDs reflect static identity within the
ruleset; runtime support alone does not change that static identity.

For identical artifacts and ruleset, serialization and ordering are deterministic.
`metadata.analyzed_at` defaults to **null**: no local wall-clock timestamp is
injected. Python callers may explicitly provide it. `scan_time` is source-derived.
`--verbose` does not change JSON. The saved `analysis.json` is derived-only and
refers to the separately saved raw `result.json`.

This is the accepted pre-1.0 JSON contract for package 0.12.0, schema 1.0 and
ruleset `mvp-b.7`; it does not promise a stable 1.x API.

## Intentional limits

The supported bounded passive scope is complete. It does not include arbitrary
framework/browser execution, missing imported-module recovery, dynamic eval/code
generation, general path solving, async causality, arbitrary obfuscation recovery,
runtime browser mutation, exact source-value matching, provider ownership,
endpoint verification, or comparison of composed findings. DOM parsing is not a
browser simulation. Brand/presentation vocabulary does not establish impersonation
or administrative ownership.
