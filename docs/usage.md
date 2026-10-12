# Usage

## Scan inputs and modes

A scan can be a UUID or a urlscan.io result URL. The CLI retrieves an existing
completed scan; it does not submit a URL for scanning. Set `URLSCAN_API_KEY` first.
Local Result file paths are not CLI inputs.

| Command | Output |
| --- | --- |
| `urlscanx <scan>` | General human-readable report |
| `urlscanx <scan> --iocs` | Indicator inventory |
| `urlscanx <scan> --requests` | Compact HTTP request inventory |
| `urlscanx <scan> --json` | Complete raw Result API JSON |
| `urlscanx <scan> --analyze` | Passive analysis of preserved evidence |
| `urlscanx <scan> --analyze --json` | Envelope with raw Result and derived analysis |

`--json`, `--iocs` and `--requests` are mutually exclusive. `--analyze` works with
`--json`, `--verbose` and `--save`, but cannot be combined with `--iocs` or
`--requests`. `--verbose` does not change JSON output.

Warnings go to stderr; JSON goes to stdout. For example:

```sh
urlscanx <scan> --analyze --json > analysis-envelope.json
```

## Compare scans

Two scans produce an A/B comparison with shared and per-scan artifacts:

```sh
urlscanx compare <scan1> <scan2>
```

Three or more **distinct** scans produce a frequency report:

```sh
urlscanx compare <scan1> <scan2> <scan3> <scan4> <scan5> --min-shared 3
```

The report distinguishes artifacts present in every scan, subset prevalence such
as `4/5` and `3/5`, and artifacts unique to each scan. Categories include domains,
IPs, URLs, hashes, technologies, external endpoints and submission endpoints.
An exact source value counts once per scan, regardless of repetitions in that scan.
Comparison occurs before display masking and shortening.

`--min-shared N` filters shared groups. It defaults to 2 and must be between 2 and
the number of scans. Per-scan unique sections are independent of this filter.
For two scans, the only valid value is 2. There is no threshold-fraction option.

Normal comparison sections show up to 15 entries; `--verbose` shows all entries
while retaining display protection and long-value shortening. Missing DOM is
optional: submission endpoints still include observed POST/PUT/PATCH requests,
plus available POST form actions. A failing Result retrieval stops comparison.

Overlap is technical evidence. It does not establish common ownership or attribute
the scans to a person or organization. Comparison does not compare composed
analysis findings.

## Save artifacts

```sh
urlscanx <scan> --save
urlscanx <scan> --analyze --save
```

Files are written under `urlscanx-output/<UUID>/`:

| File | Contents |
| --- | --- |
| `result.json` | Complete raw Result JSON |
| `report.txt` | General report |
| `dom.html` | Original DOM bytes, when available and accepted for saving |
| `screenshot.png` | Screenshot, when available |
| `analysis.txt` | Analysis text, with `--analyze` |
| `analysis.json` | Derived analysis envelope referring to `result.json`, with `--analyze` |

An existing output directory causes an error; saving does not overwrite it.
No files are written without `--save`. Optional artifacts may be absent. During
analysis, screenshot retrieval failure does not prevent saving other evidence;
invalid UTF-8 DOM bytes can still be saved unchanged with a warning while DOM
analysis remains unavailable.

Saved Result/DOM and screenshots may contain secrets. The `result` member of
`--analyze --json` is also raw evidence. Store and share them accordingly.

## Display protection

Human-readable URLs protect reusable token-like identifiers. Where an existing
view uses a token fingerprint, it is for high-entropy token-like identifiers.
Password, passwd, OTP, passcode, PIN, code, verification code, authentication code,
CVC/CVV, PAN, card number and security code values use `[omitted]`, never a
secret-value hash. Sensitive names are normalized for case, hyphens and underscores.
This also covers path values following sensitive names and URL userinfo.

Derived analysis additionally protects token-like keys/path segments and omits
query values except supported protocol selectors. Cookie/storage/body values are
not included in derived evidence. Verbose never disables this policy.

## Common errors and partial analysis

- Missing API key: configure `URLSCAN_API_KEY`.
- Invalid scan input: use a UUID or a urlscan.io result URL.
- Result retrieval/format failure: the command fails rather than fabricating evidence.
- Missing or unusable optional DOM/script/body evidence: inspect coverage for the
  affected analysis; absence is not proof that the behavior does not exist.
- Truncation: findings and counts may cover only the inspected subset. Verbose
  exposes the coverage details, but does not rerun analysis with larger budgets.
