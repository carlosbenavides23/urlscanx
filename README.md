# urlscanx

A Python CLI for inspecting, comparing and analyzing completed [urlscan.io](https://urlscan.io/) scans.

Use it to review a scan's requests, forms and indicators, find technical overlap
between scans, and inspect supported static JavaScript flows alongside preserved
runtime evidence. `--analyze` works on captured artifacts: it does not visit the
scanned site or execute its JavaScript.

## Install

Requires **Python 3.11 or newer**. Installation includes the pinned Python AST
parser `esprima2==6.0.0`; Node.js is not required.

```sh
pipx install git+https://github.com/carlosbenavides23/urlscanx.git
```

To update an existing installation:

```sh
pipx upgrade urlscanx
```

Alternatively, install in a virtual environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install git+https://github.com/carlosbenavides23/urlscanx.git
```

## Configure your API key

Set `URLSCAN_API_KEY` to your urlscan.io API key.

Bash or zsh:

```sh
export URLSCAN_API_KEY="your-api-key"
```

PowerShell:

```powershell
$env:URLSCAN_API_KEY = "your-api-key"
```

Fish:

```fish
set -Ux URLSCAN_API_KEY "your-api-key"
```

## Quick start

`<scan>` accepts a scan UUID or `https://urlscan.io/result/<UUID>/`.

```sh
urlscanx <scan>                       # General report
urlscanx <scan> --iocs                # Indicator inventory
urlscanx <scan> --requests            # HTTP request inventory
urlscanx <scan> --analyze             # Passive evidence analysis
urlscanx <scan> --analyze --verbose   # Full bounded provenance
urlscanx <scan> --analyze --json      # Raw Result + structured analysis
urlscanx <scan> --analyze --save      # Save evidence and analysis

urlscanx compare <scan1> <scan2>
urlscanx compare <scan1> <scan2> <scan3>
urlscanx compare <scan1> <scan2> <scan3> <scan4> --min-shared 3
```

For a complete option list, run `urlscanx --help` or `urlscanx compare --help`.

## What the reports mean

- **Inspect:** compact scan details, requests, form metadata and browser evidence.
- **Compare:** domains, IPs, URLs, hashes, technologies, external endpoints and
  submission endpoints. Multi-scan prevalence counts presence once per scan.
- **Analyze:** supported input-to-request static flows, bounded helper calls and
  paths, compatible runtime requests, preserved payload field structure, and
  interaction declarations with traceable evidence references.

Static code does not prove execution. A compatible runtime request does not prove
that a particular source value was transmitted. Payload correspondence describes
structure, not value equality. Findings describe technical evidence without a
phishing verdict, risk score or attribution claim. General reports may show
urlscan's own verdicts as provider data.

Unavailable artifacts, unresolved relationships and truncated inspection are
reported explicitly. Missing DOM or request bodies can limit analysis even when
the Result remains available.

## Output and privacy

Normal reports are compact; `--verbose` expands entries and analysis provenance
while retaining secret protection. Human-readable analysis is plain text without
ANSI codes. Raw `--json` returns the complete Result; `--analyze --json` includes
that same raw Result plus derived evidence.

**Raw artifacts can contain sensitive values.** Human and derived analysis views
protect secret-like tokens and omit password/OTP/PIN/card values. That protection
does not sanitize the raw Result, DOM or screenshots.

`--save` writes to `urlscanx-output/<UUID>/`. No files are saved by default.
See [usage and saving](docs/usage.md) for file names and mode combinations.

## Release and limits

Current package: **0.12.0**. Analysis schema: **1.0**. Ruleset: **mvp-b.7**.
The current bounded passive analysis scope is complete. This is a pre-1.0 release;
it does not promise a stable 1.x API. Analysis JSON is deterministic for identical
artifacts and ruleset, with `metadata.analyzed_at=null` by default.

The analyzer does not recover missing imports, execute browser/framework code,
solve arbitrary paths or async behavior, verify endpoints, or establish exact
source-value equality. It creates no new scan and performs no target interaction.

- [Usage, comparison and saved files](docs/usage.md)
- [Understanding analysis evidence and JSON](docs/analysis.md)
- [Development and offline tests](docs/development.md)

## License

[MIT](LICENSE).
