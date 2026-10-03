# urlscanx

A small CLI for inspecting and comparing completed urlscan.io scans. It fetches the Result API response and, when available, the DOM for form analysis.

## Install

```sh
pipx install git+https://github.com/carlosbenavides23/urlscanx.git
```

## API key

Create a urlscan.io API key and set it in your environment.

bash/zsh:

```sh
export URLSCAN_API_KEY="..."
```

fish:

```fish
set -Ux URLSCAN_API_KEY "..."
```

## Usage

```sh
urlscanx <scan>
urlscanx <scan> --iocs
urlscanx <scan> --requests
urlscanx <scan> --json
urlscanx <scan> --save
urlscanx <scan> --verbose
urlscanx compare <scan1> <scan2>
urlscanx compare <scan1> <scan2> <scan3>
urlscanx compare <scan1> <scan2> <scan3> <scan4> <scan5> --min-shared 3
urlscanx compare <scan1> <scan2> <scan3> --verbose
```

`<scan>` is a UUID or `https://urlscan.io/result/<UUID>/`.

Human-readable views shorten long values and redact likely URL credentials with a short SHA-256 fingerprint. `--verbose` shows all console messages (or all comparison entries). `--json` and saved `result.json` keep the complete API response.

Comparison labels use observed request methods, form actions, and resource types. They describe technical context, not attribution.

Two scans retain the existing A/B comparison, categorized overlap, and title/IP matches.
Three or more distinct scans use a prevalence report for domains, IPs, URLs, hashes,
technologies, external endpoints, and submission endpoints. Each exact source value
counts once per scan, even if it occurs repeatedly. The report lists artifacts shared
by all scans, subset groups such as `3/5` with scan membership, and per-scan unique artifacts.
Values are compared before display redaction or shortening.

`--min-shared N` filters shared groups (default `2`; valid range `2` through the scan count).
Per-scan unique sections remain visible independently of this filter. Normal comparison
sections show up to 15 entries; `--verbose` shows every entry while retaining URL
redaction and long-value shortening. DOM assets are optional: submission endpoints
include observed POST/PUT/PATCH requests and available POST form actions. A failed
Result API request stops comparison and identifies the failing scan in multi-scan mode.

## Saving scans

Nothing is persisted by default. `--save` creates `urlscanx-output/<UUID>/` with `result.json` and `report.txt`, plus `dom.html` and `screenshot.png` when urlscan has those assets available.
Saved `result.json` and `dom.html` retain raw evidence, including any sensitive values present in the scan.

## License

MIT.
