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
```

`<scan>` is a UUID or `https://urlscan.io/result/<UUID>/`.

Human-readable views shorten long values and redact likely URL credentials with a short SHA-256 fingerprint. `--verbose` shows all console messages (or all comparison entries). `--json` and saved `result.json` keep the complete API response.

Comparison labels use observed request methods, form actions, and resource types. They describe technical context, not attribution.

## Saving scans

Nothing is persisted by default. `--save` creates `urlscanx-output/<UUID>/` with `result.json` and `report.txt`, plus `dom.html` and `screenshot.png` when urlscan has those assets available.
Saved `result.json` and `dom.html` retain raw evidence, including any sensitive values present in the scan.

## License

MIT.
