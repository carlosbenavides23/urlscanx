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
urlscanx compare <scan1> <scan2>
```

`<scan>` is a UUID or `https://urlscan.io/result/<UUID>/`.

## Saving scans

Nothing is persisted by default. `--save` creates `urlscanx-output/<UUID>/` with `result.json` and `report.txt`, plus `dom.html` and `screenshot.png` when urlscan has those assets available.

## License

MIT.
