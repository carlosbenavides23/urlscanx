# Development

Requires Python 3.11 or newer. Use a virtual environment; the only runtime
dependency is the pinned Python parser `esprima2==6.0.0`.

```sh
git clone https://github.com/carlosbenavides23/urlscanx.git
cd urlscanx
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
PYTHONPATH=src python -m unittest discover -s tests -v
python -m compileall -q src tests
git diff --check
```

PowerShell test invocation:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

The 0.12.0 suite contains 852 tests. API calls are mocked and regression fixtures
are sanitized projections or synthetic inputs; unit tests require neither a
urlscan API key nor access to the scanned sites. Original capture archives are
not distributed or required for the unit suite.

## Layout

- `src/urlscanx/cli.py`: command parsing, artifact retrieval and saving.
- `src/urlscanx/api.py`: urlscan API client and input validation.
- `src/urlscanx/report.py`, `compare.py`, `display.py`: reports, technical overlap
  and shared display protection.
- `src/urlscanx/analysis/`: bounded passive evidence extraction, static analysis,
  relationships, findings and rendering.
- `tests/`: unit tests, sanitized fixtures and exact/semantic output regressions.

When changing behavior, keep raw Result unchanged and protect derived output in
both normal and verbose modes. Preserve the passive boundary and report unavailable
or truncated evidence explicitly. Regression tests should distinguish static facts,
runtime support, payload structure and value equality.

Documentation here covers the public tool. Local research, original artifacts,
roadmaps and review reports are not part of the publication checkout.
