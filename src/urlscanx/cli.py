"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

from .api import ScanError, api_key, fetch_asset, fetch_result, parse_scan
from .compare import format_comparison
from .report import format_iocs, format_report, format_requests


def save_scan(
    scan_id: str,
    result: dict,
    report: str,
    dom: bytes | None,
    screenshot: bytes | None,
) -> tuple[Path, list[str]]:
    directory = Path("urlscanx-output") / scan_id
    if directory.exists():
        raise ScanError(f"Output already exists: {directory}. Remove it to save again.")
    warnings: list[str] = []
    if screenshot is not None and not screenshot.startswith(b"\x89PNG\r\n\x1a\n"):
        warnings.append("screenshot unavailable: urlscan returned invalid PNG data")
        screenshot = None
    if dom is not None:
        try:
            dom.decode("utf-8")
        except UnicodeDecodeError:
            warnings.append("DOM unavailable: urlscan returned invalid UTF-8")
            dom = None
    staged: Path | None = None
    try:
        directory.parent.mkdir(exist_ok=True)
        staged = Path(tempfile.mkdtemp(prefix=f".{scan_id}-", dir=directory.parent))
        (staged / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        (staged / "report.txt").write_text(report + "\n", encoding="utf-8")
        if dom is not None:
            (staged / "dom.html").write_bytes(dom)
        else:
            warnings.append("DOM snapshot was not available")
        if screenshot is not None:
            (staged / "screenshot.png").write_bytes(screenshot)
        else:
            warnings.append("screenshot was not available")
        staged.rename(directory)
    except OSError as exc:
        raise ScanError(f"Could not save scan: {exc.strerror or exc}.") from exc
    finally:
        if staged is not None and staged.exists():
            shutil.rmtree(staged)
    return directory, warnings


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "compare":
        compare_parser = argparse.ArgumentParser(prog="urlscanx compare", description="Compare two urlscan results.")
        compare_parser.add_argument("scan1")
        compare_parser.add_argument("scan2")
        args = compare_parser.parse_args(argv[1:])
        try:
            first_id, second_id = parse_scan(args.scan1), parse_scan(args.scan2)
            key = api_key()
            print(format_comparison(fetch_result(first_id, key), fetch_result(second_id, key), first_id, second_id))
            return 0
        except ScanError as exc:
            print(f"urlscanx: {exc}", file=sys.stderr)
            return exc.exit_code
    parser = argparse.ArgumentParser(
        prog="urlscanx", description="Inspect and compare urlscan.io results.",
        epilog="Compare two scans with: urlscanx compare <scan1> <scan2>",
    )
    parser.add_argument("scan", help="scan UUID or result URL")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--json", action="store_true", help="print complete Result API JSON")
    modes.add_argument("--iocs", action="store_true", help="print only indicators")
    modes.add_argument("--requests", action="store_true", help="print compact HTTP requests")
    parser.add_argument("--save", action="store_true", help="save JSON, report, DOM, and screenshot when available")
    args = parser.parse_args(argv)
    try:
        scan_id = parse_scan(args.scan)
        key = api_key()
        result = fetch_result(scan_id, key)

        need_dom = (not args.json and not args.iocs and not args.requests) or args.save
        dom = fetch_asset(scan_id, "dom", key, optional=True) if need_dom else None
        screenshot = fetch_asset(scan_id, "screenshot", key, optional=True) if args.save else None
        report = format_report(result, scan_id, dom)

        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif args.iocs:
            print(format_iocs(result))
        elif args.requests:
            print(format_requests(result))
        else:
            print(report)

        if args.save:
            directory, warnings = save_scan(scan_id, result, report, dom, screenshot)
            print(f"Saved to {directory}", file=sys.stderr)
            for warning in dict.fromkeys(warnings):
                print(f"urlscanx: warning: {warning}", file=sys.stderr)
        return 0
    except ScanError as exc:
        print(f"urlscanx: {exc}", file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
