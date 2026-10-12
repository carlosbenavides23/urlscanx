import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch
from urllib.request import Request

from urlscanx import __version__
from urlscanx.api import ScanError, _ArtifactRedirectHandler
from urlscanx.analysis import analyze
from urlscanx.analysis.model import Finding
from urlscanx.cli import main
from urlscanx.report import format_iocs, format_report, format_requests
from test_analysis import fixture, request, SCAN


class AnalysisCliTests(unittest.TestCase):
    def invoke(self, result, dom, options):
        out, err = io.StringIO(), io.StringIO()
        with patch("urlscanx.cli.api_key", return_value="offline-key"), \
             patch("urlscanx.cli.fetch_result", return_value=result) as fetch, \
             patch("urlscanx.cli.fetch_asset", return_value=dom) as asset, \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([SCAN, *options])
        return code, out.getvalue(), err.getvalue(), fetch, asset

    def test_json_normal_unchanged_analysis_envelope_and_artifact_only(self):
        result = {"task": {"url": "https://example.test/?token=secret"},
                  "data": {"cookies": [{"name": "session", "value": "raw-cookie-secret"}],
                           "requests": [request(method="POST", postData="raw-body-secret")]}}
        _, normal, _, fetch, assets = self.invoke(result, b"<input>", ["--json"])
        self.assertEqual(normal, json.dumps(result, indent=2, ensure_ascii=False) + "\n")
        assets.assert_not_called()
        fetch.assert_called_once_with(SCAN, "offline-key")
        code, raw, _, fetch, assets = self.invoke(result, b"<input>", ["--analyze", "--json"])
        envelope = json.loads(raw)
        self.assertEqual(code, 0)
        self.assertEqual(envelope["schema_version"], "1.0")
        self.assertEqual(set(envelope), {"schema_version", "metadata", "result", "analysis"})
        self.assertEqual(envelope["result"], result)
        derived = json.dumps(envelope["analysis"])
        for secret in ("raw-cookie-secret", "raw-body-secret"):
            self.assertNotIn(secret, derived)
        fetch.assert_called_once_with(SCAN, "offline-key", artifact_only=True)
        assets.assert_called_once_with(SCAN, "dom", "offline-key", optional=True, artifact_only=True)

    def test_release_version_matches_package_and_analysis_metadata(self):
        project = Path(__file__).resolve().parents[1] / "pyproject.toml"
        declared = tomllib.loads(project.read_text(encoding="utf-8"))["project"]["version"]
        self.assertEqual(declared, "0.12.0")
        self.assertEqual(__version__, declared)
        code, raw, _, _, _ = self.invoke({}, None, ["--analyze", "--json"])
        self.assertEqual(code, 0)
        envelope = json.loads(raw)
        self.assertEqual(envelope["metadata"]["analyzer_version"], declared)
        self.assertEqual(envelope["metadata"]["ruleset_version"], "mvp-b.7")
        self.assertEqual(envelope["schema_version"], "1.0")

    def test_incompatible_modes_fail_before_io(self):
        with patch("urlscanx.cli.fetch_result") as fetch, patch("urlscanx.cli.api_key") as key:
            for option in ("--iocs", "--requests"):
                with self.subTest(option=option), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    main([SCAN, "--analyze", option])
                self.assertEqual(error.exception.code, 2)
            fetch.assert_not_called()
            key.assert_not_called()

    def test_missing_and_failed_dom_are_partial_exit_zero(self):
        result, _, _ = fixture(9)
        code, raw, _, _, _ = self.invoke(result, None, ["--analyze", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(raw)["analysis"]["evidence_coverage"]["dom"]["availability"], "unavailable")
        out, err = io.StringIO(), io.StringIO()
        with patch("urlscanx.cli.api_key", return_value="key"), patch("urlscanx.cli.fetch_result", return_value=result), \
             patch("urlscanx.cli.fetch_asset", side_effect=ScanError("URL with secret must not be echoed")), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(main([SCAN, "--analyze", "--json"]), 0)
        self.assertIn("partial", err.getvalue())
        self.assertNotIn("secret", err.getvalue())
        self.assertEqual(json.loads(out.getvalue())["analysis"]["status"], "partial")

    def test_result_operational_error_retains_exit_code(self):
        with patch("urlscanx.cli.api_key", return_value="key"), patch("urlscanx.cli.fetch_result", side_effect=ScanError("not ready", 3)), \
             patch("urlscanx.cli.fetch_asset") as assets, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([SCAN, "--analyze"]), 3)
            assets.assert_not_called()

    def test_analysis_does_not_use_lossy_report_helpers(self):
        source, _, dom = fixture(9)
        with patch("urlscanx.cli.format_report", side_effect=AssertionError("analysis uses its own adapter")):
            self.assertEqual(self.invoke(source, dom, ["--analyze"])[0], 0)

    def test_no_files_by_default_and_saved_artifacts_remain_authoritative(self):
        source, _, dom = fixture(9)
        png = b"\x89PNG\r\n\x1a\nDATA"
        with tempfile.TemporaryDirectory() as directory:
            previous = os.getcwd()
            os.chdir(directory)
            try:
                self.assertEqual(self.invoke(source, dom, ["--analyze"])[0], 0)
                self.assertEqual(list(Path(directory).iterdir()), [])
                out = io.StringIO()
                with patch("urlscanx.cli.api_key", return_value="key"), patch("urlscanx.cli.fetch_result", return_value=source), \
                     patch("urlscanx.cli.fetch_asset", side_effect=[dom, png]), \
                     contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(main([SCAN, "--analyze", "--json", "--save"]), 0)
                target = Path("urlscanx-output") / SCAN
                self.assertEqual({p.name for p in target.iterdir()}, {"result.json", "report.txt", "dom.html", "screenshot.png", "analysis.txt", "analysis.json"})
                self.assertEqual(json.loads((target / "result.json").read_text(encoding="utf-8")), source)
                self.assertEqual((target / "dom.html").read_bytes(), dom)
                self.assertEqual((target / "screenshot.png").read_bytes(), png)
                self.assertEqual((target / "report.txt").read_text(encoding="utf-8"), format_report(source, SCAN, dom) + "\n")
                sidecar = json.loads((target / "analysis.json").read_text(encoding="utf-8"))
                self.assertNotIn("result", sidecar)
                self.assertEqual(sidecar["metadata"]["result_file"], "result.json")
                self.assertEqual(sidecar["analysis"], json.loads(out.getvalue())["analysis"])
                self.assertTrue((target / "analysis.txt").read_text(encoding="utf-8").startswith("urlscanx analysis"))
            finally:
                os.chdir(previous)

    def test_previous_views_match_existing_renderers_on_corpus(self):
        for number in (3, 5, 9, 11):
            source, _, dom = fixture(number)
            cases = [([], format_report(source, SCAN, dom)), (["--verbose"], format_report(source, SCAN, dom, verbose=True)),
                     (["--iocs"], format_iocs(source)), (["--requests"], format_requests(source))]
            for options, expected in cases:
                with self.subTest(number=number, options=options):
                    self.assertEqual(self.invoke(source, dom, options)[1], expected + "\n")

    def test_verbose_changes_only_presentation_and_findings_do_not_change_exit(self):
        source, _, dom = fixture(11)
        normal = self.invoke(source, dom, ["--analyze", "--json"])[1]
        verbose = self.invoke(source, dom, ["--analyze", "--json", "--verbose"])[1]
        self.assertEqual(json.loads(normal)["analysis"], json.loads(verbose)["analysis"])
        output = analyze(source, SCAN, dom)
        output.findings.append(Finding("reserved", "reserved", "Neutral test finding", [], severity="high"))
        with patch("urlscanx.cli.analyze", return_value=output):
            self.assertEqual(self.invoke(source, dom, ["--analyze"])[0], 0)

    def test_real_client_uses_only_result_dom_and_optional_screenshot_endpoints(self):
        source, _, dom = fixture(3)
        class Response:
            headers = {}
            def __init__(self, body): self.body = body
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self): return self.body
        opened = []
        bodies = iter([json.dumps(source).encode(), dom])
        def open_artifact(req, timeout):
            opened.append(req.full_url)
            return Response(next(bodies))
        with patch("urlscanx.cli.api_key", return_value="key"), patch("urllib.request.OpenerDirector.open", side_effect=open_artifact), \
             patch("urlscanx.api.urlopen", side_effect=AssertionError("unrestricted retrieval")), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([SCAN, "--analyze"]), 0)
        self.assertEqual(opened, [f"https://urlscan.io/api/v1/result/{SCAN}/", f"https://urlscan.io/dom/{SCAN}/"])

    def test_analysis_redirect_boundary_blocks_target_before_following(self):
        handler = _ArtifactRedirectHandler()
        req = Request("https://urlscan.io/dom/scan/", headers={"api-key": "secret"})
        for url in ("https://target.test/collector", "http://urlscan.io/dom/x", "https://urlscan.io@target.test/x",
                    "https://urlscan.io:444/x", "file:///C:/data", "https://[bad", "https://urlscan.io/search/", "https://urlscan.io/dom/other/"):
            with self.subTest(url=url), self.assertRaises(ScanError):
                handler.redirect_request(req, None, 302, "Found", {}, url)
        redirect = handler.redirect_request(req, None, 302, "Found", {}, "https://urlscan.io:443/dom/scan")
        self.assertEqual(redirect.full_url, "https://urlscan.io:443/dom/scan")
