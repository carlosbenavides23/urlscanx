import unittest

from urlscanx.report import format_report, iocs, parse_forms, requests


class ReportTests(unittest.TestCase):
    def test_extracts_iocs_and_requests(self):
        result = {
            "task": {"url": "https://start.example/"},
            "page": {"url": "https://final.example/", "ip": "1.2.3.4"},
            "lists": {
                "domains": ["cdn.example"],
                "ips": ["2.3.4.5"],
                "urls": ["https://cdn.example/a.js"],
                "hashes": ["abc123"],
            },
            "data": {
                "requests": [{
                    "request": {"request": {"url": "https://api.example/v1", "method": "POST"}},
                    "response": {
                        "response": {"status": 200, "remoteIPAddress": "3.4.5.6"},
                        "hash": "def456",
                    },
                    "type": "XHR",
                }]
            },
        }
        values = iocs(result)
        self.assertIn("api.example", values["domains"])
        self.assertIn("1.2.3.4", values["ips"])
        self.assertIn("https://api.example/v1", values["urls"])
        self.assertIn("abc123", values["hashes"])
        self.assertIn("def456", values["hashes"])
        self.assertEqual(requests(result)[0]["method"], "POST")

    def test_sparse_result(self):
        result = {"task": {}}
        self.assertEqual(iocs(result), {"domains": [], "ips": [], "urls": [], "hashes": []})
        text = format_report(result, "example")
        self.assertIn("Forms (0):", text)
        self.assertIn("JavaScript globals (0):", text)
        self.assertIn("Console messages (0):", text)

    def test_dom_form_parsing(self):
        dom = b"""<html><form name="f1" method="post"><input name="passwd" type="password" id="i0118" autocomplete="off"><input type="submit" value="Sign in"></form></html>"""
        forms = parse_forms(dom)
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["method"], "POST")
        self.assertEqual(forms[0]["action"], "")
        self.assertEqual(forms[0]["inputs"][0]["name"], "passwd")

        report = format_report(
            {
                "task": {},
                "data": {
                    "globals": [{"prop": "inputpw", "type": "object"}],
                    "identifiers": ["html-id.i0281"],
                },
            },
            "scan",
            dom,
        )
        self.assertIn("POST (current URL)", report)
        self.assertIn("passwd (password)", report)
        self.assertIn("object| inputpw", report)
        self.assertIn("html-id.i0281", report)
