import unittest

from urlscanx.report import format_report, iocs, requests


class ReportTests(unittest.TestCase):
    def test_extracts_iocs_and_requests(self):
        result = {
            "task": {"url": "https://start.example/"},
            "page": {"url": "https://final.example/", "ip": "1.2.3.4"},
            "lists": {"domains": ["cdn.example"], "ips": ["2.3.4.5"],
                      "urls": ["https://cdn.example/a.js"], "hashes": ["abc123"]},
            "data": {"requests": [{"request": {"request": {"url": "https://api.example/v1", "method": "POST"}},
                                   "response": {"response": {"status": 200, "remoteIPAddress": "3.4.5.6"}},
                                   "type": "XHR"}]},
        }
        values = iocs(result)
        self.assertIn("api.example", values["domains"])
        self.assertIn("1.2.3.4", values["ips"])
        self.assertIn("https://api.example/v1", values["urls"])
        self.assertEqual(values["hashes"], ["abc123"])
        self.assertEqual(requests(result)[0]["method"], "POST")

    def test_sparse_result(self):
        result = {"task": {}}
        self.assertEqual(iocs(result), {"domains": [], "ips": [], "urls": [], "hashes": []})
        text = format_report(result, "example")
        self.assertIn("Forms (0):", text)
        self.assertIn("Console messages (0):", text)
