import unittest

from urlscanx.compare import compare_results, format_comparison


class CompareTests(unittest.TestCase):
    def test_overlap(self):
        first = {"page": {"url": "https://one.example/", "title": "Login", "ip": "1.1.1.1"},
                 "lists": {"domains": ["shared.example"], "ips": ["2.2.2.2"],
                           "urls": ["https://shared.example/api"], "hashes": ["sha"]},
                 "meta": {"processors": {"wappa": {"data": [{"app": "React"}]}}},
                 "data": {"requests": [{"request": {"url": "https://shared.example/api"}}]}}
        second = {"page": {"url": "https://two.example/", "title": "Login", "ip": "1.1.1.1"},
                  "lists": {"domains": ["shared.example"], "ips": ["2.2.2.2"],
                            "urls": ["https://shared.example/api"], "hashes": ["sha"]},
                  "meta": {"processors": {"wappa": {"data": [{"app": "React"}]}}},
                  "data": {"requests": [{"request": {"url": "https://shared.example/api"}}]}}
        comparison = compare_results(first, second)
        self.assertEqual(comparison["shared_domains"], ["shared.example"])
        self.assertEqual(comparison["shared_ips"], ["1.1.1.1", "2.2.2.2"])
        self.assertEqual(comparison["shared_urls"], ["https://shared.example/api"])
        self.assertEqual(comparison["shared_hashes"], ["sha"])
        self.assertEqual(comparison["shared_technologies"], ["React"])
        self.assertTrue(comparison["page_title_matches"])
        self.assertTrue(comparison["main_ip_matches"])
        self.assertEqual(comparison["request_counts"], (1, 1))
        self.assertEqual(comparison["shared_external_endpoints"], ["https://shared.example/api"])

    def test_missing_optional_fields(self):
        comparison = compare_results({"task": {}}, {"task": {}})
        self.assertFalse(comparison["page_title_matches"])
        self.assertFalse(comparison["main_ip_matches"])
        self.assertEqual(comparison["request_counts"], (0, 0))

    def test_deltas_context_and_submission_actions(self):
        static = "https://assets.nflxext.com/logo.png"
        shared_collector = "https://collect.test/api?token=reusable-secret"
        first = {
            "page": {"url": "https://phish-a.test/login"},
            "lists": {"hashes": ["unmapped-hash", "unique-a"]},
            "data": {"requests": [
                {"request": {"url": static, "method": "GET", "type": "Image"}, "response": {"hash": "asset-hash"}},
                {"request": {"url": shared_collector, "method": "POST", "type": "XHR"}},
                {"request": {"url": "https://only-a.test/a", "method": "GET"}},
            ]},
        }
        second = {
            "page": {"url": "https://phish-b.test/login"},
            "lists": {"hashes": ["unmapped-hash", "unique-b"]},
            "data": {"requests": [
                {"request": {"url": static, "method": "GET", "type": "Image"}, "response": {"hash": "asset-hash"}},
                {"request": {"url": shared_collector, "method": "POST", "type": "XHR"}},
                {"request": {"url": "https://only-b.test/b", "method": "GET"}},
            ]},
        }
        dom_a = b'<form method="post" action="https://submit-a.test/collect"></form>'
        dom_b = b'<form method="post" action="https://submit-b.test/collect"></form>'
        comparison = compare_results(first, second, dom_a, dom_b)
        self.assertEqual(comparison["shared_url_categories"]["external_static"], [static])
        self.assertEqual(comparison["shared_url_categories"]["submission"], [shared_collector])
        self.assertEqual(comparison["shared_hash_categories"]["external_static"], ["asset-hash"])
        self.assertEqual(comparison["shared_hash_categories"]["unmapped"], ["unmapped-hash"])
        self.assertIn("https://only-a.test/a", comparison["only_in_a"]["external_endpoints"])
        self.assertIn("https://only-b.test/b", comparison["only_in_b"]["external_endpoints"])
        self.assertIn("only-a.test", comparison["only_in_a"]["domains"])
        self.assertIn("https://only-b.test/b", comparison["only_in_b"]["urls"])
        self.assertIn("unique-a", comparison["only_in_a"]["hashes"])
        self.assertIn("unique-b", comparison["only_in_b"]["hashes"])
        self.assertEqual(comparison["submission_only_in_a"], ["https://submit-a.test/collect"])
        self.assertEqual(comparison["submission_only_in_b"], ["https://submit-b.test/collect"])
        report = format_comparison(first, second, "a", "b", dom_a, dom_b)
        for heading in ("Shared external static assets", "Shared hashes linked to external static assets",
                        "Only in scan A", "Only in scan B", "Shared external endpoints"):
            self.assertIn(heading, report)
        self.assertNotIn("reusable-secret", report)
        self.assertNotIn("same actor", report.lower())
        self.assertNotIn("same campaign", report.lower())
