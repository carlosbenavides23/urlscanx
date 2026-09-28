import unittest

from urlscanx.compare import compare_results


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
