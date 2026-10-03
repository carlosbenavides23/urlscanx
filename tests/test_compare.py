import copy
import unittest

from urlscanx.compare import compare_many, compare_results, format_comparison, format_multi_comparison


class CompareTests(unittest.TestCase):
    def test_binary_empty_report_snapshot(self):
        self.assertEqual(format_comparison({}, {}, "a", "b"), "\n".join([
            "urlscanx comparison: a vs b", "Page title matches: no", "Main IP matches: no",
            "Request counts: 0 vs 0",
            "Form actions unavailable for scan A, B; submission endpoints use observed requests where possible.",
            "Shared domains (0):", "  -", "Shared IPs (0):", "  -", "Shared URLs (0):", "  -",
            "Shared hashes (0):", "  -", "Shared technologies (0):", "  -",
            "Shared external endpoints (0):", "  -", "Only in scan A:", "  -", "Only in scan B:", "  -",
        ]))

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


class MultiCompareTests(unittest.TestCase):
    @staticmethod
    def scan(index):
        shared = "https://collector.test/all?token=reusable-secret"
        subset = "https://collector.test/subset"
        unique = f"https://unique-{index}.test/submit"
        urls = [shared, unique] + ([subset] if index < 3 else [])
        return {
            "page": {"url": f"https://page-{index}.test/"},
            "lists": {
                "domains": ["all.test", "all.test", f"unique-{index}.test"] + (["subset.test"] if index < 3 else []),
                "ips": ["192.0.2.1", "192.0.2.1", f"198.51.100.{index}"] + (["192.0.2.2"] if index < 3 else []),
                "hashes": ["all-hash", "all-hash", f"unique-hash-{index}"] + (["subset-hash"] if index < 3 else []),
                "urls": urls * 2,
            },
            "meta": {"processors": {"wappa": {"data": [
                {"app": name} for name in ["AllTech", "AllTech", f"UniqueTech{index}"] + (["SubsetTech"] if index < 3 else [])
            ]}}},
            "data": {"requests": [{"request": {"url": url, "method": "POST"}} for url in urls * 2]},
        }

    def test_presence_all_subset_unique_and_no_mutation(self):
        scans = [self.scan(index) for index in range(1, 4)]
        original = copy.deepcopy(scans)
        result = compare_many(scans)
        examples = {
            "domains": ("all.test", "subset.test", "unique-1.test"),
            "ips": ("192.0.2.1", "192.0.2.2", "198.51.100.1"),
            "hashes": ("all-hash", "subset-hash", "unique-hash-1"),
            "technologies": ("AllTech", "SubsetTech", "UniqueTech1"),
        }
        for key in ("urls", "external_endpoints", "submission_endpoints"):
            examples[key] = ("https://collector.test/all?token=reusable-secret", "https://collector.test/subset", "https://unique-1.test/submit")
        for key, (all_value, subset_value, unique_value) in examples.items():
            with self.subTest(category=key):
                self.assertIn(all_value, result["shared"][3][key])
                self.assertIn(subset_value, result["shared"][2][key])
                self.assertEqual(result["presence"][key][subset_value], [1, 2])
                self.assertIn(unique_value, result["unique"][0][key])
                self.assertNotIn(unique_value, result["unique"][1][key])
                self.assertEqual(result["shared"][3][key].count(all_value), 1)
        self.assertEqual(scans, original)
        report = format_multi_comparison(scans, ["a", "b", "c"])
        for text in ("Shared by all scans (3/3)", "Present in 2/3 scans", "[scans 1, 2]", "Per-scan unique artifacts", "unique-hash-1"):
            self.assertIn(text, report)
        self.assertNotIn("reusable-secret", report)
        for phrase in ("same actor", "same campaign", "same operator"):
            self.assertNotIn(phrase, report.lower())

    def test_min_shared_filters_shared_groups_only(self):
        scans = [self.scan(index) for index in range(1, 4)]
        report = format_multi_comparison(scans, ["a", "b", "c"], min_shared=3)
        self.assertIn("all-hash", report)
        self.assertNotIn("subset-hash", report)
        self.assertNotIn("Present in 2/3 scans", report)
        self.assertIn("unique-hash-1", report)

    def test_five_scan_prevalence_groups_descend_and_filter(self):
        scans = [{"lists": {"hashes": ["all"] + (["four"] if index < 4 else [])
                            + (["three"] if index < 3 else []) + (["two"] if index < 2 else [])}}
                 for index in range(5)]
        report = format_multi_comparison(scans, list("abcde"), min_shared=3)
        self.assertLess(report.index("Shared by all scans (5/5)"), report.index("Present in 4/5 scans"))
        self.assertLess(report.index("Present in 4/5 scans"), report.index("Present in 3/5 scans"))
        self.assertIn("four [scans 1, 2, 3, 4]", report)
        self.assertNotIn("Present in 2/5 scans", report)
        self.assertNotIn("two [scans", report)

    def test_missing_dom_write_methods_and_available_form_actions(self):
        scans = [{"page": {"url": "https://page.test/"}, "data": {"requests": [
            {"request": {"url": "https://submit.test/", "method": method}}
        ]}} for method in ("POST", "PUT", "PATCH")]
        result = compare_many(scans, [None, b'<form method="POST" action="/form"></form>', None])
        self.assertEqual(result["shared"][3]["submission_endpoints"], ["https://submit.test/"])
        self.assertEqual(result["unique"][1]["submission_endpoints"], ["https://page.test/form"])
        report = format_multi_comparison(scans, ["a", "b", "c"], [None, b"", None])
        self.assertIn("Form actions unavailable for scans 1, 3", report)
        self.assertIn("submission endpoints (1)", report)

    def test_verbose_removes_item_limit_but_retains_redaction(self):
        scans = [{"lists": {"urls": [f"https://shared.test/{i:02}?token=secret" for i in range(20)],
                              "hashes": [f"hash-{i:02}" for i in range(20)]}}] * 3
        normal = format_multi_comparison(scans, ["a", "b", "c"])
        verbose = format_multi_comparison(scans, ["a", "b", "c"], verbose=True)
        self.assertIn("... 5 more", normal)
        self.assertNotIn("hash-19", normal)
        self.assertNotIn("... 5 more", verbose)
        self.assertIn("hash-19", verbose)
        self.assertNotIn("token=secret", verbose)

    def test_subset_and_unique_sections_also_follow_verbose(self):
        subset = [f"subset-{i:02}" for i in range(20)]
        unique = [f"unique-{i:02}" for i in range(20)]
        scans = [{"lists": {"hashes": subset + unique}}, {"lists": {"hashes": subset}}, {}]
        normal = format_multi_comparison(scans, ["a", "b", "c"])
        verbose = format_multi_comparison(scans, ["a", "b", "c"], verbose=True)
        self.assertEqual(normal.count("... 5 more"), 2)
        for value in ("subset-19", "unique-19"):
            self.assertNotIn(value, normal)
            self.assertIn(value, verbose)

    def test_distinct_source_tokens_are_not_merged_after_redaction(self):
        first = "https://submit.test/?token=first-secret"
        second = "https://submit.test/?token=second-secret"
        scans = [{"lists": {"urls": [first]}}, {"lists": {"urls": [second]}}, {}]
        result = compare_many(scans)
        self.assertNotIn("urls", result["shared"].get(2, {}))
        self.assertEqual(result["unique"][0]["urls"], [first])
        report = format_multi_comparison(scans, ["a", "b", "c"])
        self.assertNotIn("first-secret", report)
        self.assertNotIn("second-secret", report)

    def test_empty_scans_and_invalid_arguments(self):
        self.assertEqual(compare_many([{}, {}, {}])["shared"], {})
        self.assertIn("Shared by all scans (3/3):\n  -", format_multi_comparison([{}, {}, {}], ["a", "b", "c"]))
        for results, doms in (([{}, {}], None), ([{}, {}, {}], [None])):
            with self.assertRaises(ValueError):
                compare_many(results, doms)
        for minimum in (0, 1, 4):
            with self.assertRaises(ValueError):
                format_multi_comparison([{}, {}, {}], ["a", "b", "c"], min_shared=minimum)
