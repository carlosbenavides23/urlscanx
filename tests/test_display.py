import unittest

from urlscanx.display import display_text, display_url
from urlscanx.report import format_iocs, format_report, format_requests, frames, iocs, parse_forms


class DisplayTests(unittest.TestCase):
    def test_webhook_and_query_credentials_are_redacted_consistently(self):
        webhook = "https://discord.com/api/webhooks/1547269048566292661/reusableSecretToken123"
        rendered = display_url(webhook)
        self.assertIn("/1547269048566292661/[REDACTED sha256:", rendered)
        self.assertNotIn("reusableSecretToken123", rendered)
        self.assertEqual(rendered, display_url(webhook))
        signed = "https://example.test/path/123?access_token=secret-value&X-Amz-Signature=abcdef&item=42"
        shown = display_url(signed)
        self.assertIn("item=42", shown)
        self.assertIn("access_token=[REDACTED", shown)
        self.assertIn("X-Amz-Signature=[REDACTED", shown)
        self.assertNotIn("secret-value", shown)
        self.assertNotIn("abcdef", shown)
        self.assertNotIn("pathCredential", display_url("https://example.test/api/token/pathCredential"))

    def test_long_values_non_network_and_embedded_urls(self):
        value = "https://example.test/collect?state=" + "q" * 120 + "&next=1"
        shown = display_url(value)
        self.assertIn("state=[REDACTED", shown)
        self.assertIn("next=1", shown)
        self.assertLessEqual(len(shown), 240)
        self.assertEqual(display_url("data:text/plain,secret"), "data:[omitted]")
        self.assertNotIn("secret", display_text("failed: https://example.test/?token=secret"))
        self.assertNotIn("opaque", display_text("generated blob:https://example.test/opaque"))

    def test_human_views_redact_raw_iocs_keep_full_values(self):
        secret = "https://example.test/collect?api_key=reusable-secret"
        result = {
            "task": {"url": secret}, "page": {"url": "https://example.test/"},
            "lists": {"urls": [secret, "blob:https://example.test/opaque", "data:text/plain,abc"]},
            "data": {"requests": [{"request": {"url": secret}}]},
        }
        self.assertIn(secret, iocs(result)["urls"])
        self.assertEqual(len(iocs(result)["urls"]), 2)
        for view in (format_iocs(result), format_requests(result), format_report(result, "scan")):
            self.assertNotIn("reusable-secret", view)
        report = format_report(result, "scan")
        self.assertIn("Non-network URL schemes (2):", report)
        self.assertNotIn("data:text/plain,abc", report)
        self.assertIn("Child-frame detail unavailable", report)


class FormAndFrameTests(unittest.TestCase):
    def test_forms_preserve_hidden_and_group_credentials(self):
        dom = b'''<form id="f1" method="post" action="/submit?token=secret">
            <button name="backArrow">Back</button><input name="passwd" type="password" id="i0118">
            <input name="count" type="text" hidden><input name="idSIButton9" type="submit">
            </form>'''
        forms = parse_forms(dom)
        self.assertIs(forms[0]["inputs"][2]["hidden"], True)
        report = format_report({"task": {}, "page": {"url": "https://example.test/"}}, "scan", dom)
        self.assertIn("Form input fields (2):", report)
        self.assertIn("Credentials:", report)
        self.assertIn("passwd (password)", report)
        self.assertIn("count (text) [hidden]", report)
        self.assertNotIn("backArrow", report)
        self.assertNotIn("idSIButton9", report)
        self.assertNotIn("token=secret", report)

    def test_frames_and_request_association(self):
        result = {
            "page": {"url": "https://main.test/"},
            "data": {
                "frames": [
                    {"frameId": "MAIN1234", "url": "https://main.test/", "parentId": ""},
                    {"frameId": "CHILD5678", "url": "https://frame.test/embed", "parentId": "MAIN1234"},
                ],
                "requests": [
                    {"request": {"url": "https://main.test/", "frameId": "MAIN1234", "type": "Document"}},
                    {"request": {"url": "https://frame.test/embed", "frameId": "CHILD5678", "type": "Document"}},
                ],
            },
        }
        self.assertEqual([frame["role"] for frame in frames(result)], ["main", "child 1"])
        report = format_report(result, "scan")
        self.assertIn("Frames (2):", report)
        self.assertIn("main: https://main.test/", report)
        self.assertIn("child 1: https://frame.test/embed", report)
        self.assertIn("[frame: child 1]", report)

    def test_request_frame_ids_work_without_explicit_frame_list(self):
        result = {"page": {"url": "https://main.test/"}, "data": {"requests": [
            {"request": {"url": "https://main.test/", "frameId": "MAIN", "primaryRequest": True, "type": "Document"}},
            {"request": {"url": "https://child.test/", "frameId": "CHILD", "type": "Document"}},
        ]}}
        self.assertEqual([frame["role"] for frame in frames(result)], ["main", "child 1"])
        self.assertIn("child 1: https://child.test/", format_report(result, "scan"))

    def test_default_console_is_bounded_verbose_keeps_messages(self):
        result = {"task": {}, "data": {"console": [
            {"message": {"level": "warning", "text": "WebGPU adapter unavailable"}},
            {"message": {"level": "error", "text": "Failed at https://example.test/?token=secret"}},
            {"message": {"level": "log", "text": "debug output"}},
        ]}}
        short = format_report(result, "scan")
        full = format_report(result, "scan", verbose=True)
        self.assertIn("error: Failed", short)
        self.assertNotIn("WebGPU", short)
        self.assertNotIn("debug output", short)
        self.assertIn("WebGPU", full)
        self.assertIn("debug output", full)
        self.assertNotIn("token=secret", short)
        self.assertNotIn("token=secret", full)
