import os
import unittest
from unittest.mock import patch

from urlscanx.api import ScanError, _get, api_key, parse_scan
from urlscanx.cli import main


SCAN = "01a0e84d-e186-775a-b6b8-ec96c96fccf0"


class _Headers:
    def __init__(self, values=None):
        self.values = values or {}

    def get(self, key, default=None):
        return self.values.get(key, default)


class _FakeResponse:
    def __init__(self, body=b"ok", headers=None):
        self.body = body
        self.headers = _Headers(headers)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return self.body


class InputTests(unittest.TestCase):
    def test_uuid_and_result_url(self):
        self.assertEqual(parse_scan(SCAN.upper()), SCAN)
        self.assertEqual(parse_scan(f"https://urlscan.io/result/{SCAN}/"), SCAN)
        self.assertEqual(parse_scan(f"https://urlscan.io/result/{SCAN}"), SCAN)

    def test_invalid_input(self):
        for value in ("oops", "https://evil.test/result/" + SCAN, "http://urlscan.io/result/" + SCAN,
                      "https://urlscan.io/result/" + SCAN + "?x=1", "https://urlscan.io@evil.test/result/" + SCAN):
            with self.subTest(value=value), self.assertRaises(ScanError):
                parse_scan(value)

    def test_missing_key(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ScanError, "URLSCAN_API_KEY"):
                api_key()
            self.assertEqual(main([SCAN]), 2)

    def test_compare_missing_second_scan(self):
        with self.assertRaises(SystemExit) as error:
            main(["compare", SCAN])
        self.assertEqual(error.exception.code, 2)

    @patch("urlscanx.api.urlopen")
    def test_requests_identity_encoding(self, mocked_urlopen):
        mocked_urlopen.return_value = _FakeResponse()
        self.assertEqual(_get("/dom/test/", "key"), b"ok")
        request = mocked_urlopen.call_args.args[0]
        self.assertEqual(request.get_header("Accept-encoding"), "gzip, deflate")

    @patch("urlscanx.api.urlopen")
    def test_gzip_response_is_decompressed(self, mocked_urlopen):
        import gzip

        mocked_urlopen.return_value = _FakeResponse(
            gzip.compress(b"<form></form>"),
            {"Content-Encoding": "gzip"},
        )
        self.assertEqual(_get("/dom/test/", "key"), b"<form></form>")

    @patch("urlscanx.api.urlopen")
    def test_deflate_response_is_decompressed(self, mocked_urlopen):
        import zlib

        mocked_urlopen.return_value = _FakeResponse(
            zlib.compress(b"<form></form>"),
            {"Content-Encoding": "deflate"},
        )
        self.assertEqual(_get("/dom/test/", "key"), b"<form></form>")
