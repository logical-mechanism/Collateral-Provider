import os
import tempfile

from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from api import views


@override_settings(ALLOWED_HOSTS=["testserver"])
class TestHealthz(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = "/healthz"
        # Clear the lru_cache on _load_known_hosts in case earlier tests
        # populated it with stale state.
        views._load_known_hosts.cache_clear()

    def test_returns_200_when_keys_and_known_hosts_present(self):
        # Default settings point SKEY_PATH/VKEY_PATH at api/key/payment.{skey,vkey}
        # which are checked into the repo. known.hosts.json lives at the repo root.
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertEqual(body["status"], "ok")
        self.assertIn("version", body)

    def test_returns_503_when_skey_missing(self):
        with override_settings(SKEY_PATH="/nonexistent/payment.skey"):
            response = self.client.get(self.url)
        self.assertEqual(response.status_code, 503)
        body = response.json()
        self.assertEqual(body["status"], "error")
        self.assertTrue(any("skey missing" in p for p in body["problems"]))

    def test_returns_503_when_vkey_unreadable(self):
        # An existing-but-unreadable file: chmod 000 a tmp file.
        with tempfile.NamedTemporaryFile(suffix=".vkey", delete=False) as f:
            f.write(b'{"cborHex": "5820' + b"00" * 32 + b'"}')
            path = f.name
        try:
            os.chmod(path, 0)
            with override_settings(VKEY_PATH=path):
                response = self.client.get(self.url)
            self.assertEqual(response.status_code, 503)
            self.assertTrue(
                any("vkey not readable" in p for p in response.json()["problems"])
            )
        finally:
            os.chmod(path, 0o600)
            os.unlink(path)

    def test_healthz_is_not_throttled(self):
        # Hit it many times in quick succession; nothing should 429.
        # If the view inherited the global throttle this would fail at 61.
        for _ in range(80):
            response = self.client.get(self.url)
            self.assertEqual(response.status_code, 200)

    def test_healthz_method_not_allowed_on_post(self):
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 405)
