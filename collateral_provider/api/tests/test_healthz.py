import os
import tempfile

from django.test import TestCase, override_settings
from rest_framework.test import APIClient


@override_settings(ALLOWED_HOSTS=["testserver"])
class TestHealthz(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = "/healthz"

    def test_returns_200_when_keys_and_known_hosts_present(self):
        # Default settings point SKEY_PATH/VKEY_PATH at api/key/payment.{skey,vkey}
        # which are checked into the repo. known.hosts.json lives at the repo root.
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertEqual(body["status"], "ok")
        self.assertIn("version", body)

    def test_returns_503_when_skey_missing(self):
        secret_path = "/nonexistent/payment.skey"
        with override_settings(SKEY_PATH=secret_path):
            response = self.client.get(self.url)
        self.assertEqual(response.status_code, 503)
        body = response.json()
        self.assertEqual(body["status"], "error")
        # Public body says what's wrong by label only — never the path.
        self.assertEqual(body["problems"], ["skey missing"])
        self.assertNotIn(secret_path, response.content.decode())

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
            body = response.json()
            self.assertEqual(body["problems"], ["vkey unreadable"])
            # The absolute path must not appear anywhere in the body.
            self.assertNotIn(path, response.content.decode())
        finally:
            os.chmod(path, 0o600)
            os.unlink(path)

    def test_healthz_sets_cache_control_no_store(self):
        # An upstream proxy must not cache "ok" past the moment the
        # signing keys disappear (or vice versa).
        response = self.client.get(self.url)
        self.assertEqual(response["Cache-Control"], "no-store")
        with override_settings(SKEY_PATH="/nonexistent/payment.skey"):
            response = self.client.get(self.url)
        self.assertEqual(response["Cache-Control"], "no-store")

    def test_healthz_is_not_throttled(self):
        # Hit it many times in quick succession; nothing should 429.
        # If the view inherited the global throttle this would fail at 61.
        for _ in range(80):
            response = self.client.get(self.url)
            self.assertEqual(response.status_code, 200)

    def test_healthz_method_not_allowed_on_post(self):
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 405)

    @override_settings(KNOWN_HOSTS_PATH="/nonexistent/known.hosts.json")
    def test_known_hosts_registry_is_not_a_signing_dependency(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

    @override_settings(
        SKEY_PATH="/nonexistent/payment.skey",
        VKEY_PATH="/nonexistent/payment.vkey",
    )
    def test_livez_stays_up_when_readiness_fails(self):
        response = self.client.get("/livez")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
        self.assertEqual(response["Cache-Control"], "no-store")


@override_settings(ALLOWED_HOSTS=["testserver"])
class ReadinessCoversThrottleCacheTestCase(TestCase):
    """A broken throttle cache must fail readiness, not just requests.

    CACHE_DIR defaults inside the release tree, which the shipped systemd
    unit mounts read-only. Before this probe existed, such a deploy passed
    /healthz, satisfied the deploy script's readiness gate, never rolled
    back, and then 500'd on every collateral POST.
    """

    def test_unwritable_cache_reports_unready(self):
        with override_settings(
            CACHES={
                "default": {
                    "BACKEND": "django.core.cache.backends.filebased.FileBasedCache",
                    "LOCATION": "/proc/definitely-not-writable/cache",
                }
            }
        ):
            response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["status"], "error")
        self.assertIn("throttle cache", " ".join(response.json()["problems"]))

    def test_healthy_cache_reports_ok(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
