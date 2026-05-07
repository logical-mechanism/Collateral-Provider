from unittest.mock import patch

import cbor2
from django.conf import settings
from django.core.cache import cache
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from api.tx_fields import (
    COLLATERAL_INPUTS,
    INPUTS,
    OUTPUTS,
    REQUIRED_SIGNERS,
    SET_TAG,
)
from api.views import _client_ip


def build_happy_path_tx_cbor(env: str = "preprod") -> str:
    """Construct the smallest tx CBOR that satisfies every structural
    validator for the configured env. The transaction validator (Koios)
    must still be mocked separately."""
    env_settings = settings.ENVIRONMENTS[env]
    collateral_txid = bytes.fromhex(env_settings["TXID"])
    collateral_idx = env_settings["TXIDX"]
    pkh = bytes.fromhex(settings.PKH)

    # Different txid for the regular input — must not equal the collateral.
    other_txid = bytes(32)  # 32 zero bytes is fine, just != collateral_txid

    # Shelley-style enterprise address (header byte 0x60 + 28-byte payment hash).
    address = bytes.fromhex("60" + "ab" * 28)

    body = {
        INPUTS: cbor2.CBORTag(SET_TAG, [(other_txid, 0)]),
        OUTPUTS: [[address, 5_000_000]],
        COLLATERAL_INPUTS: cbor2.CBORTag(SET_TAG, [(collateral_txid, collateral_idx)]),
        REQUIRED_SIGNERS: cbor2.CBORTag(SET_TAG, [pkh]),
    }
    tx = [body, {}, True, None]
    return cbor2.dumps(tx).hex()


@override_settings(ALLOWED_HOSTS=["testserver"])
class TestHappyPath(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse("collateral", kwargs={"environment": "preprod"})

    def tearDown(self):
        cache.clear()

    @patch("api.validators.transaction.evaluate_transaction")
    def test_valid_tx_returns_witness(self, mock_eval):
        mock_eval.return_value = {"jsonrpc": "2.0", "result": []}
        tx_cbor = build_happy_path_tx_cbor()

        response = self.client.post(
            self.url, {"tx_body": tx_cbor}, format="json"
        )

        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertIn("witness", body)
        # Witness CBOR is hex-encoded bytes; validate shape via cbor2.
        decoded = cbor2.loads(bytes.fromhex(body["witness"]))
        self.assertEqual(decoded[0], 0)  # vkey-witness type tag
        self.assertEqual(len(decoded[1]), 2)  # [pubkey, signature]
        self.assertEqual(len(decoded[1][0]), 32)  # Ed25519 pubkey
        self.assertEqual(len(decoded[1][1]), 64)  # Ed25519 signature

    @patch("api.validators.transaction.evaluate_transaction")
    def test_koios_rejects_returns_400(self, mock_eval):
        mock_eval.return_value = {"jsonrpc": "2.0", "error": {"code": -32602}}
        tx_cbor = build_happy_path_tx_cbor()

        response = self.client.post(
            self.url, {"tx_body": tx_cbor}, format="json"
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Transaction Fails Validation", str(response.content))

    @patch("api.validators.transaction.evaluate_transaction")
    def test_koios_unavailable_returns_503(self, mock_eval):
        from api.simulate import UpstreamUnavailable
        mock_eval.side_effect = UpstreamUnavailable("preprod timed out")
        tx_cbor = build_happy_path_tx_cbor()

        response = self.client.post(
            self.url, {"tx_body": tx_cbor}, format="json"
        )
        self.assertEqual(response.status_code, 503)


@override_settings(ALLOWED_HOSTS=["testserver"])
class TestEnvironmentRouting(TestCase):
    def setUp(self):
        self.client = APIClient()

    def tearDown(self):
        cache.clear()

    def test_unknown_environment_returns_400(self):
        url = reverse("collateral", kwargs={"environment": "fakenet"})
        response = self.client.post(url, {"tx_body": "deadbeef"}, format="json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"detail": "Invalid Environment"})

    def test_get_method_not_allowed(self):
        url = reverse("collateral", kwargs={"environment": "preprod"})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 405)


@override_settings(ALLOWED_HOSTS=["testserver"])
class TestLandingPages(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_landing_page_renders_with_pkh(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        # The configured PKH must appear so a user can verify they're talking
        # to the provider they expect.
        self.assertIn(settings.PKH.encode(), response.content)

    def test_known_hosts_returns_json(self):
        response = self.client.get("/known_hosts/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        # Must be a JSON object, not a list, since it's keyed by PKH.
        self.assertIsInstance(response.json(), dict)


@override_settings(ALLOWED_HOSTS=["testserver"])
class TestThrottle(TestCase):
    """Verify the per-IP rate limit is wired up. We override the rate to a
    small value so the test stays fast; the production rate is configured
    on ProvideCollateralThrottle directly."""

    def setUp(self):
        self.client = APIClient()
        self.url = reverse("collateral", kwargs={"environment": "preprod"})

    def tearDown(self):
        cache.clear()

    @patch("api.views.ProvideCollateralThrottle.rate", "2/min")
    def test_429_after_rate_limit_exceeded(self):
        # Two requests succeed (well, get processed — they'll 400 because the
        # tx_body is junk, but that's after the throttle check). The third
        # request hits the throttle.
        for _ in range(2):
            response = self.client.post(self.url, {"tx_body": "deadbeef"}, format="json")
            self.assertNotEqual(response.status_code, 429)

        response = self.client.post(self.url, {"tx_body": "deadbeef"}, format="json")
        self.assertEqual(response.status_code, 429)


class TestClientIp(TestCase):
    """_client_ip is what we throttle and log on, so its parsing has to be
    correct under whatever X-Forwarded-For headers a reverse proxy sends.
    Trust is scoped to settings.TRUSTED_PROXY_IPS so an attacker connecting
    to gunicorn directly can't forge their way past the throttle."""

    def setUp(self):
        self.factory = RequestFactory()

    def test_uses_first_ip_in_xff_chain_when_proxy_is_trusted(self):
        # RequestFactory's default REMOTE_ADDR is 127.0.0.1, which is in
        # the default TRUSTED_PROXY_IPS list, so XFF is honored.
        request = self.factory.post("/", HTTP_X_FORWARDED_FOR="1.2.3.4, 5.6.7.8")
        self.assertEqual(_client_ip(request), "1.2.3.4")

    def test_strips_whitespace_around_xff_value(self):
        request = self.factory.post("/", HTTP_X_FORWARDED_FOR="   9.9.9.9   , 1.1.1.1")
        self.assertEqual(_client_ip(request), "9.9.9.9")

    def test_falls_back_to_remote_addr_when_no_xff(self):
        request = self.factory.post("/", REMOTE_ADDR="2.2.2.2")
        self.assertEqual(_client_ip(request), "2.2.2.2")

    def test_ignores_xff_when_remote_addr_is_not_a_trusted_proxy(self):
        # An attacker connecting straight to gunicorn (REMOTE_ADDR is
        # their real IP, not the proxy's) cannot forge XFF to bypass the
        # throttle.
        request = self.factory.post(
            "/",
            HTTP_X_FORWARDED_FOR="1.2.3.4",
            REMOTE_ADDR="9.9.9.9",
        )
        with override_settings(TRUSTED_PROXY_IPS=["127.0.0.1"]):
            self.assertEqual(_client_ip(request), "9.9.9.9")

    def test_empty_trusted_proxies_disables_xff_entirely(self):
        request = self.factory.post(
            "/",
            HTTP_X_FORWARDED_FOR="1.2.3.4",
            REMOTE_ADDR="127.0.0.1",
        )
        with override_settings(TRUSTED_PROXY_IPS=[]):
            self.assertEqual(_client_ip(request), "127.0.0.1")

    def test_ipv6_loopback_proxy_is_trusted_by_default(self):
        request = self.factory.post(
            "/",
            HTTP_X_FORWARDED_FOR="2001:db8::1",
            REMOTE_ADDR="::1",
        )
        self.assertEqual(_client_ip(request), "2001:db8::1")
