from unittest.mock import patch

import cbor2
from django.conf import settings
from django.core.cache import cache
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from api.script_integrity import calculate_script_data_hash
from api.tx_fields import (
    COLLATERAL_INPUTS,
    INPUTS,
    OUTPUTS,
    REQUIRED_SIGNERS,
    SET_TAG,
)
from api.views import _client_ip

TEST_COST_MODELS = {1: (4, 5)}


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
    # A phase-2 transaction must commit execution units in its redeemers.
    # The upstream mock below reports a 1/1 requirement, so 10/10 leaves a
    # small explicit margin and exercises the provider's budget comparison.
    witnesses = {
        5: {(0, 0): [cbor2.CBORTag(121, []), [10, 10]]},
    }
    body[11] = calculate_script_data_hash(
        cbor2.dumps(witnesses[5]), b"", TEST_COST_MODELS
    )
    tx = [body, witnesses, True, None]
    return cbor2.dumps(tx).hex()


@override_settings(ALLOWED_HOSTS=["testserver"])
class TestHappyPath(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse("collateral", kwargs={"environment": "preprod"})
        self.models_patcher = patch(
            "api.validators.transaction.get_protocol_cost_models",
            return_value=TEST_COST_MODELS,
        )
        self.models_patcher.start()

    def tearDown(self):
        self.models_patcher.stop()
        cache.clear()

    @patch("api.validators.transaction.evaluate_transaction")
    def test_valid_tx_returns_witness(self, mock_eval):
        mock_eval.return_value = {
            "jsonrpc": "2.0",
            "method": "evaluateTransaction",
            "result": [{"validator": "spend:0", "budget": {"memory": 1, "cpu": 1}}],
        }
        tx_cbor = build_happy_path_tx_cbor()

        response = self.client.post(
            self.url, {"tx": tx_cbor}, format="json"
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

    @patch("api.views.issue_witness")
    @patch("api.views.logger.info")
    def test_success_log_does_not_link_client_ip_to_tx_hash(
        self,
        mock_info,
        mock_issue_witness,
    ):
        tx_hash = "ab" * 32
        mock_issue_witness.return_value = ("8200", tx_hash)

        response = self.client.post(
            self.url,
            {"tx": "00"},
            format="json",
            REMOTE_ADDR="198.51.100.42",
            HTTP_X_REQUEST_ID="wallet-request-42",
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response["X-Request-ID"], "wallet-request-42")
        mock_info.assert_called_once()
        call = mock_info.call_args
        rendered_message = call.args[0] % call.args[1:]
        self.assertIn("env=preprod", rendered_message)
        self.assertIn("duration_ms=", rendered_message)
        self.assertNotIn("198.51.100.42", rendered_message)
        self.assertNotIn(tx_hash, rendered_message)
        self.assertEqual(set(call.kwargs["extra"]), {"env", "duration_ms"})

    @patch("api.validators.transaction.evaluate_transaction")
    def test_koios_rejects_returns_400(self, mock_eval):
        mock_eval.return_value = {
            "jsonrpc": "2.0",
            "method": "evaluateTransaction",
            "error": {"code": -32602},
        }
        tx_cbor = build_happy_path_tx_cbor()

        response = self.client.post(
            self.url, {"tx": tx_cbor}, format="json"
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Transaction Fails Validation", str(response.content))

    @patch("api.validators.transaction.evaluate_transaction")
    def test_koios_unavailable_returns_503(self, mock_eval):
        from api.simulate import UpstreamUnavailable
        mock_eval.side_effect = UpstreamUnavailable("preprod timed out")
        tx_cbor = build_happy_path_tx_cbor()

        response = self.client.post(
            self.url, {"tx": tx_cbor}, format="json"
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
        response = self.client.post(url, {"tx": "deadbeef"}, format="json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"detail": "Invalid Environment"})

    def test_unknown_environment_log_does_not_persist_client_ip(self):
        client_ip = "198.51.100.241"
        url = reverse("collateral", kwargs={"environment": "fakenet"})
        with self.assertLogs("api", level="WARNING") as captured:
            response = self.client.post(
                url,
                {"tx": "deadbeef"},
                format="json",
                REMOTE_ADDR=client_ip,
            )
        self.assertEqual(response.status_code, 400)
        self.assertNotIn(client_ip, "\n".join(captured.output))

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

    def test_known_hosts_sets_cache_control_no_store(self):
        # The file is hot-reloadable; an upstream proxy serving a stale
        # registry would defeat that.
        response = self.client.get("/known_hosts/")
        self.assertEqual(response["Cache-Control"], "no-store")

    def test_landing_page_post_is_405(self):
        response = self.client.post("/")
        self.assertEqual(response.status_code, 405)

    def test_known_hosts_post_is_405(self):
        response = self.client.post("/known_hosts/")
        self.assertEqual(response.status_code, 405)


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
        # tx is junk, but that's after the throttle check). The third
        # request hits the throttle.
        for _ in range(2):
            response = self.client.post(self.url, {"tx": "deadbeef"}, format="json")
            self.assertNotEqual(response.status_code, 429)

        response = self.client.post(self.url, {"tx": "deadbeef"}, format="json")
        self.assertEqual(response.status_code, 429)

    @patch("api.views.ProvideCollateralThrottle.rate", "2/min")
    @override_settings(TRUSTED_PROXY_IPS=["127.0.0.1"])
    def test_untrusted_peer_cannot_rotate_xff_to_evade_limit(self):
        for forged_ip in ("1.1.1.1", "2.2.2.2"):
            response = self.client.post(
                self.url,
                {"tx": "deadbeef"},
                format="json",
                REMOTE_ADDR="9.9.9.9",
                HTTP_X_FORWARDED_FOR=forged_ip,
            )
            self.assertNotEqual(response.status_code, 429)

        response = self.client.post(
            self.url,
            {"tx": "deadbeef"},
            format="json",
            REMOTE_ADDR="9.9.9.9",
            HTTP_X_FORWARDED_FOR="3.3.3.3",
        )
        self.assertEqual(response.status_code, 429)

    @patch("api.views.ProvideCollateralThrottle.rate", "1/min")
    @override_settings(TRUSTED_PROXY_IPS=["10.0.0.0/8"])
    def test_trusted_proxy_clients_have_separate_limit_buckets(self):
        for client_ip in ("1.1.1.1", "2.2.2.2"):
            response = self.client.post(
                self.url,
                {"tx": "deadbeef"},
                format="json",
                REMOTE_ADDR="10.42.7.99",
                HTTP_X_FORWARDED_FOR=client_ip,
            )
            self.assertNotEqual(response.status_code, 429)

        response = self.client.post(
            self.url,
            {"tx": "deadbeef"},
            format="json",
            REMOTE_ADDR="10.42.7.99",
            HTTP_X_FORWARDED_FOR="1.1.1.1",
        )
        self.assertEqual(response.status_code, 429)


class TestClientIp(TestCase):
    """_client_ip is what we throttle, ban, and authorize metrics on, so its
    parsing has to be correct under whatever X-Forwarded-For headers a proxy sends.
    Trust is scoped to settings.TRUSTED_PROXY_IPS so an attacker connecting
    to gunicorn directly can't forge their way past the throttle."""

    def setUp(self):
        self.factory = RequestFactory()

    def test_uses_rightmost_untrusted_ip_when_proxy_is_trusted(self):
        # RequestFactory's default REMOTE_ADDR is 127.0.0.1, which is in
        # the default TRUSTED_PROXY_IPS list. The leftmost value can be an
        # attacker-supplied prefix preserved by $proxy_add_x_forwarded_for.
        request = self.factory.post("/", HTTP_X_FORWARDED_FOR="1.2.3.4, 5.6.7.8")
        self.assertEqual(_client_ip(request), "5.6.7.8")

    def test_strips_whitespace_around_xff_value(self):
        request = self.factory.post("/", HTTP_X_FORWARDED_FOR="   9.9.9.9   , 1.1.1.1")
        self.assertEqual(_client_ip(request), "1.1.1.1")

    def test_walks_right_to_left_across_multiple_trusted_proxies(self):
        request = self.factory.post(
            "/",
            HTTP_X_FORWARDED_FOR="198.51.100.8, 10.9.8.7",
            REMOTE_ADDR="127.0.0.1",
        )
        with override_settings(TRUSTED_PROXY_IPS=["127.0.0.1", "10.0.0.0/8"]):
            self.assertEqual(_client_ip(request), "198.51.100.8")

    def test_caller_prefixed_value_is_not_used_as_client(self):
        request = self.factory.post(
            "/",
            HTTP_X_FORWARDED_FOR="203.0.113.99, 198.51.100.8",
            REMOTE_ADDR="127.0.0.1",
        )
        self.assertEqual(_client_ip(request), "198.51.100.8")

    def test_malformed_rightmost_hop_falls_back_to_immediate_peer(self):
        request = self.factory.post(
            "/",
            HTTP_X_FORWARDED_FOR="203.0.113.99, not-an-ip",
            REMOTE_ADDR="127.0.0.1",
        )
        self.assertEqual(_client_ip(request), "127.0.0.1")

    def test_does_not_use_leftmost_value_when_all_hops_are_trusted(self):
        request = self.factory.post(
            "/",
            HTTP_X_FORWARDED_FOR="10.1.2.3, 10.2.3.4",
            REMOTE_ADDR="127.0.0.1",
        )
        with override_settings(TRUSTED_PROXY_IPS=["127.0.0.1", "10.0.0.0/8"]):
            self.assertEqual(_client_ip(request), "127.0.0.1")

    def test_falls_back_to_remote_addr_when_no_xff(self):
        request = self.factory.post("/", REMOTE_ADDR="2.2.2.2")
        self.assertEqual(_client_ip(request), "2.2.2.2")

    def test_invalid_remote_addr_is_not_used_as_identity(self):
        request = self.factory.post("/", REMOTE_ADDR="not-an-ip")
        self.assertIsNone(_client_ip(request))

    def test_remote_addr_is_canonicalized(self):
        request = self.factory.post("/", REMOTE_ADDR="2001:0db8:0:0:0:0:0:1")
        self.assertEqual(_client_ip(request), "2001:db8::1")

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

    def test_scoped_ipv6_forwarded_hop_is_rejected(self):
        request = self.factory.post(
            "/",
            HTTP_X_FORWARDED_FOR="fe80::1%eth0",
            REMOTE_ADDR="127.0.0.1",
        )
        self.assertEqual(_client_ip(request), "127.0.0.1")

    def test_cidr_block_in_trusted_proxies_is_honored(self):
        # Container platforms (DO App Platform, etc.) source LB traffic
        # from a private range rather than a single pinned IP. Listing
        # the CIDR rather than every individual IP must Just Work.
        request = self.factory.post(
            "/",
            HTTP_X_FORWARDED_FOR="1.2.3.4",
            REMOTE_ADDR="10.42.7.99",
        )
        with override_settings(TRUSTED_PROXY_IPS=["10.0.0.0/8"]):
            self.assertEqual(_client_ip(request), "1.2.3.4")

    def test_remote_addr_outside_cidr_is_not_trusted(self):
        request = self.factory.post(
            "/",
            HTTP_X_FORWARDED_FOR="1.2.3.4",
            REMOTE_ADDR="8.8.8.8",
        )
        with override_settings(TRUSTED_PROXY_IPS=["10.0.0.0/8"]):
            self.assertEqual(_client_ip(request), "8.8.8.8")

    def test_invalid_cidr_entry_is_skipped_not_fatal(self):
        # An operator typo in TRUSTED_PROXY_IPS should not 500 every
        # request; the bad entry is logged and ignored, the valid one
        # still works.
        request = self.factory.post(
            "/",
            HTTP_X_FORWARDED_FOR="1.2.3.4",
            REMOTE_ADDR="127.0.0.1",
        )
        with override_settings(TRUSTED_PROXY_IPS=["not-an-ip", "127.0.0.1"]):
            self.assertEqual(_client_ip(request), "1.2.3.4")


@override_settings(ALLOWED_HOSTS=["testserver"])
class TestRequestLogPrivacy(TestCase):
    def setUp(self):
        self.client = APIClient()

    @patch("api.validators.environment.banned_ip_address", ["198.51.100.242"])
    def test_banned_request_does_not_log_or_return_raw_ip(self):
        url = reverse("collateral", kwargs={"environment": "preprod"})
        with self.assertLogs("api", level="DEBUG") as captured:
            response = self.client.post(
                url,
                {"tx": "deadbeef"},
                format="json",
                REMOTE_ADDR="198.51.100.242",
            )
        combined = "\n".join(captured.output) + response.content.decode()
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("198.51.100.242", combined)

    @override_settings(METRICS_ENABLED=True, METRICS_ALLOW_IPS=["127.0.0.1"])
    def test_rejected_metrics_request_does_not_log_raw_ip(self):
        with self.assertLogs("api", level="WARNING") as captured:
            response = self.client.get("/metrics", REMOTE_ADDR="198.51.100.243")
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("198.51.100.243", "\n".join(captured.output))
