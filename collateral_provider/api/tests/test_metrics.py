"""Behavior tests for the /metrics endpoint and the metrics middleware.

The default state of the endpoint (off) is part of the contract: the
service must not leak that it has prometheus-style metrics unless an
operator turns the flag on, and even then must only respond to
allow-listed source IPs.
"""

from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient


@override_settings(ALLOWED_HOSTS=["testserver"])
class TestMetricsEndpoint(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = "/metrics"

    def tearDown(self):
        cache.clear()

    def test_404_when_disabled(self):
        # Default — METRICS_ENABLED=False — the endpoint must not exist.
        with override_settings(METRICS_ENABLED=False):
            response = self.client.get(self.url)
        self.assertEqual(response.status_code, 404)

    def test_403_when_enabled_but_ip_not_allowlisted(self):
        with override_settings(METRICS_ENABLED=True, METRICS_ALLOW_IPS=["10.0.0.1"]):
            response = self.client.get(self.url, REMOTE_ADDR="172.16.0.5")
        self.assertEqual(response.status_code, 403)

    def test_200_when_enabled_and_ip_allowlisted(self):
        with override_settings(METRICS_ENABLED=True, METRICS_ALLOW_IPS=["127.0.0.1"]):
            response = self.client.get(self.url, REMOTE_ADDR="127.0.0.1")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response["Content-Type"].startswith("text/plain"),
            f"got Content-Type={response['Content-Type']!r}",
        )

    def test_exposition_format_includes_our_metrics(self):
        with override_settings(METRICS_ENABLED=True, METRICS_ALLOW_IPS=["127.0.0.1"]):
            response = self.client.get(self.url, REMOTE_ADDR="127.0.0.1")
        body = response.content.decode()
        # Both metric families our code emits should appear by name.
        self.assertIn("collateral_http_requests_total", body)
        self.assertIn("collateral_koios_requests_total", body)
        # And the HELP / TYPE lines that prometheus-client always emits.
        self.assertIn("# HELP", body)
        self.assertIn("# TYPE", body)


@override_settings(ALLOWED_HOSTS=["testserver"])
class TestMetricsMiddleware(TestCase):
    """The middleware must observe /<env>/collateral/ requests and ignore
    everything else."""

    def setUp(self):
        self.client = APIClient()

    def tearDown(self):
        cache.clear()

    def test_collateral_path_increments_counter(self):
        from api.metrics import http_requests_total

        before = self._counter_value("preprod", "400")
        url = reverse("collateral", kwargs={"environment": "preprod"})
        self.client.post(url, {"tx": "not-hex"}, format="json")
        after = self._counter_value("preprod", "400")
        self.assertEqual(after - before, 1)
        # Histogram should also have observed at least one sample for preprod.
        self.assertGreater(
            sum(
                metric.samples[-1].value
                for metric in http_requests_total.collect()
            ),
            0,
        )

    def test_other_paths_do_not_emit_counter(self):
        # Hitting / shouldn't add to collateral_http_requests_total at all.
        before = self._total_collateral_requests()
        with override_settings(METRICS_ENABLED=True, METRICS_ALLOW_IPS=["127.0.0.1"]):
            self.client.get("/")
            self.client.get("/healthz")
            self.client.get("/known_hosts/")
        after = self._total_collateral_requests()
        self.assertEqual(before, after)

    def _counter_value(self, env: str, status: str) -> float:
        from api.metrics import http_requests_total
        for metric in http_requests_total.collect():
            for sample in metric.samples:
                if (
                    sample.name.endswith("_total")
                    and sample.labels.get("environment") == env
                    and sample.labels.get("status") == status
                ):
                    return sample.value
        return 0.0

    def _total_collateral_requests(self) -> float:
        from api.metrics import http_requests_total
        total = 0.0
        for metric in http_requests_total.collect():
            for sample in metric.samples:
                if sample.name.endswith("_total"):
                    total += sample.value
        return total


class TestKoiosMetricsRecorded(TestCase):
    """Each branch of the simulate.evaluate_transaction try/except should
    bump the right outcome label so an operator can tell timeout
    (probably-our-config) from http_error (probably-Koios-side) at a glance."""

    @patch("api.simulate.requests.post")
    def test_success_outcome(self, mock_post):
        from api.simulate import evaluate_transaction

        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"result": []}
        before = self._koios_outcome_value("preprod", "success")
        evaluate_transaction("deadbeef", "preprod")
        after = self._koios_outcome_value("preprod", "success")
        self.assertEqual(after - before, 1)

    @patch("api.simulate.requests.post")
    def test_tx_invalid_outcome(self, mock_post):
        from api.simulate import evaluate_transaction

        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"error": {"code": -32602}}
        before = self._koios_outcome_value("preprod", "tx_invalid")
        evaluate_transaction("deadbeef", "preprod")
        after = self._koios_outcome_value("preprod", "tx_invalid")
        self.assertEqual(after - before, 1)

    @patch("api.simulate.requests.post")
    def test_timeout_outcome(self, mock_post):
        import requests as _requests

        from api.simulate import UpstreamUnavailable, evaluate_transaction

        mock_post.side_effect = _requests.Timeout("read timed out")
        before = self._koios_outcome_value("preprod", "timeout")
        with self.assertRaises(UpstreamUnavailable):
            evaluate_transaction("deadbeef", "preprod")
        after = self._koios_outcome_value("preprod", "timeout")
        self.assertEqual(after - before, 1)

    def _koios_outcome_value(self, env: str, outcome: str) -> float:
        from api.metrics import koios_requests_total
        for metric in koios_requests_total.collect():
            for sample in metric.samples:
                if (
                    sample.name.endswith("_total")
                    and sample.labels.get("environment") == env
                    and sample.labels.get("outcome") == outcome
                ):
                    return sample.value
        return 0.0
