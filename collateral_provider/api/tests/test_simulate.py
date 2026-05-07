import unittest
from unittest.mock import Mock, patch

import requests
from django.test import override_settings

from api.simulate import UpstreamUnavailable, evaluate_transaction


def _mock_response(status_code: int, json_value=None, json_raises=None):
    """Helper: build a Mock that looks like a requests.Response."""
    response = Mock()
    response.status_code = status_code
    response.text = "" if json_value is None else str(json_value)
    if json_raises is not None:
        response.json.side_effect = json_raises
    else:
        response.json.return_value = json_value
    return response


class TestEvaluateTransaction(unittest.TestCase):
    @patch("api.simulate.requests.post")
    def test_returns_parsed_json_on_2xx_success(self, mock_post):
        mock_post.return_value = _mock_response(200, {"jsonrpc": "2.0", "result": []})

        result = evaluate_transaction("deadbeef", "preprod")
        self.assertEqual(result, {"jsonrpc": "2.0", "result": []})

        # URL comes from settings.ENVIRONMENTS[<env>]['KOIOS_URL'].
        call_url = mock_post.call_args[0][0]
        self.assertEqual(call_url, "https://preprod.koios.rest/api/v1/ogmios")

    @patch("api.simulate.requests.post")
    def test_mainnet_uses_api_subdomain(self, mock_post):
        mock_post.return_value = _mock_response(200, {"result": []})

        evaluate_transaction("deadbeef", "mainnet")
        call_url = mock_post.call_args[0][0]
        self.assertEqual(call_url, "https://api.koios.rest/api/v1/ogmios")

    @patch("api.simulate.requests.post")
    def test_unknown_environment_raises_upstream_unavailable(self, mock_post):
        with self.assertRaises(UpstreamUnavailable):
            evaluate_transaction("deadbeef", "fakenet")
        mock_post.assert_not_called()

    @patch("api.simulate.requests.post")
    def test_url_can_be_overridden_via_settings(self, mock_post):
        mock_post.return_value = _mock_response(200, {"result": []})
        with override_settings(ENVIRONMENTS={
            "preprod": {
                "NETWORK": "--testnet-magic 1",
                "TXID": "00" * 32,
                "TXIDX": 0,
                "KOIOS_URL": "https://my-koios.example.com/ogmios",
            },
        }):
            evaluate_transaction("deadbeef", "preprod")
        self.assertEqual(
            mock_post.call_args[0][0], "https://my-koios.example.com/ogmios"
        )

    @patch("api.simulate.requests.post")
    def test_payload_carries_jsonrpc_envelope(self, mock_post):
        mock_post.return_value = _mock_response(200, {"result": []})
        evaluate_transaction("cafebabe", "mainnet")
        sent_json = mock_post.call_args.kwargs["json"]
        self.assertEqual(sent_json["jsonrpc"], "2.0")
        self.assertEqual(sent_json["method"], "evaluateTransaction")
        self.assertEqual(sent_json["params"]["transaction"]["cbor"], "cafebabe")

    @patch("api.simulate.requests.post")
    def test_passes_timeout_to_requests(self, mock_post):
        mock_post.return_value = _mock_response(200, {"result": []})
        evaluate_transaction("deadbeef", "preprod")
        self.assertIsNotNone(mock_post.call_args.kwargs.get("timeout"))

    # Network failure cases ------------------------------------------------

    @patch("api.simulate.requests.post")
    def test_timeout_raises_upstream_unavailable(self, mock_post):
        mock_post.side_effect = requests.Timeout("read timed out")
        with self.assertRaises(UpstreamUnavailable) as ctx:
            evaluate_transaction("deadbeef", "preprod")
        self.assertIn("preprod", str(ctx.exception))

    @patch("api.simulate.requests.post")
    def test_connection_error_raises_upstream_unavailable(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("dns failed")
        with self.assertRaises(UpstreamUnavailable):
            evaluate_transaction("deadbeef", "preprod")

    # HTTP status handling -------------------------------------------------

    @patch("api.simulate.requests.post")
    def test_4xx_with_jsonrpc_error_body_returned_as_verdict(self, mock_post):
        # Koios may legitimately use a 4xx status to signal a tx-level
        # error (rather than 200 + {"error": ...}). Either way it's a real
        # verdict on the user's transaction, not an outage. Must NOT raise
        # UpstreamUnavailable — the caller relies on inspecting "result".
        body = {"jsonrpc": "2.0", "error": {"code": -32602, "message": "Bad inputs"}}
        mock_post.return_value = _mock_response(400, body)

        result = evaluate_transaction("deadbeef", "preprod")
        self.assertEqual(result, body)
        self.assertNotIn("result", result)

    @patch("api.simulate.requests.post")
    def test_4xx_with_non_json_body_raises_upstream_unavailable(self, mock_post):
        # If the body isn't even JSON, Koios is hosed in some way that
        # we shouldn't blame on the user's tx.
        mock_post.return_value = _mock_response(400, json_raises=ValueError("not json"))
        with self.assertRaises(UpstreamUnavailable):
            evaluate_transaction("deadbeef", "preprod")

    @patch("api.simulate.requests.post")
    def test_5xx_with_json_body_raises_upstream_unavailable(self, mock_post):
        # Server errors are server-side — even with a JSON body, this is
        # not a verdict on the tx.
        mock_post.return_value = _mock_response(503, {"error": "scheduled maintenance"})
        with self.assertRaises(UpstreamUnavailable):
            evaluate_transaction("deadbeef", "preprod")

    @patch("api.simulate.requests.post")
    def test_5xx_with_non_json_body_raises_upstream_unavailable(self, mock_post):
        mock_post.return_value = _mock_response(500, "<html>Server error</html>")
        # The mock above sets json_value="<html>...", which the real
        # response.json() would reject. Force the side_effect explicitly.
        mock_post.return_value = _mock_response(500, json_raises=ValueError("html"))
        with self.assertRaises(UpstreamUnavailable):
            evaluate_transaction("deadbeef", "preprod")

    @patch("api.simulate.requests.post")
    def test_2xx_with_non_json_body_raises_upstream_unavailable(self, mock_post):
        # Unlikely from a real Koios but defensible — a 200 with an
        # unparseable body still isn't a verdict.
        mock_post.return_value = _mock_response(200, json_raises=ValueError("not json"))
        with self.assertRaises(UpstreamUnavailable):
            evaluate_transaction("deadbeef", "preprod")
