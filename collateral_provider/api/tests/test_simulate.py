import json
import unittest
from unittest.mock import Mock, patch

import requests
from django.test import override_settings

from api.simulate import (
    UpstreamUnavailable,
    evaluate_transaction,
)

TEST_RPC_ID = "0123456789abcdef0123456789abcdef"


def _mock_response(status_code: int, json_value=None, json_raises=None):
    """Helper: build a Mock that looks like a requests.Response."""
    if isinstance(json_value, dict) and (
        "result" in json_value or "error" in json_value
    ):
        json_value = {
            "id": TEST_RPC_ID,
            "jsonrpc": "2.0",
            "method": "evaluateTransaction",
            **json_value,
        }
    response = Mock()
    response.status_code = status_code
    response.text = "" if json_value is None else str(json_value)
    raw_content = (
        b"<not-json>"
        if json_raises is not None
        else b"" if json_value is None else json.dumps(json_value).encode("utf-8")
    )
    response.content = raw_content
    response.headers = {}
    response.iter_content.return_value = [raw_content]
    if json_raises is not None:
        response.json.side_effect = json_raises
    else:
        response.json.return_value = json_value
    return response


class TestEvaluateTransaction(unittest.TestCase):
    def setUp(self):
        self.rpc_id_patcher = patch(
            "api.simulate.secrets.token_hex", return_value=TEST_RPC_ID
        )
        self.rpc_id_patcher.start()

    def tearDown(self):
        self.rpc_id_patcher.stop()

    @patch("api.simulate._session.post")
    @patch("api.simulate._upstream_slots")
    def test_local_capacity_exhaustion_fails_before_http(self, mock_slots, mock_post):
        mock_slots.acquire.return_value = False
        with self.assertRaises(UpstreamUnavailable):
            evaluate_transaction("deadbeef", "preprod")
        mock_post.assert_not_called()
        mock_slots.release.assert_not_called()

    @patch("api.simulate._session.post")
    def test_returns_parsed_json_on_2xx_success(self, mock_post):
        mock_post.return_value = _mock_response(200, {"jsonrpc": "2.0", "result": []})

        result = evaluate_transaction("deadbeef", "preprod")
        self.assertEqual(
            result,
            {
                "id": TEST_RPC_ID,
                "jsonrpc": "2.0",
                "method": "evaluateTransaction",
                "result": [],
            },
        )

        # URL comes from settings.ENVIRONMENTS[<env>]['KOIOS_URL'].
        call_url = mock_post.call_args[0][0]
        self.assertEqual(call_url, "https://preprod.koios.rest/api/v1/ogmios")

    @patch("api.simulate._session.post")
    def test_mainnet_uses_api_subdomain(self, mock_post):
        mock_post.return_value = _mock_response(200, {"result": []})

        evaluate_transaction("deadbeef", "mainnet")
        call_url = mock_post.call_args[0][0]
        self.assertEqual(call_url, "https://api.koios.rest/api/v1/ogmios")

    @patch("api.simulate._session.post")
    def test_unknown_environment_raises_upstream_unavailable(self, mock_post):
        with self.assertRaises(UpstreamUnavailable):
            evaluate_transaction("deadbeef", "fakenet")
        mock_post.assert_not_called()

    @patch("api.simulate._session.post")
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

    @patch("api.simulate._session.post")
    def test_payload_carries_jsonrpc_envelope(self, mock_post):
        mock_post.return_value = _mock_response(200, {"result": []})
        evaluate_transaction("cafebabe", "mainnet")
        sent_json = mock_post.call_args.kwargs["json"]
        self.assertEqual(sent_json["jsonrpc"], "2.0")
        self.assertEqual(sent_json["id"], TEST_RPC_ID)
        self.assertEqual(sent_json["method"], "evaluateTransaction")
        self.assertEqual(sent_json["params"]["transaction"]["cbor"], "cafebabe")
        self.assertIs(mock_post.call_args.kwargs["stream"], True)
        self.assertIs(mock_post.call_args.kwargs["allow_redirects"], False)
        # Caller-supplied chain state is never sent to the evaluator.
        self.assertNotIn("additionalUtxo", sent_json["params"])

    @patch("api.simulate._session.post")
    def test_passes_timeout_to_requests(self, mock_post):
        mock_post.return_value = _mock_response(200, {"result": []})
        evaluate_transaction("deadbeef", "preprod")
        self.assertIsNotNone(mock_post.call_args.kwargs.get("timeout"))

    # Network failure cases ------------------------------------------------

    @patch("api.simulate._session.post")
    def test_timeout_raises_upstream_unavailable(self, mock_post):
        mock_post.side_effect = requests.Timeout("read timed out")
        with self.assertRaises(UpstreamUnavailable) as ctx:
            evaluate_transaction("deadbeef", "preprod")
        self.assertIn("preprod", str(ctx.exception))

    @patch("api.simulate._session.post")
    def test_connection_error_raises_upstream_unavailable(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("dns failed")
        with self.assertRaises(UpstreamUnavailable):
            evaluate_transaction("deadbeef", "preprod")
    # HTTP status handling -------------------------------------------------

    @patch("api.simulate._session.post")
    def test_4xx_with_jsonrpc_error_body_returned_as_verdict(self, mock_post):
        # Koios may legitimately use a 4xx status to signal a tx-level
        # error (rather than 200 + {"error": ...}). Either way it's a real
        # verdict on the user's transaction, not an outage. Must NOT raise
        # UpstreamUnavailable — the caller relies on inspecting "result".
        body = {
            "id": TEST_RPC_ID,
            "jsonrpc": "2.0",
            "method": "evaluateTransaction",
            "error": {"code": -32602, "message": "Bad inputs"},
        }
        mock_post.return_value = _mock_response(400, body)

        result = evaluate_transaction("deadbeef", "preprod")
        self.assertEqual(result, body)
        self.assertNotIn("result", result)

    @patch("api.simulate._session.post")
    def test_4xx_with_non_json_body_raises_upstream_unavailable(self, mock_post):
        # If the body isn't even JSON, Koios is hosed in some way that
        # we shouldn't blame on the user's tx.
        mock_post.return_value = _mock_response(400, json_raises=ValueError("not json"))
        with self.assertRaises(UpstreamUnavailable):
            evaluate_transaction("deadbeef", "preprod")

    @patch("api.simulate._session.post")
    def test_5xx_with_json_body_raises_upstream_unavailable(self, mock_post):
        # Server errors are server-side — even with a JSON body, this is
        # not a verdict on the tx.
        mock_post.return_value = _mock_response(503, {"error": "scheduled maintenance"})
        with self.assertRaises(UpstreamUnavailable):
            evaluate_transaction("deadbeef", "preprod")

    @patch("api.simulate._session.post")
    def test_operational_4xx_is_upstream_unavailable(self, mock_post):
        for status_code in (401, 403, 404, 429):
            with self.subTest(status_code=status_code):
                mock_post.return_value = _mock_response(
                    status_code, {"error": "not a transaction verdict"}
                )
                with self.assertRaises(UpstreamUnavailable):
                    evaluate_transaction("deadbeef", "preprod")

    @patch("api.simulate._session.post")
    def test_oversized_evaluation_response_is_upstream_unavailable(self, mock_post):
        mock_post.return_value = _mock_response(200, {"result": []})
        mock_post.return_value.iter_content.return_value = [
            b"x" * (1024 * 1024 + 1)
        ]
        with self.assertRaises(UpstreamUnavailable):
            evaluate_transaction("deadbeef", "preprod")

    @patch("api.simulate._session.post")
    def test_5xx_with_non_json_body_raises_upstream_unavailable(self, mock_post):
        mock_post.return_value = _mock_response(500, "<html>Server error</html>")
        # The mock above sets json_value="<html>...", which the real
        # response.json() would reject. Force the side_effect explicitly.
        mock_post.return_value = _mock_response(500, json_raises=ValueError("html"))
        with self.assertRaises(UpstreamUnavailable):
            evaluate_transaction("deadbeef", "preprod")

    @patch("api.simulate._session.post")
    def test_2xx_with_non_json_body_raises_upstream_unavailable(self, mock_post):
        # Unlikely from a real Koios but defensible — a 200 with an
        # unparseable body still isn't a verdict.
        mock_post.return_value = _mock_response(200, json_raises=ValueError("not json"))
        with self.assertRaises(UpstreamUnavailable):
            evaluate_transaction("deadbeef", "preprod")

    @patch("api.simulate._session.post")
    def test_pathological_json_parse_failures_are_upstream_unavailable(self, mock_post):
        invalid_bodies = (
            b'{"number":' + (b"1" * 5000) + b"}",
            (b"[" * 2000) + (b"]" * 2000),
        )
        for body in invalid_bodies:
            with self.subTest(size=len(body)):
                response = _mock_response(200, {"result": []})
                response.iter_content.return_value = [body]
                mock_post.return_value = response
                with self.assertRaises(UpstreamUnavailable):
                    evaluate_transaction("deadbeef", "preprod")

    @patch("api.simulate._session.post")
    def test_missing_or_mismatched_jsonrpc_id_is_upstream_unavailable(self, mock_post):
        for body in (
            {"jsonrpc": "2.0", "result": []},
            {"id": "another-request", "jsonrpc": "2.0", "result": []},
            [],
        ):
            with self.subTest(body=body):
                response = _mock_response(200, body)
                # _mock_response normally adds the fixed id to RPC-shaped
                # dictionaries, so restore the exact malformed vector.
                response.json.return_value = body
                response.content = json.dumps(body).encode("utf-8")
                response.iter_content.return_value = [response.content]
                mock_post.return_value = response
                with self.assertRaises(UpstreamUnavailable):
                    evaluate_transaction("deadbeef", "preprod")
