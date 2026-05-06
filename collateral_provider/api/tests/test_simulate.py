import unittest
from unittest.mock import Mock, patch

import requests

from api.simulate import UpstreamUnavailable, evaluate_transaction


class TestEvaluateTransaction(unittest.TestCase):
    @patch("api.simulate.requests.post")
    def test_returns_parsed_json_on_success(self, mock_post):
        mock_post.return_value.raise_for_status = Mock()
        mock_post.return_value.json.return_value = {"jsonrpc": "2.0", "result": []}

        result = evaluate_transaction("deadbeef", "preprod")
        self.assertEqual(result, {"jsonrpc": "2.0", "result": []})

        # Sanity check: the URL is constructed correctly per environment.
        call_url = mock_post.call_args[0][0]
        self.assertEqual(call_url, "https://preprod.koios.rest/api/v1/ogmios")

    @patch("api.simulate.requests.post")
    def test_mainnet_uses_api_subdomain(self, mock_post):
        mock_post.return_value.raise_for_status = Mock()
        mock_post.return_value.json.return_value = {"result": []}

        evaluate_transaction("deadbeef", "mainnet")
        call_url = mock_post.call_args[0][0]
        self.assertEqual(call_url, "https://api.koios.rest/api/v1/ogmios")

    @patch("api.simulate.requests.post")
    def test_payload_carries_jsonrpc_envelope(self, mock_post):
        mock_post.return_value.raise_for_status = Mock()
        mock_post.return_value.json.return_value = {"result": []}

        evaluate_transaction("cafebabe", "preview")
        sent_json = mock_post.call_args.kwargs["json"]
        self.assertEqual(sent_json["jsonrpc"], "2.0")
        self.assertEqual(sent_json["method"], "evaluateTransaction")
        self.assertEqual(sent_json["params"]["transaction"]["cbor"], "cafebabe")

    @patch("api.simulate.requests.post")
    def test_timeout_raises_upstream_unavailable(self, mock_post):
        mock_post.side_effect = requests.Timeout("read timed out")
        with self.assertRaises(UpstreamUnavailable) as context:
            evaluate_transaction("deadbeef", "preprod")
        self.assertIn("preprod", str(context.exception))

    @patch("api.simulate.requests.post")
    def test_connection_error_raises_upstream_unavailable(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("dns failed")
        with self.assertRaises(UpstreamUnavailable):
            evaluate_transaction("deadbeef", "preprod")

    @patch("api.simulate.requests.post")
    def test_5xx_raises_upstream_unavailable(self, mock_post):
        # raise_for_status raises HTTPError on non-2xx — that's a RequestException.
        response = Mock()
        response.raise_for_status.side_effect = requests.HTTPError("500 Server Error")
        mock_post.return_value = response
        with self.assertRaises(UpstreamUnavailable):
            evaluate_transaction("deadbeef", "preprod")

    @patch("api.simulate.requests.post")
    def test_non_json_response_raises_upstream_unavailable(self, mock_post):
        response = Mock()
        response.raise_for_status = Mock()
        response.json.side_effect = ValueError("not json")
        mock_post.return_value = response
        with self.assertRaises(UpstreamUnavailable):
            evaluate_transaction("deadbeef", "preprod")

    @patch("api.simulate.requests.post")
    def test_passes_timeout_to_requests(self, mock_post):
        mock_post.return_value.raise_for_status = Mock()
        mock_post.return_value.json.return_value = {"result": []}

        evaluate_transaction("deadbeef", "preprod")
        # Default is the (connect, read) tuple.
        self.assertIsNotNone(mock_post.call_args.kwargs.get("timeout"))
