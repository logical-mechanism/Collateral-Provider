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
    @patch("api.simulate._session.post")
    def test_returns_parsed_json_on_2xx_success(self, mock_post):
        mock_post.return_value = _mock_response(200, {"jsonrpc": "2.0", "result": []})

        result = evaluate_transaction("deadbeef", "preprod")
        self.assertEqual(result, {"jsonrpc": "2.0", "result": []})

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
        self.assertEqual(sent_json["method"], "evaluateTransaction")
        self.assertEqual(sent_json["params"]["transaction"]["cbor"], "cafebabe")
        # additionalUtxo only appears when the caller provided one.
        self.assertNotIn("additionalUtxo", sent_json["params"])

    @patch("api.simulate._session.post")
    def test_additional_utxos_flattened_into_v6_utxo_objects(self, mock_post):
        # Public API takes [txin, txout] pairs (per the prose docs) but
        # Ogmios v6's JSON-RPC schema rejects array-shaped entries with
        # "parsing TxIn failed, expected Object, but encountered Array".
        # simulate.py merges the pair into one flat Utxo object before
        # forwarding so the call actually reaches script evaluation.
        mock_post.return_value = _mock_response(200, {"result": []})
        txin = {"transaction": {"id": "ab" * 32}, "index": 0}
        txout = {"address": "addr_test1...", "value": {"ada": {"lovelace": 1_000_000}}}
        evaluate_transaction("cafebabe", "preprod", additional_utxos=[[txin, txout]])
        params = mock_post.call_args.kwargs["json"]["params"]
        self.assertEqual(params["additionalUtxo"], [{**txin, **txout}])

    @patch("api.simulate._session.post")
    def test_additional_utxos_flattening_preserves_optional_output_fields(self, mock_post):
        # datum/datumHash/script live on the output side of the pair and
        # must survive the merge so script evaluation sees them.
        mock_post.return_value = _mock_response(200, {"result": []})
        txin = {"transaction": {"id": "cd" * 32}, "index": 3}
        txout = {
            "address": "addr_test1...",
            "value": {"ada": {"lovelace": 2_000_000}},
            "datumHash": "ef" * 32,
            "script": {"language": "plutus:v3", "cbor": "deadbeef"},
        }
        evaluate_transaction("cafebabe", "preprod", additional_utxos=[[txin, txout]])
        sent = mock_post.call_args.kwargs["json"]["params"]["additionalUtxo"]
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["transaction"], txin["transaction"])
        self.assertEqual(sent[0]["index"], txin["index"])
        self.assertEqual(sent[0]["address"], txout["address"])
        self.assertEqual(sent[0]["datumHash"], txout["datumHash"])
        self.assertEqual(sent[0]["script"], txout["script"])

    @patch("api.simulate._session.post")
    def test_additional_utxos_flat_object_entries_pass_through(self, mock_post):
        # When a caller already sends Ogmios v6's flat Utxo shape (e.g.
        # they built against Koios docs directly), no merge is needed —
        # the entry is forwarded unchanged.
        mock_post.return_value = _mock_response(200, {"result": []})
        flat = {
            "transaction": {"id": "ab" * 32},
            "index": 0,
            "address": "addr_test1...",
            "value": {"ada": {"lovelace": 1_000_000}},
        }
        evaluate_transaction("cafebabe", "preprod", additional_utxos=[flat])
        sent = mock_post.call_args.kwargs["json"]["params"]["additionalUtxo"]
        self.assertEqual(sent, [flat])

    @patch("api.simulate._session.post")
    def test_additional_utxos_mixed_pair_and_flat_entries(self, mock_post):
        # A single request may interleave both accepted input shapes;
        # each is normalized independently to the flat wire shape.
        mock_post.return_value = _mock_response(200, {"result": []})
        txin = {"transaction": {"id": "ab" * 32}, "index": 0}
        txout = {"address": "addr_test1...", "value": {"ada": {"lovelace": 1_000_000}}}
        flat = {
            "transaction": {"id": "cd" * 32},
            "index": 1,
            "address": "addr_test1...other",
            "value": {"ada": {"lovelace": 2_000_000}},
        }
        evaluate_transaction(
            "cafebabe", "preprod", additional_utxos=[[txin, txout], flat]
        )
        sent = mock_post.call_args.kwargs["json"]["params"]["additionalUtxo"]
        self.assertEqual(sent, [{**txin, **txout}, flat])

    @patch("api.simulate._session.post")
    def test_empty_additional_utxos_omitted_from_payload(self, mock_post):
        mock_post.return_value = _mock_response(200, {"result": []})
        evaluate_transaction("cafebabe", "preprod", additional_utxos=[])
        self.assertNotIn(
            "additionalUtxo", mock_post.call_args.kwargs["json"]["params"]
        )

    @patch("api.simulate._session.post")
    def test_none_additional_utxos_omitted_from_payload(self, mock_post):
        mock_post.return_value = _mock_response(200, {"result": []})
        evaluate_transaction("cafebabe", "preprod", additional_utxos=None)
        self.assertNotIn(
            "additionalUtxo", mock_post.call_args.kwargs["json"]["params"]
        )

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
        body = {"jsonrpc": "2.0", "error": {"code": -32602, "message": "Bad inputs"}}
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
