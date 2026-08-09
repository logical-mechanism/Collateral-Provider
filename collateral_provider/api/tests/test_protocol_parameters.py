import json
import unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from unittest.mock import Mock, patch

import requests
from django.test import SimpleTestCase, override_settings

from api.simulate import (
    PROTOCOL_PARAMETERS_MAX_RESPONSE_BYTES,
    ProtocolParametersUnavailable,
    _clear_protocol_cost_models_cache,
    _parse_protocol_cost_models,
    _protocol_cost_models_condition,
    _protocol_cost_models_refreshing,
    get_protocol_cost_models,
)

RPC_ID = "protocol-parameters-test-id"
RPC_METHOD = "queryLedgerState/protocolParameters"


def _response(status: int = 200, body: object | None = None) -> Mock:
    response = Mock()
    response.status_code = status
    response.headers = {}
    content = b"" if body is None else json.dumps(body).encode()
    response.iter_content.return_value = [content]
    return response


def _rpc_response(result: object) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": RPC_ID,
        "method": RPC_METHOD,
        "result": result,
    }


class TestProtocolCostModels(unittest.TestCase):
    def setUp(self):
        _clear_protocol_cost_models_cache()
        self.id_patcher = patch("api.simulate.secrets.token_hex", return_value=RPC_ID)
        self.id_patcher.start()

    def tearDown(self):
        self.id_patcher.stop()
        _clear_protocol_cost_models_cache()

    @patch("api.simulate._session.post")
    def test_parses_current_models_and_sends_correlated_request(self, mock_post):
        result = {
            "plutusCostModels": {
                "plutus:v1": [1, 2],
                "plutus:v2": [3],
                "plutus:v3": [-900, 4],
            }
        }
        mock_post.return_value = _response(body=_rpc_response(result))

        self.assertEqual(
            get_protocol_cost_models("preprod"),
            {0: (1, 2), 1: (3,), 2: (-900, 4)},
        )
        call = mock_post.call_args
        self.assertEqual(
            call.args[0], "https://preprod.koios.rest/api/v1/ogmios"
        )
        self.assertEqual(
            call.kwargs["json"],
            {"jsonrpc": "2.0", "id": RPC_ID, "method": RPC_METHOD},
        )
        self.assertIs(call.kwargs["stream"], True)
        self.assertIs(call.kwargs["allow_redirects"], False)

    @patch("api.simulate._session.post")
    def test_success_is_cached_and_return_value_cannot_mutate_cache(self, mock_post):
        body = _rpc_response({"plutusCostModels": {"plutus:v3": [1, 2]}})
        mock_post.return_value = _response(body=body)

        first = get_protocol_cost_models("preprod")
        first[2] = (999,)
        second = get_protocol_cost_models("preprod")

        self.assertEqual(second, {2: (1, 2)})
        mock_post.assert_called_once()

    @patch("api.simulate._session.post")
    def test_concurrent_cold_cache_uses_one_upstream_refresh(self, mock_post):
        body = _rpc_response({"plutusCostModels": {"plutus:v3": [1, 2]}})
        response = _response(body=body)
        content = json.dumps(body).encode()
        started = Event()
        release = Event()

        def delayed_chunks(*_args, **_kwargs):
            started.set()
            self.assertTrue(release.wait(timeout=2))
            yield content

        response.iter_content.side_effect = delayed_chunks
        mock_post.return_value = response

        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(get_protocol_cost_models, "preprod")
            self.assertTrue(started.wait(timeout=2))
            second = executor.submit(get_protocol_cost_models, "preprod")
            release.set()

            self.assertEqual(first.result(timeout=2), {2: (1, 2)})
            self.assertEqual(second.result(timeout=2), {2: (1, 2)})

        mock_post.assert_called_once()

    @patch("api.simulate._session.post")
    def test_failed_refresh_wakes_followers_and_allows_retry(self, mock_post):
        started = Event()
        release = Event()
        waiter_started = Event()
        failed_response = _response()

        def failed_chunks(*_args, **_kwargs):
            started.set()
            self.assertTrue(release.wait(timeout=2))
            raise requests.ConnectionError("stream failed")

        failed_response.iter_content.side_effect = failed_chunks
        mock_post.return_value = failed_response
        original_wait_for = _protocol_cost_models_condition.wait_for

        def observed_wait_for(predicate, timeout=None):
            waiter_started.set()
            return original_wait_for(predicate, timeout=timeout)

        with (
            patch.object(
                _protocol_cost_models_condition,
                "wait_for",
                side_effect=observed_wait_for,
            ),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            first = executor.submit(get_protocol_cost_models, "preprod")
            self.assertTrue(started.wait(timeout=2))
            second = executor.submit(get_protocol_cost_models, "preprod")
            self.assertTrue(waiter_started.wait(timeout=2))
            release.set()

            with self.assertRaises(ProtocolParametersUnavailable):
                first.result(timeout=2)
            with self.assertRaises(ProtocolParametersUnavailable):
                second.result(timeout=2)

        mock_post.return_value = _response(
            body=_rpc_response({"plutusCostModels": {"plutus:v3": [1, 2]}})
        )
        self.assertEqual(get_protocol_cost_models("preprod"), {2: (1, 2)})
        self.assertEqual(mock_post.call_count, 2)

    def test_follower_refresh_wait_timeout_fails_closed(self):
        cache_key = (
            "preprod",
            "https://preprod.koios.rest/api/v1/ogmios",
        )
        with _protocol_cost_models_condition:
            _protocol_cost_models_refreshing.add(cache_key)
        try:
            with (
                patch.object(
                    _protocol_cost_models_condition,
                    "wait_for",
                    return_value=False,
                ),
                self.assertRaises(ProtocolParametersUnavailable),
            ):
                get_protocol_cost_models("preprod", timeout=0.0)
        finally:
            with _protocol_cost_models_condition:
                _protocol_cost_models_refreshing.discard(cache_key)
                _protocol_cost_models_condition.notify_all()

    @patch("api.simulate._session.post")
    def test_cache_identity_includes_configured_url(self, mock_post):
        body = _rpc_response({"plutusCostModels": {"plutus:v2": [1]}})
        mock_post.return_value = _response(body=body)
        get_protocol_cost_models("preprod")

        with override_settings(
            ENVIRONMENTS={
                "preprod": {"KOIOS_URL": "https://operator.example/ogmios"}
            }
        ):
            get_protocol_cost_models("preprod")

        self.assertEqual(mock_post.call_count, 2)
        self.assertEqual(mock_post.call_args.args[0], "https://operator.example/ogmios")

    @patch("api.simulate._session.post")
    def test_timeout_and_request_failure_fail_closed(self, mock_post):
        for failure in (requests.Timeout("slow"), requests.ConnectionError("down")):
            with self.subTest(failure=failure):
                mock_post.side_effect = failure
                with self.assertRaises(ProtocolParametersUnavailable):
                    get_protocol_cost_models("preprod")

    @patch("api.simulate._session.post")
    def test_non_200_invalid_json_and_oversized_fail_closed(self, mock_post):
        cases = (
            _response(status=429),
            _response(body=None),
            _response(body=_rpc_response({"plutusCostModels": {"plutus:v2": [1]}})),
        )
        cases[1].iter_content.return_value = [b"not-json"]
        cases[2].iter_content.return_value = [
            b"x" * (PROTOCOL_PARAMETERS_MAX_RESPONSE_BYTES + 1)
        ]
        for response in cases:
            with self.subTest(status=response.status_code):
                mock_post.return_value = response
                with self.assertRaises(ProtocolParametersUnavailable):
                    get_protocol_cost_models("preprod")

    @patch("api.simulate._session.post")
    def test_pathological_json_parse_failures_fail_closed(self, mock_post):
        invalid_bodies = (
            b'{"number":' + (b"1" * 5000) + b"}",
            (b"[" * 2000) + (b"]" * 2000),
        )
        for body in invalid_bodies:
            with self.subTest(size=len(body)):
                response = _response()
                response.iter_content.return_value = [body]
                mock_post.return_value = response
                with self.assertRaises(ProtocolParametersUnavailable):
                    get_protocol_cost_models("preprod")

    @patch("api.simulate._session.post")
    def test_mismatched_jsonrpc_envelopes_fail_closed(self, mock_post):
        valid = _rpc_response({"plutusCostModels": {"plutus:v2": [1]}})
        malformed = (
            [],
            {**valid, "jsonrpc": "1.0"},
            {**valid, "id": "another-request"},
            {**valid, "method": "queryLedgerState/utxo"},
            {**valid, "error": {"code": -1}},
            {key: value for key, value in valid.items() if key != "result"},
        )
        for body in malformed:
            with self.subTest(body=body):
                mock_post.return_value = _response(body=body)
                with self.assertRaises(ProtocolParametersUnavailable):
                    get_protocol_cost_models("preprod")

    @patch("api.simulate._session.post")
    def test_malformed_cost_models_fail_closed(self, mock_post):
        malformed_models = (
            None,
            {},
            {"PlutusV3": [1]},
            {"plutus:v3": []},
            {"plutus:v3": [True]},
            {"plutus:v3": [1 << 63]},
            {"plutus:v3": [1] * 1025},
            {"plutus:v4": "not-a-list"},
        )
        for models in malformed_models:
            with self.subTest(models=models):
                result = {"plutusCostModels": models}
                mock_post.return_value = _response(body=_rpc_response(result))
                with self.assertRaises(ProtocolParametersUnavailable):
                    get_protocol_cost_models("preprod")

    @patch("api.simulate._session.post")
    @patch("api.simulate._upstream_slots")
    def test_local_capacity_exhaustion_skips_http(self, mock_slots, mock_post):
        mock_slots.acquire.return_value = False
        with self.assertRaises(ProtocolParametersUnavailable):
            get_protocol_cost_models("preprod")
        mock_post.assert_not_called()
        mock_slots.release.assert_not_called()


class UnknownPlutusLanguageTestCase(SimpleTestCase):
    """A future Plutus language must not take the whole service down.

    Rejecting the entire cost-model set on one unrecognized name turns every
    request into a 503 the moment a hard fork ships `plutus:v5` — including
    transactions that only use languages we already understand.
    """

    def test_unknown_language_is_skipped(self):
        parsed = _parse_protocol_cost_models(
            {
                "plutusCostModels": {
                    "plutus:v3": [1, 2, 3],
                    "plutus:v5": [4, 5, 6],
                }
            }
        )
        self.assertEqual(parsed, {2: (1, 2, 3)})

    def test_all_languages_unknown_fails_closed(self):
        with self.assertRaises(ProtocolParametersUnavailable):
            _parse_protocol_cost_models(
                {"plutusCostModels": {"plutus:v5": [1, 2, 3]}}
            )

    def test_known_languages_still_parsed_together(self):
        parsed = _parse_protocol_cost_models(
            {"plutusCostModels": {"plutus:v1": [1], "plutus:v2": [2]}}
        )
        self.assertEqual(parsed, {0: (1,), 1: (2,)})
