"""Orchestrator for the collateral-witnessing pipeline.

The serializer's job is to validate the *shape* of the incoming JSON.
This module's job is to run the actual business pipeline: ban / env /
CBOR / inputs / outputs / collateral / signers / upstream evaluation,
and — on success — sign the tx body and return the witness.

Keeping orchestration here (instead of in ``ProvideCollateralSerializer``)
means the serializer doesn't import the upstream HTTP client, the
validators don't depend on DRF, and unit tests can call ``issue_witness``
directly without building a serializer context.
"""

import logging

from django.conf import settings
from nacl.exceptions import RuntimeError as NaClRuntimeError
from rest_framework.exceptions import APIException

from api.signature import witness_tx_cbor
from api.validators.cbor import (
    check_cbor_hex,
    check_collateral,
    check_collateral_return,
    check_inputs,
    check_outputs,
    check_signers,
    check_tx_body,
)
from api.validators.environment import check_environment, check_ip_address
from api.validators.transaction import check_valid_tx

logger = logging.getLogger("api")


class SigningServiceUnavailable(APIException):
    status_code = 503
    default_detail = "Signing Service Unavailable"
    default_code = "signing_unavailable"


def issue_witness(
    *,
    tx_cbor: str,
    environment: str,
    env_settings: dict,
    ip_address: str | None,
    networks: list[str],
) -> tuple[str, str]:
    """Run the validator chain in cheap-to-expensive order; on success
    sign the tx body and return ``(witness_hex, tx_hash_hex)``.

    The first failure raises a DRF ``ValidationError`` (or
    ``UpstreamServiceUnavailable`` for the Koios path) and short-
    circuits the rest. The view's standard error handling pipeline
    turns either into the canonical ``{"detail": ...}`` envelope.
    """
    logger.debug("Validating collateral transaction")

    check_ip_address(ip_address)
    check_environment(environment, networks)

    tx_bytes = check_cbor_hex(tx_cbor)
    body = check_tx_body(tx_bytes)
    check_inputs(body, env_settings)
    check_outputs(body)
    check_collateral(body, env_settings)
    check_collateral_return(body, settings.PKH)
    check_signers(body, settings.PKH)

    # Most expensive check last: it's a remote HTTP call.
    check_valid_tx(tx_cbor, environment)

    try:
        return witness_tx_cbor(tx_cbor, settings.SKEY_PATH, settings.PKH)
    except (OSError, KeyError, TypeError, ValueError, NaClRuntimeError) as exc:
        logger.error("Signing identity became unavailable: %s", exc)
        raise SigningServiceUnavailable() from exc
