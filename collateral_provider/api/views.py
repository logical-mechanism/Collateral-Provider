import json
import logging
import os
from typing import ClassVar

from django.conf import settings
from django.http import HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect, render
from drf_spectacular.utils import (
    OpenApiExample,
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    inline_serializer,
)
from rest_framework import serializers, status, throttling
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import ProvideCollateralSerializer
from .signature import witness_tx_cbor

logger = logging.getLogger("api")


def _known_hosts_path() -> str:
    return os.path.join(os.path.dirname(settings.BASE_DIR), "known.hosts.json")


def _load_known_hosts() -> dict:
    with open(_known_hosts_path()) as f:
        return json.load(f)


class ProvideCollateralThrottle(throttling.AnonRateThrottle):
    # The real bottleneck is the Koios evaluation call, not us. 60/min/IP is
    # generous for legit clients (one tx per second) and tight enough that a
    # single bad actor can't exhaust an upstream rate limit on their own.
    rate = "60/min"


class ProvideCollateralView(APIView):
    throttle_classes: ClassVar[list] = [ProvideCollateralThrottle]

    @extend_schema(
        operation_id="provide_collateral",
        summary="Sign a transaction that uses this provider's collateral",
        description=(
            "Validate the submitted Cardano transaction CBOR against the "
            "collateral-usage contract and, if it passes, return a vkey "
            "witness for it. Validation includes: collateral UTxO matches "
            "the configured one for this network, the provider PKH appears "
            "in required signers, the collateral is not in inputs, the "
            "is_valid flag is true, and Koios `evaluateTransaction` accepts "
            "the tx. Rate limited to 60 req/min per IP."
        ),
        parameters=[
            OpenApiParameter(
                name="environment",
                location=OpenApiParameter.PATH,
                description="One of the configured networks (e.g. `preprod`, `mainnet`).",
                required=True,
                type=str,
            ),
        ],
        request=ProvideCollateralSerializer,
        responses={
            200: OpenApiResponse(
                response=inline_serializer(
                    name="WitnessResponse",
                    fields={"witness": serializers.CharField()},
                ),
                description="Witness CBOR (hex). Decoded shape: `[0, [pubkey, signature]]`.",
            ),
            400: OpenApiResponse(description="Validation error — invalid environment, invalid CBOR, or tx fails the collateral-usage rules."),
            429: OpenApiResponse(description="Rate limit exceeded."),
            503: OpenApiResponse(description="Validation upstream (Koios) is unavailable; try again later."),
        },
        examples=[
            OpenApiExample(
                "Sample request",
                value={"tx_body": "84a900d901028182582000...f5f6"},
                request_only=True,
            ),
            OpenApiExample(
                "Sample success",
                value={"witness": "8200825820...5840..."},
                response_only=True,
            ),
        ],
    )
    def post(self, request, environment):
        return self._post(request, environment)

    def http_method_not_allowed(self, request, *args, **kwargs):
        ip_address = self.get_client_ip(request)
        logger.warning(
            f"Method Not Allowed From IP: {ip_address} "
            f"Method: {request.method} Path: {request.path}"
        )
        return Response(
            {"detail": "Method Not Allowed"},
            status=status.HTTP_405_METHOD_NOT_ALLOWED,
        )

    def _post(self, request, environment):
        ip_address = self.get_client_ip(request)
        logger.debug(f"Request Received From IP: {ip_address} For Environment: {environment}")

        env_settings = settings.ENVIRONMENTS.get(environment)
        if not env_settings:
            logger.error(f"Invalid Environment {environment} From IP: {ip_address}")
            return Response(
                {"error": "Invalid Environment"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = ProvideCollateralSerializer(
            data=request.data,
            context={
                "environment": environment,
                "env_settings": env_settings,
                "ip_address": ip_address,
                "networks": list(settings.ENVIRONMENTS.keys()),
            },
        )
        if not serializer.is_valid():
            logger.error(f"Invalid Data From IP: {ip_address}: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        tx_body_cbor = serializer.validated_data["tx_body"]
        witness_cbor = witness_tx_cbor(tx_body_cbor, settings.SKEY_PATH, settings.VKEY_PATH)
        logger.debug(f"Witnessed Tx From IP: {ip_address} On Environment: {environment}")
        return Response({"witness": witness_cbor}, status=status.HTTP_200_OK)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")


def landing_page(request):
    """Render the public-facing landing page. Shows the provider's PKH so a
    user can confirm they're talking to the right provider, and the network
    config from known.hosts.json keyed by that PKH."""
    try:
        hosts = _load_known_hosts()
    except FileNotFoundError:
        hosts = {}
    networks = hosts.get(settings.PKH, "Public Key Hash Not Found In Known Hosts")
    return render(
        request,
        "api/landing.html",
        {"pkh": settings.PKH, "networks_json": json.dumps(networks, indent=4)},
    )


def known_hosts_view(request):
    """Return the full known-hosts registry as JSON."""
    try:
        return JsonResponse(_load_known_hosts())
    except FileNotFoundError:
        return JsonResponse({"error": "File Not Found"}, status=404)


def custom_page_not_found(request, exception):
    return redirect("/")


def custom_disallowed_host_handler(request, exception):
    logger.warning(f"DisallowedHost: {request.get_host()}")
    return HttpResponseBadRequest("Invalid Host Header")
