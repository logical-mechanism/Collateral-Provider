# api/views.py

import json
import os
import tempfile

from django.conf import settings
from rest_framework import status, throttling
from rest_framework.response import Response
from rest_framework.views import APIView

from .cli import witness
from .serializers import ProvideCollateralSerializer


class ProvideCollateralThrottle(throttling.AnonRateThrottle):
    # set this to whatever makes sense
    rate = '1/min'


class ProvideCollateralView(APIView):
    throttle_classes = [ProvideCollateralThrottle]

    def post(self, request, environment):
        env_settings = settings.ENVIRONMENTS.get(environment)
        if not env_settings:
            return Response({"error": "Invalid environment specified."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = ProvideCollateralSerializer(
            data=request.data,
            context={
                'environment': environment,
                'env_settings': env_settings,
            }
        )
        if serializer.is_valid():
            tx_body_cbor = serializer.validated_data['tx_body']

            # we need the tx draft file
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tx_draft:
                tx_body_content = {
                    "type": "Unwitnessed Tx ConwayEra",
                    "description": "Ledger Cddl Format",
                    "cborHex": tx_body_cbor
                }
                json.dump(tx_body_content, tx_draft)
                tx_draft_file_path = tx_draft.name

            # need a temp file for the signed tx
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tx_witness:
                tx_witness_file_path = tx_witness.name

            # witness the tx draft
            witness(tx_draft_file_path, tx_witness_file_path,
                    env_settings['NETWORK'], settings.KEY_PATH, settings.CLI_PATH)

            # get the cborHex of the witness
            with open(tx_witness_file_path, 'r') as temp_file:
                witness_data = json.load(temp_file)
            try:
                witness_cbor = witness_data['cborHex']
            except KeyError as e:
                return Response(e, status=status.HTTP_400_BAD_REQUEST)

            # remove the temp files
            os.remove(tx_draft_file_path)
            os.remove(tx_witness_file_path)

            # if everything went ok return the cbor and 200
            return Response({'witness': witness_cbor}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
