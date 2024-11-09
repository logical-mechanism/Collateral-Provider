import json
import logging
import os
import tempfile

from django.conf import settings
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect
from rest_framework import status, throttling
from rest_framework.response import Response
from rest_framework.views import APIView

from .cli import witness
from .serializers import ProvideCollateralSerializer

logger = logging.getLogger('api')


class ProvideCollateralThrottle(throttling.AnonRateThrottle):
    # set this to whatever makes sense
    # the real limit here is the simulate api
    rate = '60/min'


class ProvideCollateralView(APIView):
    throttle_classes = [ProvideCollateralThrottle]

    def http_method_not_allowed(self, request, *args, **kwargs):
        ip_address = self.get_client_ip(request)
        logger.warning(f'Get request received from {ip_address} Method not allowed: {request.method} on {request.path}')
        return Response(
            {"detail": "Method not allowed."},
            status=status.HTTP_405_METHOD_NOT_ALLOWED
        )

    def post(self, request, environment):
        # Get client's IP address
        ip_address = self.get_client_ip(request)

        logger.debug(f'Request received from {ip_address} for environment: {environment}')

        # Check if the environment is valid
        networks = list(settings.ENVIRONMENTS.keys())
        env_settings = settings.ENVIRONMENTS.get(environment)
        if not env_settings:
            logger.error(f'Invalid environment "{environment}" from {ip_address}')
            return Response({"error": "Invalid environment specified."}, status=status.HTTP_400_BAD_REQUEST)

        # Log the incoming request data
        serializer = ProvideCollateralSerializer(
            data=request.data,
            context={
                'environment': environment,
                'env_settings': env_settings,
                'ip_address': ip_address,
                'networks': networks,
            }
        )

        if serializer.is_valid():
            tx_body_cbor = serializer.validated_data['tx_body']

            # Temporary files for tx draft and witness
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tx_draft:
                tx_body_content = {
                    "type": "Unwitnessed Tx ConwayEra",
                    "description": "Ledger Cddl Format",
                    "cborHex": tx_body_cbor
                }
                json.dump(tx_body_content, tx_draft)
                tx_draft_file_path = tx_draft.name

            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tx_witness:
                tx_witness_file_path = tx_witness.name

            # Witness the transaction
            witness(tx_draft_file_path, tx_witness_file_path, env_settings['NETWORK'], settings.KEY_PATH, settings.CLI_PATH)

            # Get the cborHex of the witness
            try:
                with open(tx_witness_file_path, 'r') as temp_file:
                    witness_data = json.load(temp_file)
                witness_cbor = witness_data['cborHex']
            except KeyError as e:
                logger.error(f'Missing cborHex in witness data for {ip_address}')
                return Response(e, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                logger.error(f'Error processing witness for {ip_address}: {str(e)}')
                return Response({"error": "Failed to process the witness."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            finally:
                # Remove temporary files
                os.remove(tx_draft_file_path)
                os.remove(tx_witness_file_path)

            logger.debug(f'Successfully processed witness for {ip_address} and environment {environment}')

            # Return the witness data
            return Response({'witness': witness_cbor}, status=status.HTTP_200_OK)

        else:
            logger.error(f'Invalid data from {ip_address}: {serializer.errors}')
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # Get the first IP from the list
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


# very simply landing page that auto loads from the known.host.json file
def landing_page(request):
    # Get the parent directory of BASE_DIR
    parent_dir = os.path.abspath(os.path.join(settings.BASE_DIR, os.pardir))
    # Load the JSON file from the parent directory
    json_file_path = os.path.join(parent_dir, 'known.hosts.json')
    with open(json_file_path, 'r') as json_file:
        data = json.load(json_file)
    content = data.get(
        settings.PKH, "Public Key Hash Not Found In Known Hosts")
    return HttpResponse(f"""
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta name="description" content="An altruistic collateral provider that offers complimentary access to collateral UTxOs on Cardano.">
                <meta name="keywords" content="collateral provider, Cardano, blockchain, decentralized, smart contracts, networks">
                <meta name="robots" content="index, follow">
                <link rel="canonical" href="https://giveme.my">
                <meta property="og:title" content="Cardano Collateral Provider">
                <meta property="og:description" content="An altruistic collateral provider that offers complimentary access to collateral UTxOs on Cardano."">
                <meta property="og:url" content="https://giveme.my">
                <meta property="og:type" content="website">
                <meta property="og:image" content="{settings.STATIC_URL}android-chrome-512x512.png">
                <link rel="icon" type="image/x-icon" href="{settings.STATIC_URL}favicon.ico">
                <title>Cardano Collateral Provider</title>
            </head>
            <body>
                <header>
                    <h1>Cardano Collateral Provider</h1>
                </header>
                <main>
                    <section>
                        <h2>Required Signer Hash:</h2>
                        <p>{settings.PKH}</p>
                    </section>
                    <section>
                        <h2>Available Networks:</h2>
                        <pre>{json.dumps(content, indent=4)}</pre>
                    </section>
                    <section>
                        <h2>Resources</h2>
                        <ul>
                            <li>
                                <a href="https://github.com/logical-mechanism/Collateral-Provider?tab=readme-ov-file#example-use" target="_blank" rel="noopener noreferrer">
                                    View GitHub for Example Use
                                </a>
                            </li>
                            <li>
                                <a href="/known_hosts/">
                                    View Known Collateral Providers
                                </a>
                            </li>
                        </ul>
                    </section>
                </main>
                <footer>
                    <p>Created By Logical Mechanism LLC</p>
                </footer>
            </body>
        </html>

    """)


def custom_page_not_found(request, exception):
    return redirect('/')


def known_hosts_view(request):
    # Get the parent directory of BASE_DIR
    parent_dir = os.path.abspath(os.path.join(settings.BASE_DIR, os.pardir))
    # Load the JSON file from the parent directory
    json_file_path = os.path.join(parent_dir, 'known.hosts.json')
    try:
        with open(json_file_path, 'r') as json_file:
            data = json.load(json_file)
    except FileNotFoundError:
        return JsonResponse({'error': 'File not found'}, status=404)
    # Return the JSON response
    return JsonResponse(data)


def custom_disallowed_host_handler(request, exception):
    logger.warning(f"DisallowedHost: {request.get_host()}")
    return HttpResponseBadRequest("Invalid Host Header")
