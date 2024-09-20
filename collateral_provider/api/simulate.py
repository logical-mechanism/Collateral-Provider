import requests


def evaluate_tx(tx_body_cbor_hex, environment, project_id):
    """
    Evaluate a Cardano transaction using the Blockfrost API.

    :param tx_body_cbor_hex: Hexadecimal string of the CBOR-encoded transaction body.
    :return: JSON response from the Blockfrost API.
    """
    url = f'https://cardano-{environment}.blockfrost.io/api/v0/utils/txs/evaluate'
    headers = {
        'Content-Type': 'application/cbor',
        'Accept': 'application/json',
        'project_id': project_id
    }

    # Send the POST request
    response = requests.post(url, headers=headers, data=tx_body_cbor_hex)

    # Check for HTTP errors
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        # You can add more detailed error handling here if needed
        raise e

    # Return the JSON response
    return response.json()
