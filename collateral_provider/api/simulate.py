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


def evaluate_transaction(tx_body_cbor_hex, environment):
    # Set up the payload for the POST request
    payload = {
        "jsonrpc": "2.0",
        "method": "evaluateTransaction",
        "params": {
            "transaction": {
                "cbor": tx_body_cbor_hex
            }
        }
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json"
    }

    # Send the POST request
    prefix = "api" if environment == "mainnet" else environment
    response = requests.post(f"https://{prefix}.koios.rest/api/v1/ogmios", headers=headers, json=payload)

    # Check for HTTP errors
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        # You can add more detailed error handling here if needed
        raise e

    # Return the result of the evaluation
    return response.json()
