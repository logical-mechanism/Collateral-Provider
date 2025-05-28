import requests


def evaluate_transaction(tx_body_cbor_hex: str, environment: str) -> dict:
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

    # Return the result of the evaluation
    return response.json()
