import json

import requests


def collat_witness(tx_cbor: str, network: str) -> str:
    """
    Inputs:
        tx_cbor: The transaction CBOR as a string.
        network: Either 'preprod' or 'mainnet'.

    Returns:
        The collateral witness if successful, otherwise raises an error.
    """
    url = f"https://www.giveme.my/{network}/collateral/"
    headers = {'Content-Type': 'application/json'}
    data = {"tx": tx_cbor}

    # Perform the POST request
    response = requests.post(url, headers=headers, json=data)

    # Check if the response is valid (status code 200)
    if response.status_code == 200:
        response_json = response.json()
        collat_witness = response_json.get('witness')

        # If 'witness' is present in the response, return it
        if collat_witness:
            return collat_witness
        else:
            # If no witness, raise an error with the full response
            error_message = json.dumps(response_json, indent=2)
            raise Exception(
                f"Error: Failed to retrieve witness. Response:\n{error_message}")
    else:
        # Raise an error if the request fails
        raise Exception(
            f"HTTP Error: {response.status_code} - {response.text}")


# Example usage: one request, against a network you choose.
#
# This deliberately does NOT loop. An earlier version fired 1000 back-to-back
# POSTs at the live provider on import-as-script, which is a self-inflicted
# denial of service and will trip the per-IP throttle immediately. For load
# testing use scripts/stress_test/locustfile.py against a staging instance.
if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} <preprod|mainnet> <tx-cbor-hex>")

    network, tx_cbor = sys.argv[1], sys.argv[2]
    try:
        print(collat_witness(tx_cbor, network))
    except Exception as exc:
        raise SystemExit(f"request failed: {exc}") from exc
