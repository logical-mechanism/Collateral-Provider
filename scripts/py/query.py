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
    data = {
        "tx_body": tx_cbor
    }

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


# Example usage
if __name__ == "__main__":
    for _ in range(1000):
        try:
            tx_cbor = '84ab00d901028182582041921857027783d566a758c3c77e07804e75313f80c7d3eff63ed8964b467705010dd90102818258201d388e615da2dca607e28f704130d04e39da6f251d551d66d054b75607e0393f0012d901028182582004c9ee8e85ebe51a9702f0cdfab4b2d44dc57a083aeaf478f4829612017eff18010182a300581d705c0cfc947012e6f2b9da8968a592df56109179173d0e05bb37b8f31601821a0018dbfca1581cec0023109dc706d4f894e7b2a908fb715e3599dac3b51e3baa781876a158205eed0e1f746573740141921857027783d566a758c3c77e07804e75313f80c7d301028201d8185868d8799f583097f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb5830a06ac9cbf5044a9263a72ce83e6d02d290830c32f3a3b853dc0df631556462f1e39a1f861958bd9202815473a16b994dff82581d60a2d0bdf9260505f38e22ea0fb3bbedc327b7eaea628f9317bcbab9be1a024d08d81082581d60a2d0bdf9260505f38e22ea0fb3bbedc327b7eaea628f9317bcbab9be1a004718bb111a00053285021a000377030ed9010282581c7c24c22d1dc252d31f6022ff22ccc838c2ab83a461172d7c2dae61f4581ca2d0bdf9260505f38e22ea0fb3bbedc327b7eaea628f9317bcbab9be09a1581cec0023109dc706d4f894e7b2a908fb715e3599dac3b51e3baa781876a158205eed0e1f746573740141921857027783d566a758c3c77e07804e75313f80c7d3010b5820130bbefb6d657d98ec4995253b334f886eb53cb4b82a5cde64fc1860a4a88dd407582081c9ab8a4bcdccff7b0e928b51c085dae13ca4099cc42b89ba2d10228f5f8df9a105a1820100824474657374821a000136a41a016239eaf5d90103a100a1006461636162'  # Replace this with the actual tx_cbor value
            witness = collat_witness(tx_cbor, "preprod")
            print(witness)
        except Exception as e:
            print("Exception:", e)
            exit
