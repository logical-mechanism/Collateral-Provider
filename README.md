# Altruistic Collateral Provider API

This repo aims to provide the back-end code that allows anyone to run an altruistic collateral provider for other users using Cardano smart contracts. Users will build transactions executing smart contracts using one of the available collateral UTxOs and public key hashes. The `/collateral` endpoint includes the transaction CBOR in the HTTP POST data. The return data is a witness to the transaction to use that collateral.

The design of this repo is to allow a provider to host on just mainnet or any of the testnets. The back-end code does not require a full node. However, the code requires a blockfront API key for the networks used. Providers setting up their back end must configure the settings file to reflect which networks they want to provide collateral correctly. The collateral keys live in the `api/key` folder.

A single `payment.skey` must exist to witness the transaction. Each network will use the same payment key. Currently, five ADA is the suggested collateral amount.

Please reference a guide on setting up a server to serve the Django app. The repo provides a sample environment file.

### How do I use it?

A collateral UTxO is required when building a smart contract transaction on Cardano. Typically, the wallet creating the transaction provides the collateral UTxO. With the API, users can use one of the collateral UTxOs from the known hosts inside transactions. It is as simple as including a signer requirement for the collateral public key hash and the UTxO information inside the transaction. 

### Why should I use it?

There are situations where providing collateral is a security and privacy concern. This API allows many users to use the same collateral while maintaining a certain level of anonymity. In addition to privacy, it also provides a method for new users to have collateral without forcing them to set one up in their wallet.

### Example Use

Change preprod to mainnet or whichever network is available at the url you are using.

```bash
curl -X POST https://www.giveme.my/preprod/collateral/ \
  -H 'Content-Type: application/json' \
  -d '{
        "tx_body": "tx_body_cbor_here"
      }'
```

For more examples, please refer to the scripts folder.

## Setup

```bash
# Create a Python virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate

# Install required Python packages
pip install -r requirements.txt
```

## Testing

Enter into the `collateral_provider` folder.

```bash
cd collateral_provider
```

Run tests with:

```bash
python3 manage.py test
```

Run the server with:

```bash
python3 manage.py runserver
```