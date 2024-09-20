# Altruistic Collateral Provider API

This repo aims to provide the back-end code that allows anyone to run an altruistic collateral provider for other users using Cardano smart contracts. Users will build transactions executing smart contracts using one of the available collateral UTxOs and public key hashes. The `/collateral` endpoint includes the transaction CBOR in the HTTP POST data. The return data is a witness to the transaction to use that collateral.

The design of this repo is to allow a provider to host on just mainnet or any of the testnets. The back-end code does not require a full node. However, the code requires a blockfront API key for the networks used. Providers setting up their back end must configure the settings file to correctly reflect which networks they want to provide collateral. The code requires a cardano-cli binary to live in the `api/bin` folder. The collateral keys live in the `api/key` folder.

Please reference a guide to set up a server to serve the Django app. A sample environment file is provided.

### Example Use

```bash
curl -X POST https://www.giveme.my/preprod/collateral/ \
  -H 'Content-Type: application/json' \
  -d '{
        "tx_body": '${tx_body_cbor}'
      }'
```

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