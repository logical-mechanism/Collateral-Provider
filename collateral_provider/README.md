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

### local testing query

This is just for testing locally

```bash
# put in some cbor hex here
cbor_hex=""

# anon users
curl -X POST http://127.0.0.1:8000/preprod/collateral/ \
  -H 'Content-Type: application/json' \
  -d '{
        "tx_body": "'${cbor_hex}'"
      }'
```

```bash
# put in some cbor hex here
cbor_hex=""
# put in the api token here
token=""

# token users users
curl -X POST http://127.0.0.1:8000/preprod/collateral/ \
  -H "Authorization: Token ${token}" \
  -H 'Content-Type: application/json' \
  -d '{
        "tx_body": "'${cbor_hex}'"
      }'
```