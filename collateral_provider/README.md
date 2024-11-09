### local testing query

This is just for testing locally

```bash
# put in some cbor hex here
cbor_hex=""

curl -X POST http://127.0.0.1:8000/preprod/collateral/ \
  -H 'Content-Type: application/json' \
  -d '{
        "tx_body": "'${cbor_hex}'"
      }'
```