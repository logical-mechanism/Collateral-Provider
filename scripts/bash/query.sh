#!/usr/bin/env bash
set -e

collat_witness() {
  # Inputs: $1 = tx_cbor, $2 = network (preprod or mainnet)
  local tx_cbor=$1
  local network=$2

  # Perform the curl request and capture the response
  local response=$(curl -s -X POST "https://www.giveme.my/${network}/collateral/" \
    -H 'Content-Type: application/json' \
    -d '{
          "tx_body": "'"${tx_cbor}"'"
        }')

  # Check if the response contains a 'witness' field
  local collat_witness=$(echo "$response" | jq -r '.witness')

  # If the witness is present, return it, otherwise handle the error
  if [[ "$collat_witness" != "null" && -n "$collat_witness" ]]; then
    echo "$collat_witness"
  else
    # Optionally, capture the error message from the response
    local error_message=$(echo "$response")
    echo -e "\033[0;31m$error_message\033[0m"
    exit 1
  fi
}

# Example Usage

tx_cbor="84a900d9010282825820e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c500825820e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c5010dd90102818258201d388e615da2dca607e28f704130d04e39da6f251d551d66d054b75607e0393f0012d9010282825820680d6b17aeac96bd3c965f6e9a6b45082870e267ea260e4aeac31550719d315901825820724b724ec5c489dff4d70a2cf94389aac21f88193891a2d6b3e02b4e2997d395010182a300581d7025891024cd6915ab6f7d85d43869c7bfc7021b7008bad86e70a7c6ce011a001605bc028201d81843d87980a300581d70c757598c8d204251f0e102b5092adf5627aeed553911cd6f82bd315401821a00184476a1581c20d133fb8814f3f6e9aa7777d73aab7c8cdfa7d9b2d1c94ba0f94100a1582000aeb168c1c5a787d5de5cbc0760d078bcc51b22ba8fa69e432a89137f17d9f601028201d818585bd8799f1b00000192ea62da801b00000192ea676e601a000493e0581c20d133fb8814f3f6e9aa7777d73aab7c8cdfa7d9b2d1c94ba0f94100582000aeb168c1c5a787d5de5cbc0760d078bcc51b22ba8fa69e432a89137f17d9f6ff021a000186a0031a047eb7ff081a047eb5a60ed9010281581c7c24c22d1dc252d31f6022ff22ccc838c2ab83a461172d7c2dae61f40b582001ca3d633ca222424e36c1ba5a9cd5501fd4b19f3f6b136af820dd4b3ccdf349a105a282000082d87a8082000082000182d87980820000f5f6"
collat_witness "$tx_cbor" "preprod"
