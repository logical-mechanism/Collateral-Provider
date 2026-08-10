#!/usr/bin/env bash
#
# Start a local collateral provider for testing.
#
# The point is to make the service reachable at a known address with a signing
# identity we actually hold, so tests/live_service.rs has something to talk to.
# It configures the instance to sponsor a REAL, unspent collateral UTxO — the
# reference provider's preprod one — while signing with this repo's
# development key. Nothing spends that UTxO: field 13 only names it, and the
# transactions built for testing are never submitted.
#
#   ./scripts/run-local.sh                 # foreground, Ctrl-C to stop
#   ./scripts/run-local.sh --print-env     # emit the environment and exit
#
# Override anything via the environment, e.g.
#   COLLATERAL_TXID=<txid> COLLATERAL_TXIDX=1 ./scripts/run-local.sh
set -euo pipefail

cd "$(dirname "$0")/.."

BIND="${COLLATERAL_BIND:-127.0.0.1:8099}"
SKEY="${SKEY_PATH:-$PWD/../collateral_provider/api/key/payment.skey}"
VKEY="${VKEY_PATH:-$PWD/../collateral_provider/api/key/payment.vkey}"
# The reference provider's preprod collateral UTxO. Real and unspent, which is
# what lets the evaluator resolve it; we never spend it.
TXID="${COLLATERAL_TXID:-ef18e00c412c06b74606c5e68901693c3974b2073dbec1dfd8b74f01af3102a1}"
TXIDX="${COLLATERAL_TXIDX:-0}"
WORKDIR="${COLLATERAL_LOCAL_DIR:-${TMPDIR:-/tmp}/collateral-provider-local}"

for key in "$SKEY" "$VKEY"; do
    if [ ! -r "$key" ]; then
        echo "error: cannot read $key" >&2
        echo "       set SKEY_PATH and VKEY_PATH to a Cardano CLI keypair you hold." >&2
        exit 1
    fi
done

mkdir -p "$WORKDIR"

# Build first so the PKH helper and the server come from the same tree.
cargo build --quiet --release --locked
cargo build --quiet --release --locked --example derive_pkh

PKH="$(./target/release/examples/derive_pkh "$VKEY")"
VKEY_HEX="$(sed -n 's/.*"cborHex"[[:space:]]*:[[:space:]]*"....\([0-9a-fA-F]*\)".*/\1/p' "$VKEY")"

# A registry describing THIS instance, so a transaction builder pointed at
# /known_hosts/ discovers the identity we are actually signing with rather than
# the production provider's. The url field is unused by those builders but must
# satisfy the registry validator, which requires absolute HTTPS.
cat > "$WORKDIR/known.hosts.json" <<JSON
{
  "$PKH": {
    "preprod": {
      "utxo": { "id": "$TXID", "idx": $TXIDX },
      "url": "https://localhost/preprod/collateral/"
    },
    "public_key": "$VKEY_HEX"
  }
}
JSON

cat > "$WORKDIR/env" <<ENV
PKH=$PKH
ENVIRONMENT=development
SKEY_PATH=$SKEY
VKEY_PATH=$VKEY
KNOWN_HOSTS_PATH=$WORKDIR/known.hosts.json
PREPROD_TXID=$TXID
PREPROD_TXIDX=$TXIDX
# Quoted: the value contains a space, and dotenvy stops at the first one.
PREPROD_NETWORK="--testnet-magic 1"
MAINNET_TXID=0000000000000000000000000000000000000000000000000000000000000000
MAINNET_TXIDX=0
MAINNET_NETWORK="--mainnet"
BIND_ADDRESS=$BIND
LOG_TO_CONSOLE=True
LOG_FORMAT=json
LOG_LEVEL=INFO
ENV

if [ "${1:-}" = "--print-env" ]; then
    cat "$WORKDIR/env"
    exit 0
fi

echo "pkh        : $PKH"
echo "collateral : $TXID#$TXIDX (preprod, real and unspent — never spent by this service)"
echo "listening  : http://$BIND"
echo "workdir    : $WORKDIR"
echo
echo "In another shell:"
echo "  COLLATERAL_BASE_URL=http://$BIND cargo test --test live_service -- --nocapture"
echo

# dotenvy reads ./.env relative to the working directory; keep the generated
# one out of the source tree by running from the workdir.
cp "$WORKDIR/env" "$WORKDIR/.env"
cd "$WORKDIR"
exec "$OLDPWD/target/release/collateral-provider"
