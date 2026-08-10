#!/usr/bin/env bash
#
# The whole end-to-end cycle: start a local instance, build a transaction that
# genuinely earns a witness, run tests/live_service.rs against it, stop.
#
#   ./scripts/e2e.sh
#
# What makes the witness real: the transaction mints one token under an
# always-true PlutusV3 policy, which gives the evaluator something to run, and
# commits body field 11 to those exact redeemer bytes and the network's current
# cost models. The service therefore fetches live protocol parameters, verifies
# the script-data binding, and runs live phase-2 evaluation before signing.
# Nothing is submitted and no funds move — the transaction names a real
# collateral UTxO in field 13 and never spends it, and its input belongs to
# someone else.
#
# The transaction builder is scripts/py/dummy_collateral_tx.py from the Python
# side of the repo. That is the only Python in this path and it is a test tool,
# not a runtime dependency: `cargo test` never needs it, and neither does the
# binary. Without python3 the script still runs everything except the final
# witness check, and says so.
set -euo pipefail

cd "$(dirname "$0")/.."

BIND="${COLLATERAL_BIND:-127.0.0.1:8099}"
BASE_URL="http://$BIND"
NETWORK="${COLLATERAL_NETWORK:-preprod}"
BUILDER="../scripts/py/dummy_collateral_tx.py"
PYTHON="${PYTHON:-python3}"

if curl -sf -o /dev/null --max-time 2 "$BASE_URL/livez" 2>/dev/null; then
    echo "error: something is already listening on $BIND" >&2
    echo "       stop it, or set COLLATERAL_BIND to a free address." >&2
    exit 1
fi

# Build here rather than inside the backgrounded server, so a cold compile
# spends its own time instead of eating the readiness budget below.
echo "==> building"
cargo build --quiet --release --locked
cargo build --quiet --release --locked --example derive_pkh

echo "==> starting a local instance"
./scripts/run-local.sh > /tmp/collateral-e2e.log 2>&1 &
server=$!
cleanup() {
    # run-local.sh execs the binary, so $server is the binary itself.
    kill "$server" 2>/dev/null || true
    wait "$server" 2>/dev/null || true
}
trap cleanup EXIT

for _ in $(seq 1 200); do
    curl -sf -o /dev/null "$BASE_URL/livez" 2>/dev/null && break
    kill -0 "$server" 2>/dev/null || { echo "server exited:"; cat /tmp/collateral-e2e.log; exit 1; }
    sleep 0.1
done
if ! curl -sf -o /dev/null "$BASE_URL/livez" 2>/dev/null; then
    echo "server never became ready:" >&2; cat /tmp/collateral-e2e.log >&2; exit 1
fi
echo "    up at $BASE_URL"

live_tx=""
if command -v "$PYTHON" > /dev/null && [ -f "$BUILDER" ] \
   && "$PYTHON" -c "import cbor2, requests" 2>/dev/null; then
    echo "==> building a transaction that earns a witness ($NETWORK)"
    # --dry-run prints the CBOR without POSTing, so the Rust test is what
    # actually exercises the endpoint.
    if build_output=$("$PYTHON" "$BUILDER" --network "$NETWORK" --url "$BASE_URL" --dry-run 2>&1); then
        live_tx=$(printf '%s\n' "$build_output" | sed -n 's/^tx cbor *: *//p' | tail -1)
    fi
    if [ -n "$live_tx" ]; then
        echo "    built ${#live_tx} hex characters"
    else
        echo "    could not build one; the full signing path will be skipped:" >&2
        printf '%s\n' "${build_output:-}" | tail -5 >&2
    fi
else
    echo "==> skipping transaction build (needs $PYTHON with cbor2 and requests)"
    echo "    the full signing path will report itself skipped"
fi

echo "==> running tests/live_service.rs"
COLLATERAL_BASE_URL="$BASE_URL" \
COLLATERAL_LIVE_TX="$live_tx" \
COLLATERAL_LIVE_NETWORK="$NETWORK" \
    cargo test --quiet --locked --test live_service -- --nocapture

echo "==> done"
