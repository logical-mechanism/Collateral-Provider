#!/bin/sh
# Container entrypoint.
#
# Materializes signing keys onto a tmpfs path if they were supplied via
# encrypted env vars (the common DigitalOcean App Platform pattern):
#
#   SKEY_CONTENTS=<full JSON of payment.skey, OR just the cborHex value>
#   VKEY_CONTENTS=<full JSON of payment.vkey, OR just the cborHex value>
#
# The "just the cborHex value" form (e.g. 5820abc...def) exists because
# DO App Platform's spec parser treats `{` / `}` as template syntax and
# rejects pasted JSON with errors like 'Unexpected "}" at <pos>'. If
# the value starts with `{` we trust it's full JSON and write it as-is;
# otherwise we treat it as a bare cborHex string and wrap it in the
# minimal Cardano-CLI envelope get_key_from_file() expects.
#
# If those env vars are unset the script does nothing — whatever
# SKEY_PATH / VKEY_PATH the operator configured (e.g. a mounted volume)
# is used as-is.
#
# Why a tmpfs path: the materialized files live under /run, which is a
# tmpfs on most container runtimes; they do not persist across container
# restarts and are not written to the image layers.

set -eu

KEYDIR=/run/keys
mkdir -p "$KEYDIR"

write_key() {
    # $1 = env var content, $2 = output path, $3 = JSON `type` field used
    # when wrapping a bare cborHex value.
    contents="$1"
    out="$2"
    keytype="$3"
    umask 077
    case "$contents" in
        '{'*)
            printf '%s' "$contents" > "$out"
            ;;
        *)
            printf '{"type":"%s","description":"","cborHex":"%s"}' \
                "$keytype" "$contents" > "$out"
            ;;
    esac
}

if [ -n "${SKEY_CONTENTS:-}" ]; then
    write_key "$SKEY_CONTENTS" "$KEYDIR/payment.skey" \
        "PaymentSigningKeyShelley_ed25519"
    SKEY_PATH="$KEYDIR/payment.skey"
    export SKEY_PATH
    unset SKEY_CONTENTS
fi

if [ -n "${VKEY_CONTENTS:-}" ]; then
    write_key "$VKEY_CONTENTS" "$KEYDIR/payment.vkey" \
        "PaymentVerificationKeyShelley_ed25519"
    VKEY_PATH="$KEYDIR/payment.vkey"
    export VKEY_PATH
    unset VKEY_CONTENTS
fi

exec "$@"
