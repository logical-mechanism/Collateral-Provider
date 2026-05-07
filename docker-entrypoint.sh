#!/bin/sh
# Container entrypoint.
#
# Materializes signing keys onto a tmpfs path if they were supplied via
# encrypted env vars (the common DigitalOcean App Platform pattern):
#
#   SKEY_CONTENTS=<full JSON of payment.skey>
#   VKEY_CONTENTS=<full JSON of payment.vkey>
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

if [ -n "${SKEY_CONTENTS:-}" ]; then
    umask 077
    printf '%s' "$SKEY_CONTENTS" > "$KEYDIR/payment.skey"
    SKEY_PATH="$KEYDIR/payment.skey"
    export SKEY_PATH
    unset SKEY_CONTENTS
fi

if [ -n "${VKEY_CONTENTS:-}" ]; then
    umask 077
    printf '%s' "$VKEY_CONTENTS" > "$KEYDIR/payment.vkey"
    VKEY_PATH="$KEYDIR/payment.vkey"
    export VKEY_PATH
    unset VKEY_CONTENTS
fi

exec "$@"
