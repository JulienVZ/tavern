#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Prepares a Tavern deployment:
#   - creates .env, Caddyfile and livekit.yaml from their .example files;
#   - generates every secret that is still empty in .env.
#
# Safe to run again: existing files and existing secrets are never modified.
#
# Secrets generated today: PostgreSQL password, LiveKit API key and secret.
# The OPAQUE server setup, the dedicated MLS external sender key and the TOTP
# encryption key are added with milestone M1, when the server can use them.

set -eu

cd "$(dirname "$0")/.."

random_hex() {
    # $1 = number of bytes
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex "$1"
    else
        od -An -N "$1" -tx1 /dev/urandom | tr -d ' \n'
    fi
}

copy_if_missing() {
    # $1 = source, $2 = destination
    if [ -e "$2" ]; then
        echo "kept     $2"
    else
        cp "$1" "$2"
        echo "created  $2"
    fi
}

get_value() {
    # $1 = variable name
    sed -n "s/^$1=//p" .env | head -n 1
}

set_if_empty() {
    # $1 = variable name, $2 = value
    if ! grep -q "^$1=" .env; then
        printf '%s=%s\n' "$1" "$2" >>.env
        echo "generated $1"
    elif [ -z "$(get_value "$1")" ]; then
        tmp=$(mktemp)
        awk -v name="$1" -v value="$2" '
            index($0, name "=") == 1 && !done { print name "=" value; done = 1; next }
            { print }
        ' .env >"$tmp"
        cat "$tmp" >.env
        rm -f "$tmp"
        echo "generated $1"
    else
        echo "kept     $1"
    fi
}

umask 077
copy_if_missing .env.example .env
chmod 600 .env
umask 022
copy_if_missing Caddyfile.example Caddyfile
copy_if_missing livekit.yaml.example livekit.yaml

set_if_empty POSTGRES_PASSWORD "$(random_hex 32)"
set_if_empty LIVEKIT_API_KEY "API$(random_hex 8)"
set_if_empty LIVEKIT_API_SECRET "$(random_hex 32)"

missing=""
for name in TAVERN_DOMAIN LIVEKIT_DOMAIN; do
    if [ -z "$(get_value "$name")" ]; then
        missing="$missing $name"
    fi
done

echo
if [ -n "$missing" ]; then
    echo "Next: edit deploy/.env and set:$missing"
    echo "Then: docker compose up -d"
else
    echo "Ready: docker compose up -d"
fi
echo "Keep deploy/.env private and back it up: it contains the instance secrets."
