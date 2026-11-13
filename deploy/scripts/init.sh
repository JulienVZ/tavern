#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Prepares a Tavern deployment:
#   - creates .env, Caddyfile and livekit.yaml from their .example files;
#   - generates every secret that is still empty in .env;
#   - makes sure the two domain names are set.
#
# Usage:
#   ./scripts/init.sh          real instance: asks for the domains when run in
#                              a terminal, otherwise lists what is missing
#   ./scripts/init.sh --dev    local test: fills in localhost names
#
# Safe to run again: existing files, values and secrets are never modified.
#
# Secrets: the PostgreSQL password and the LiveKit key pair are random values
# generated here. The four instance secrets (OPAQUE server setup, MLS external
# sender key, TOTP encryption key, handle privacy key) are produced by
# `tavern-server gen-secrets`, run in the server image. The first run builds
# that image, which takes a few minutes.

set -eu

dev=false
for arg in "$@"; do
    case "$arg" in
        --dev) dev=true ;;
        -h | --help)
            echo "usage: init.sh [--dev]"
            exit 0
            ;;
        *)
            echo "init.sh: unknown option $arg" >&2
            echo "usage: init.sh [--dev]" >&2
            exit 2
            ;;
    esac
done

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

set_value() {
    # $1 = variable name, $2 = value. Replaces the line, or appends it.
    if grep -q "^$1=" .env; then
        tmp=$(mktemp)
        awk -v name="$1" -v value="$2" '
            index($0, name "=") == 1 && !done { print name "=" value; done = 1; next }
            { print }
        ' .env >"$tmp"
        cat "$tmp" >.env
        rm -f "$tmp"
    else
        printf '%s=%s\n' "$1" "$2" >>.env
    fi
}

set_if_empty() {
    # $1 = variable name, $2 = value, $3 = verb shown to the user
    if [ -z "$(get_value "$1")" ]; then
        set_value "$1" "$2"
        echo "${3:-generated} $1"
    else
        echo "kept     $1"
    fi
}

is_host_name() {
    # Accepts letters, digits, dots and hyphens: a host name without scheme,
    # port or path.
    case "$1" in
        "" | *[!A-Za-z0-9.-]* | .* | *. | -*) return 1 ;;
        *) return 0 ;;
    esac
}

ask_host_name() {
    # $1 = variable name, $2 = question
    while [ -z "$(get_value "$1")" ]; do
        printf '%s: ' "$2"
        if ! read -r answer; then
            echo
            return 1
        fi
        if is_host_name "$answer"; then
            set_value "$1" "$answer"
            echo "set      $1"
        else
            echo "  Enter a host name only, such as chat.example.org (no https://, no port, no path)."
        fi
    done
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

if [ "$dev" = true ]; then
    set_if_empty TAVERN_DOMAIN localhost "set     "
    set_if_empty LIVEKIT_DOMAIN livekit.localhost "set     "
elif [ -t 0 ]; then
    if [ -z "$(get_value TAVERN_DOMAIN)" ] || [ -z "$(get_value LIVEKIT_DOMAIN)" ]; then
        echo
        echo "Two DNS names must point to this machine (see docs/self-hosting.md)."
        echo "For a test on your own computer, stop here and run: ./scripts/init.sh --dev"
        ask_host_name TAVERN_DOMAIN "Instance host name, e.g. chat.example.org" || true
        ask_host_name LIVEKIT_DOMAIN "LiveKit host name, e.g. livekit.example.org" || true
    fi
fi

missing=""
for name in TAVERN_DOMAIN LIVEKIT_DOMAIN; do
    if [ -z "$(get_value "$name")" ]; then
        missing="$missing $name"
    fi
done

echo
echo "Keep deploy/.env private and back it up together with the database:"
echo "it contains the instance secrets, and the database cannot be used without it."
echo

if [ -n "$missing" ]; then
    echo "NOT READY. These values are still empty in deploy/.env:" >&2
    for name in $missing; do
        echo "  - $name" >&2
    done
    echo "Set them (edit deploy/.env, or run this script again in a terminal)," >&2
    echo "or run ./scripts/init.sh --dev for a local test. Then: docker compose up -d" >&2
    exit 1
fi

instance_secrets="TAVERN_OPAQUE_SERVER_SETUP TAVERN_MLS_EXTERNAL_SENDER_KEY TAVERN_TOTP_ENCRYPTION_KEY TAVERN_HANDLE_PRIVACY_KEY"
need_instance_secrets=false
for name in $instance_secrets; do
    if [ -z "$(get_value "$name")" ]; then
        need_instance_secrets=true
    fi
done

if [ "$need_instance_secrets" = true ]; then
    echo "Generating the instance secrets (this builds the server image the first time)..."
    if ! generated=$(docker compose run --rm --no-deps -T server gen-secrets); then
        echo >&2
        echo "NOT READY. The instance secrets could not be generated." >&2
        echo "Check that Docker is running, then run this script again." >&2
        exit 1
    fi
    for name in $instance_secrets; do
        value=$(printf '%s\n' "$generated" | tr -d '\r' | sed -n "s/^$name=//p" | head -n 1)
        if [ -z "$value" ]; then
            echo "NOT READY. gen-secrets did not return $name." >&2
            exit 1
        fi
        set_if_empty "$name" "$value"
    done
    echo
fi

if [ "$dev" != true ] && [ -z "$(get_value LIVEKIT_NODE_IP)" ]; then
    echo "Note: LIVEKIT_NODE_IP is empty. Set it to the public IPv4 address of this"
    echo "machine in deploy/.env before inviting anyone, or calls will not connect."
    echo
fi

echo "Ready: docker compose up -d"
