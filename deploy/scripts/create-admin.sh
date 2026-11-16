#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Creates an invitation code for an administrator. The account registered
# with it becomes an administrator. The code is single use, valid 24 hours,
# and shown only once.
#
# The server never creates an account with a password itself: registration
# always goes through OPAQUE in a client, so the server never sees a password.
#
# The code is created by the server container that is already running, with
# the configuration it was started with. This script never builds, pulls or
# starts anything: start the stack first (docker compose up -d).
#
# Usage: ./scripts/create-admin.sh
#
# Run it again whenever you need another administrator. Each run is recorded
# in the administration log.

set -eu

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
    echo "create-admin.sh: deploy/.env not found. Run ./scripts/init.sh first." >&2
    exit 1
fi

if ! running=$(docker compose ps --status running --services 2>/dev/null); then
    echo "create-admin.sh: Docker cannot be reached. Start Docker, then the stack" >&2
    echo "(docker compose up -d), and run this script again." >&2
    exit 1
fi
if ! printf '%s\n' "$running" | grep -qx server; then
    echo "create-admin.sh: the Tavern server is not running. Start the stack first:" >&2
    echo "    docker compose up -d" >&2
    echo "then run this script again. If the server keeps stopping, see why with:" >&2
    echo "    docker compose logs server" >&2
    exit 1
fi

docker compose exec -T server /usr/local/bin/tavern-server create-admin-invite
