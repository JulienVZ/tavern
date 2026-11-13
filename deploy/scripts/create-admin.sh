#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Creates the first invitation code of an instance. The account registered
# with it becomes an administrator. The code is single use, valid 24 hours,
# and shown only once.
#
# The server never creates an account with a password itself: registration
# always goes through OPAQUE in a client, so the server never sees a password.
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

docker compose run --rm -T server create-admin-invite
