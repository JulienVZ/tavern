#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Creates the first invitation code of an instance. The account registered
# with it becomes the first administrator.
#
# Not available yet: accounts and invitations arrive with milestone M1. From
# then on this script will run, inside the server container, a command that
# inserts a single-use admin invitation and prints its code once:
#
#   docker compose exec server tavern-server create-admin-invite
#
# The server never creates an account with a password itself: registration
# always goes through OPAQUE in a client, so the server never sees a password.

set -eu

echo "create-admin.sh: not implemented yet (milestone M1: accounts and invitations)." >&2
exit 1
