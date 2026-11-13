#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Backs up a Tavern instance into deploy/backups/tavern-<timestamp>.tar.gz:
#   - db.dump       PostgreSQL dump (custom format)
#   - .env          configuration AND instance secrets
#   - Caddyfile, livekit.yaml
#
# The archive contains secrets. Store it encrypted and off the machine.
#
# .env holds the instance secrets: the OPAQUE server setup (without it no
# password works any more), the MLS external sender key (without it the server
# cannot remove members from existing groups by itself), the TOTP encryption
# key and the handle privacy key. The database dump is useless without the
# .env it was made with, which is why both go in the same archive.
#
# Usage: ./scripts/backup.sh [output-directory]
#
# TODO(M5): include the encrypted blob storage once attachments exist.

set -eu

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
    echo "backup.sh: deploy/.env not found. Nothing to back up." >&2
    exit 1
fi

out_dir=${1:-backups}
stamp=$(date -u +%Y%m%dT%H%M%SZ)
name="tavern-$stamp"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

umask 077
mkdir -p "$out_dir" "$work/$name"

echo "Dumping PostgreSQL..."
docker compose exec -T postgres sh -c \
    'pg_dump --format=custom --username "$POSTGRES_USER" --dbname "$POSTGRES_DB"' \
    >"$work/$name/db.dump"

cp .env "$work/$name/.env"
for file in Caddyfile livekit.yaml; do
    if [ -f "$file" ]; then
        cp "$file" "$work/$name/$file"
    fi
done

tar -czf "$out_dir/$name.tar.gz" -C "$work" "$name"
echo "Backup written to deploy/$out_dir/$name.tar.gz"
echo "It contains the instance secrets: keep it encrypted and off this machine."
