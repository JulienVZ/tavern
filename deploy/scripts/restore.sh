#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Restores a backup made by backup.sh. This REPLACES the current database and,
# unless --db-only is given, the current .env, Caddyfile and livekit.yaml.
#
# Usage: ./scripts/restore.sh [--db-only] [--yes] <backup.tar.gz>
#
# Restore the configuration files too when moving to a new machine: clients
# and existing groups depend on the instance secrets stored in .env.
#
# TODO(M5): restore the encrypted blob storage once attachments exist.

set -eu

db_only=false
assume_yes=false
archive=""

for arg in "$@"; do
    case "$arg" in
        --db-only) db_only=true ;;
        --yes) assume_yes=true ;;
        -*) echo "restore.sh: unknown option $arg" >&2; exit 2 ;;
        *) archive=$arg ;;
    esac
done

if [ -z "$archive" ] || [ ! -f "$archive" ]; then
    echo "usage: restore.sh [--db-only] [--yes] <backup.tar.gz>" >&2
    exit 2
fi

archive=$(cd "$(dirname "$archive")" && pwd)/$(basename "$archive")
cd "$(dirname "$0")/.."

if [ "$assume_yes" != true ]; then
    printf 'This replaces the current database of this instance. Continue? [y/N] '
    read -r answer
    case "$answer" in
        y | Y | yes | YES) ;;
        *) echo "Aborted."; exit 1 ;;
    esac
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
umask 077
tar -xzf "$archive" -C "$work"
dir=$(find "$work" -mindepth 1 -maxdepth 1 -type d | head -n 1)

if [ -z "$dir" ] || [ ! -f "$dir/db.dump" ]; then
    echo "restore.sh: this archive is not a Tavern backup." >&2
    exit 1
fi

if [ "$db_only" != true ]; then
    for file in .env Caddyfile livekit.yaml; do
        if [ -f "$dir/$file" ]; then
            cp "$dir/$file" "$file"
            echo "restored $file"
        fi
    done
    chmod 600 .env
fi

echo "Stopping the server..."
docker compose stop server caddy >/dev/null 2>&1 || true
docker compose up -d --wait postgres

echo "Restoring PostgreSQL..."
docker compose exec -T postgres sh -c \
    'pg_restore --clean --if-exists --no-owner --username "$POSTGRES_USER" --dbname "$POSTGRES_DB"' \
    <"$dir/db.dump"

docker compose up -d
echo "Restore complete."
