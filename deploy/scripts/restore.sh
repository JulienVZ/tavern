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
# After the database, the script raises the instance generation and records
# when the backup was taken. At its next start the server revokes every
# session, tells every account what the restore undid, and has every
# conversation's group recreated (docs/self-hosting.md, "Backups"). The
# server also tells a restored database by itself, from its marker, should
# the database be restored another way.
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

# When the backup was taken: the file backup.sh writes, else the time in the
# archive's name. Checked strictly: it goes into SQL.
taken_at=""
if [ -f "$dir/taken_at" ]; then
    taken_at=$(cat "$dir/taken_at")
else
    stamp=$(basename "$dir" | sed -n 's/^tavern-\([0-9]\{8\}T[0-9]\{6\}Z\)$/\1/p')
    if [ -n "$stamp" ]; then
        taken_at=$(echo "$stamp" | sed 's/^\(....\)\(..\)\(..\)T\(..\)\(..\)\(..\)Z$/\1-\2-\3T\4:\5:\6Z/')
    fi
fi
if ! echo "$taken_at" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'; then
    echo "restore.sh: the date of this backup is unknown; the restore notice gives an estimate." >&2
    taken_at=""
fi

echo "Recording the restore..."
# A dump older than the table (migration 0014) is told by the server's
# marker instead.
docker compose exec -T postgres sh -c \
    'psql --quiet --no-psqlrc --set ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB"' <<SQL
DO \$\$
BEGIN
    IF to_regclass('instance_state') IS NOT NULL THEN
        UPDATE instance_state SET generation = generation + 1,
            backup_taken_at = NULLIF('$taken_at', '')::timestamptz;
    END IF;
END
\$\$;
SQL

docker compose up -d
echo "Restore complete."
