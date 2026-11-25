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

. "$(dirname "$0")/lib/archive.sh"

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

# The database and the instance must be on the same schema: pg_restore
# --clean puts back the dump's list of migrations but leaves the tables the
# dump does not have, so the server could not start on the result.
docker compose up -d --wait postgres
instance_schema=$(docker compose exec -T postgres sh -c \
    'psql --no-psqlrc --tuples-only --no-align --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
         --command "SELECT max(version) FROM _sqlx_migrations"' 2>/dev/null || true)
instance_schema=${instance_schema:-0}
backup_schema=$(docker compose exec -T postgres \
    pg_restore --data-only --table=_sqlx_migrations --file=- <"$dir/db.dump" |
    newest_migration_in_dump_listing)
# Migration 0014 holds what records a restore (instance_state): an older
# backup could not be told restored, on this machine or a new one.
if [ "$backup_schema" -lt 14 ]; then
    echo "restore.sh: this backup was made by a version of Tavern too old to be restored" \
        "(database schema $backup_schema, before 14): the server could not tell that its" \
        "database was restored." >&2
    exit 1
fi
if [ "$instance_schema" -ne 0 ] && [ "$backup_schema" -lt "$instance_schema" ]; then
    echo "restore.sh: this backup was made by an older version of Tavern (database schema" \
        "$backup_schema, this instance: $instance_schema). Restoring it over this database" \
        "would leave a database the server cannot start on. Restore it with the version of" \
        "Tavern it was made with, then update." >&2
    exit 1
fi
if [ "$instance_schema" -ne 0 ] && [ "$backup_schema" -gt "$instance_schema" ]; then
    echo "restore.sh: this backup was made by a newer version of Tavern (database schema" \
        "$backup_schema, this instance: $instance_schema). Update Tavern first." >&2
    exit 1
fi

# Always with the server stopped: a server running on a database restored
# under it would serve the restored sessions until it notices (it then
# stops, and handles the restore at its next start).
echo "Stopping the server..."
docker compose stop server caddy >/dev/null
if docker compose ps --status running --services | grep -qx server; then
    echo "restore.sh: the server is still running; stop it (docker compose stop server)." >&2
    exit 1
fi

echo "Restoring PostgreSQL..."
if ! docker compose exec -T postgres sh -c \
    'pg_restore --clean --if-exists --no-owner --username "$POSTGRES_USER" --dbname "$POSTGRES_DB"' \
    <"$dir/db.dump"; then
    echo "restore.sh: pg_restore failed (its errors are above). The database may be partly" \
        "restored, and the restore is not recorded. The server is left stopped: do not start" \
        "it on this database. Fix the cause, then run restore.sh again with the same backup." >&2
    exit 1
fi

taken_at=$(backup_date "$dir")
if [ -z "$taken_at" ]; then
    echo "restore.sh: the date of this backup is unknown; the restore notice gives an estimate." >&2
fi

echo "Recording the restore..."
# The dump's schema is 14 or later (checked above): instance_state exists.
if ! docker compose exec -T postgres sh -c \
    'psql --quiet --no-psqlrc --set ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB"' <<SQL
UPDATE instance_state SET generation = generation + 1,
    backup_taken_at = NULLIF('$taken_at', '')::timestamptz;
SQL
then
    echo "restore.sh: the database is restored, but the restore could not be recorded (the" \
        "error is above). The server is left stopped: run restore.sh again with the same backup." >&2
    exit 1
fi

docker compose up -d
echo "Restore complete."
