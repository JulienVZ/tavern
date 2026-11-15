#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Creates, in the PostgreSQL of the development stack, a database reserved
# for the automated tests, and prints its URL. The tests create accounts by
# the hundred: they never run on the database of the instance itself, and
# refuse any database whose name does not end in "_test".
#
# Usage, from the repository root (the stack must be up, see init.sh --dev):
#
#   TAVERN_TEST_DATABASE_URL=$(./deploy/scripts/test-db.sh) \
#     cargo test --package tavern-server --package tavern-e2e-tests -- --ignored
#
#   ./deploy/scripts/test-db.sh --reset    # drop it and start from an empty one

set -eu

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
    echo "test-db.sh: deploy/.env not found. Run ./scripts/init.sh --dev first." >&2
    exit 1
fi

get_value() {
    sed -n "s/^$1=//p" .env | head -n 1
}

user=$(get_value POSTGRES_USER)
user=${user:-tavern}
password=$(get_value POSTGRES_PASSWORD)
port=$(get_value DEV_POSTGRES_PORT)
port=${port:-5432}
name=tavern_test

psql() {
    docker compose exec -T postgres psql --username "$user" --dbname postgres \
        --quiet --tuples-only --no-align "$@"
}

if [ "${1:-}" = "--reset" ]; then
    psql --command "DROP DATABASE IF EXISTS $name WITH (FORCE)" >&2
fi
if [ -z "$(psql --command "SELECT 1 FROM pg_database WHERE datname = '$name'")" ]; then
    psql --command "CREATE DATABASE $name OWNER \"$user\"" >&2
fi

echo "postgres://${user}:${password}@localhost:${port}/${name}"
