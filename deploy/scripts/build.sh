#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Builds the server image from this checkout and records the commit it was
# built from, which `GET /version` then reports as "commit". Uncommitted
# changes are marked with a "-dirty" suffix.
#
# Only needed when running from source; the published images already carry
# their commit.
#
# Usage: ./scripts/build.sh [--quiet] && docker compose up -d
#        curl http://localhost:8080/version    # development stack
#
# init.sh builds the image through this script, so that an image is never
# built from a checkout without its commit.

set -eu

cd "$(dirname "$0")/.."

# Without Git (a source archive) the image is built without a commit.
commit=
if head=$(git rev-parse HEAD 2>/dev/null); then
    commit=$head
    if [ -n "$(git status --porcelain)" ]; then
        commit="${commit}-dirty"
    fi
fi

if [ "${1:-}" = "--quiet" ]; then
    TAVERN_BUILD_COMMIT=$commit docker compose build --quiet server
else
    TAVERN_BUILD_COMMIT=$commit docker compose build server
    echo "build.sh: built the server image from ${commit:-an unknown commit (not a Git checkout)}"
fi
