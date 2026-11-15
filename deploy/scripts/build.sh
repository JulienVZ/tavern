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
# Usage: ./scripts/build.sh && docker compose up -d
#        curl http://localhost:8080/version    # development stack

set -eu

cd "$(dirname "$0")/.."

commit=$(git rev-parse HEAD)
if [ -n "$(git status --porcelain)" ]; then
    commit="${commit}-dirty"
fi

TAVERN_BUILD_COMMIT=$commit docker compose build server
echo "build.sh: built the server image from ${commit}"
