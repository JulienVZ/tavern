#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Fails when the stand-in is no longer needed: when a published release of
# sqlx (0.9.0 or later) can be resolved together with the libsqlite3-sys of
# our Cargo.lock. Then delete this directory and the [patch.crates-io] entry
# (see README.md). Run by CI; needs cargo and access to crates.io.
#
# Cargo's own resolver answers the question, in a throwaway project outside
# the workspace: same rules as for the real build, optional dependencies
# included.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
lock="$here/../../Cargo.lock"
# The features matter: sqlx's weak references to its SQLite driver (for
# example `sqlx-sqlite?/migrate`) are what put the driver in the resolution.
features=$(sed -n 's/^sqlx = {.*\(features = \[[^]]*\]\).*$/\1/p' "$here/../../Cargo.toml")
if [ -z "$features" ]; then
    echo "still-needed.sh: cannot read sqlx's features in Cargo.toml." >&2
    exit 1
fi
ours=$(grep -A1 '^name = "libsqlite3-sys"$' "$lock" | sed -n 's/^version = "\(.*\)"$/\1/p')
if [ -z "$ours" ]; then
    echo "still-needed.sh: libsqlite3-sys is not in Cargo.lock: remove the stand-in." >&2
    exit 1
fi

project=$(mktemp -d)
trap 'rm -rf "$project"' EXIT
mkdir "$project/src"
: > "$project/src/lib.rs"
cat > "$project/Cargo.toml" <<EOF
[package]
name = "sqlx-sqlite-check"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
sqlx = { version = ">=0.9.0", default-features = false, $features }
libsqlite3-sys = "=$ours"

[workspace]
EOF

if (cd "$project" && cargo generate-lockfile --quiet) 2> "$project/err.txt"; then
    sqlx=$(grep -A1 '^name = "sqlx"$' "$project/Cargo.lock" | sed -n 's/^version = "\(.*\)"$/\1/p')
    echo "sqlx $sqlx accepts libsqlite3-sys $ours: the stand-in is no longer needed." >&2
    echo "Upgrade sqlx, then delete third_party/sqlx-sqlite-unused and the [patch.crates-io] entry." >&2
    exit 1
fi
if grep -q 'links to the native library `sqlite3`' "$project/err.txt"; then
    echo "No release of sqlx accepts libsqlite3-sys $ours yet: the stand-in is still needed."
    exit 0
fi
echo "still-needed.sh: the check itself failed:" >&2
cat "$project/err.txt" >&2
exit 1
