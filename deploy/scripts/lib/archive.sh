# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Functions for restore.sh, sourced (tested by crates/server/tests/scripts.rs).

# Prints when the backup in directory $1 was taken, as YYYY-MM-DDTHH:MM:SSZ:
# the file taken_at that backup.sh writes, else the time in the directory's
# name (tavern-YYYYMMDDTHHMMSSZ). Prints nothing when neither is a valid
# date: the value goes into SQL, so it is checked strictly.
backup_date() {
    date=""
    if [ -f "$1/taken_at" ]; then
        date=$(head -n 1 "$1/taken_at")
    else
        date=$(basename "$1" |
            sed -n 's/^tavern-\([0-9]\{4\}\)\([0-9]\{2\}\)\([0-9]\{2\}\)T\([0-9]\{2\}\)\([0-9]\{2\}\)\([0-9]\{2\}\)Z$/\1-\2-\3T\4:\5:\6Z/p')
    fi
    if printf '%s\n' "$date" | grep -Eqx '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z'; then
        printf '%s\n' "$date"
    fi
}

# Prints the newest migration in a dump in custom format, read on stdin by
# `pg_restore --data-only --table=_sqlx_migrations --file=-` (0 if none).
newest_migration_in_dump_listing() {
    awk '/^COPY .*_sqlx_migrations / { rows = 1; next }
         /^\\\.$/ { rows = 0 }
         rows && $1 + 0 > newest { newest = $1 + 0 }
         END { print newest + 0 }'
}
