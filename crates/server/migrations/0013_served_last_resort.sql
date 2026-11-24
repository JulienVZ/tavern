-- SPDX-License-Identifier: AGPL-3.0-or-later

-- A last-resort KeyPackage is served to every claim that finds no one-time
-- package, and keeps its bytes while it is the device's last resort; it now
-- records when it was first served too (served_at). A claim's device may
-- add it to a group's first commit after the device replaced it: a served
-- package's row, its reference and its leaf key stay until it expires, so
-- that the server still matches that commit's Welcome (ADR 0019, section 4).
-- A served last resort that was replaced is kept as served, without its
-- bytes and no longer the last resort; one never served is deleted.
ALTER TABLE key_packages DROP CONSTRAINT key_packages_served;
ALTER TABLE key_packages ADD CONSTRAINT key_packages_served CHECK (
    served_at IS NULL OR last_resort OR octet_length(key_package) = 0
);
