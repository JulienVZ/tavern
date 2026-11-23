-- SPDX-License-Identifier: AGPL-3.0-or-later

-- The encryption key of each KeyPackage's leaf (ADR 0019, section 4), kept
-- after the package is served. The server cannot read a group's first
-- commit (it has no state of epoch 0), but its tree has, for each device
-- the commit adds, the leaf of the package that added it: the server checks
-- that the Welcome is for exactly those packages. Public MLS data: the leaf
-- is in every GroupInfo of the group. Packages uploaded before this
-- migration have none, and no first commit can add them.
ALTER TABLE key_packages
    ADD COLUMN leaf_key bytea NOT NULL DEFAULT ''::bytea,
    ADD CONSTRAINT key_packages_leaf_key CHECK (octet_length(leaf_key) <= 256);
ALTER TABLE key_packages ALTER COLUMN leaf_key DROP DEFAULT;
