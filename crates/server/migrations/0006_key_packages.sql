-- SPDX-License-Identifier: AGPL-3.0-or-later

-- The KeyPackages each device keeps on the server (ADR 0019, section 3): up
-- to 200 one-time packages, each served once and deleted in the claiming
-- transaction, and one last-resort package, served when no one-time package
-- is left and kept until the device replaces it. Public MLS data only: the
-- private parts stay on the device. A revoked device's packages are deleted
-- with its revocation.

CREATE TABLE key_packages (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),          -- META
    device_id    uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE, -- META
    key_package  bytea NOT NULL,                             -- PUB   MLS KeyPackage, signed by the device
    reference    bytea NOT NULL UNIQUE,                      -- PUB   KeyPackageRef (hash)
    last_resort  boolean NOT NULL DEFAULT false,             -- META
    expires_at   timestamptz NOT NULL,                       -- META  end of the KeyPackage's lifetime
    created_at   timestamptz NOT NULL DEFAULT now(),         -- META
    CHECK (octet_length(key_package) <= 4096)
);
-- A claim serves a device's oldest one-time package first.
CREATE INDEX key_packages_device_idx ON key_packages (device_id, last_resort, created_at);
-- One last-resort package per device.
CREATE UNIQUE INDEX key_packages_last_resort_idx ON key_packages (device_id) WHERE last_resort;
