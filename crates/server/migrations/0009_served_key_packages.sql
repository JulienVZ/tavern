-- SPDX-License-Identifier: AGPL-3.0-or-later

-- A one-time KeyPackage is served once (ADR 0019, section 3), even when its
-- device sends it again (an upload retried after its answer was lost): a
-- claim keeps the package's row, without its bytes, until the package
-- expires, so that its reference stays taken and the same package cannot be
-- stored again. Expired rows, served or not, go at the device's next upload
-- and with the hourly purge (M2, tasks 8 and 9).

ALTER TABLE key_packages
    ADD COLUMN served_at timestamptz,
    ADD CONSTRAINT key_packages_served CHECK (
        served_at IS NULL OR (NOT last_resort AND octet_length(key_package) = 0)
    );
