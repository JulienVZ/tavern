-- SPDX-License-Identifier: AGPL-3.0-or-later

-- The server's part of the key that wraps a device's local store (ADR 0017).
--
-- Random, one per device, handed out only when that device opens a session,
-- and erased when the device is revoked. Useless alone: opening the store
-- also takes a part derived from the account root secret, which the server
-- never has. NULL for a revoked device, and for a device enrolled before
-- this column existed until its next session.

ALTER TABLE devices ADD COLUMN local_store_share bytea;  -- HALF
