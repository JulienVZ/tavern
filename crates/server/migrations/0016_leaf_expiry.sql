-- SPDX-License-Identifier: AGPL-3.0-or-later

-- The end of the lifetime of a leaf still as its KeyPackage made it, never
-- updated: OpenMLS refuses to join a group once one is over, so the server
-- asks to remove such a leaf 7 days before (ADR 0019, section 3). NULL once
-- the leaf is updated. Written from the merged tree, with the other rows of
-- `conversation_devices`.
ALTER TABLE conversation_devices ADD COLUMN leaf_expires_at timestamptz;
