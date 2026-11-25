-- SPDX-License-Identifier: AGPL-3.0-or-later

-- The notice of a restore to the administrators (kind 7) carries the date
-- of the backup too: what they did after it is undone (ADR 0019, section
-- 15; ADR 0016).
ALTER TABLE security_notices
    DROP CONSTRAINT security_notices_backup_taken_at,
    ADD CONSTRAINT security_notices_backup_taken_at
        CHECK (backup_taken_at IS NULL OR kind IN (6, 7));
