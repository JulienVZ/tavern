-- SPDX-License-Identifier: AGPL-3.0-or-later

-- A restored backup (ADR 0019, sections 15 and 17).
--
-- The instance generation is raised by restore.sh, or by the server itself
-- when its marker shows the database is behind (crate::restore). The server
-- handles a new generation once, at start-up, before it serves anything.

CREATE TABLE instance_state (
    id                 boolean PRIMARY KEY DEFAULT true,     -- META  a single row
    instance_id        uuid NOT NULL DEFAULT gen_random_uuid(), -- META  names this database in the server's marker
    generation         bigint NOT NULL DEFAULT 0,            -- META  raised by each restore
    handled_generation bigint NOT NULL DEFAULT 0,            -- META  the last generation handled at start-up
    backup_taken_at    timestamptz,                          -- META  when the restored backup was taken, if known
    alive_at           timestamptz,                          -- META  the server's last record of a change, at most a few seconds old
    CHECK (id),
    CHECK (handled_generation BETWEEN 0 AND generation)
);
INSERT INTO instance_state DEFAULT VALUES;

-- Advanced by every statement that writes to another table: a database
-- restored from a backup has it behind what the server last saw. A sequence
-- is not transactional, so no write waits for another; a dump records its
-- value, and a restore rewinds it with the data.
CREATE SEQUENCE instance_changes AS bigint;

CREATE FUNCTION instance_changed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM nextval('instance_changes');
    RETURN NULL;
END
$$;

-- Every table but instance_state and the migrations' own. A table added
-- later gets its trigger in its own migration: tests/schema.rs checks it.
DO $$
DECLARE
    name text;
BEGIN
    FOR name IN
        SELECT tablename FROM pg_tables
        WHERE schemaname = current_schema()
          AND tablename NOT IN ('instance_state', '_sqlx_migrations')
    LOOP
        EXECUTE format(
            'CREATE TRIGGER instance_changed AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON %I '
            'FOR EACH STATEMENT EXECUTE FUNCTION instance_changed()',
            name
        );
    END LOOP;
END
$$;

-- Recreation of a conversation's group (section 17): required after a
-- restore, or asked by a user at most once an hour.
ALTER TABLE conversations
    ADD COLUMN needs_recreation boolean NOT NULL DEFAULT false, -- META  set by a restore, cleared by the recreation
    ADD COLUMN recreated_at     timestamptz;                    -- META  last recreation of its group

-- The date of the backup, for the notice of a restore (kind 6) only.
ALTER TABLE security_notices
    ADD COLUMN backup_taken_at timestamptz,                    -- META  INSTANCE_RESTORED: when the backup was taken, if known
    ADD CONSTRAINT security_notices_backup_taken_at CHECK (backup_taken_at IS NULL OR kind = 6);
