-- SPDX-License-Identifier: AGPL-3.0-or-later

-- A conversation whose group has no member left that can commit (every leaf
-- being removed by the server): it must be recreated, at the next
-- generation, like a restored one at the restore's (ADR 0019, sections 3
-- and 17). Set with `needs_recreation`, which makes every other request
-- refused; both cleared by the recreation.
ALTER TABLE conversations
    ADD COLUMN group_dead boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT conversations_group_dead CHECK (NOT group_dead OR needs_recreation);
