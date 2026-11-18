-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Conversations (ADR 0019, section 4). One row per conversation; a DM also
-- has its pair of users in dm_conversations, unique: one DM per pair. A
-- conversation may have no MLS group yet (its creating device stopped
-- before the first commit): any active device of a participant may create
-- it. Groups and channels come with M3 and M4.

CREATE TYPE conversation_kind AS ENUM ('dm', 'group', 'text_channel', 'voice_channel');

CREATE TABLE conversations (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),         -- META
    kind          conversation_kind NOT NULL,                -- META
    last_seq      bigint NOT NULL DEFAULT 0,                 -- META  last assigned sequence number
    created_by    uuid REFERENCES users(id) ON DELETE SET NULL, -- META
    created_at    timestamptz NOT NULL DEFAULT now(),        -- META
    CHECK (last_seq >= 0)
);

CREATE TABLE dm_conversations (
    conversation_id uuid PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE, -- META
    user_low        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, -- META  smaller id of the pair
    user_high       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, -- META
    UNIQUE (user_low, user_high),
    CHECK (user_low < user_high)
);
CREATE INDEX dm_conversations_high_idx ON dm_conversations (user_high);

-- Announced with mls_groups (migration 0005): a group belongs to its
-- conversation.
ALTER TABLE mls_groups
    ADD CONSTRAINT mls_groups_conversation_id_fkey
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE;
