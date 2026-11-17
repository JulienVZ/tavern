-- SPDX-License-Identifier: AGPL-3.0-or-later

-- The public state of each MLS group (ADR 0019, section 14): one row per
-- group generation, and the rows OpenMLS keeps for it (ratchet tree, group
-- context, transcript hash, confirmation tag, the server's own stored
-- proposals). No secret and no content: public MLS data and metadata only.
-- The server keeps the current generation of a conversation only: creating
-- a generation deletes the earlier ones in the same transaction.
--
-- conversation_id gets its foreign key to conversations with that table
-- (M2, task 7).

CREATE TABLE mls_groups (
    group_id        bytea PRIMARY KEY,                       -- META  conversation id then generation, 20 bytes
    conversation_id uuid NOT NULL,                           -- META
    generation      bigint NOT NULL,                         -- META
    epoch           bigint NOT NULL,                         -- META  current epoch
    revision        bigint NOT NULL DEFAULT 0,               -- META  saves so far: a save writes only over the revision it loaded
    group_info      bytea NOT NULL,                          -- PUB   latest GroupInfo with its ratchet tree, for external commits
    updated_at      timestamptz NOT NULL DEFAULT now(),      -- META
    UNIQUE (conversation_id, generation),
    CHECK (generation BETWEEN 0 AND 4294967295),
    -- The MLS group id: the conversation id, then the generation as 4
    -- big-endian bytes (ADR 0019, section 17).
    CHECK (group_id = uuid_send(conversation_id) || substring(int8send(generation) FROM 5 FOR 4)),
    CHECK (epoch >= 1),
    CHECK (revision >= 0)
);

CREATE TABLE mls_group_entries (
    group_id  bytea NOT NULL REFERENCES mls_groups(group_id) ON DELETE CASCADE, -- META
    kind      smallint NOT NULL,                             -- META  1 tree, 2 context, 3 transcript hash, 4 tag, 5 proposal queue, 6 proposal
    key       bytea NOT NULL,                                -- PUB   empty, or a proposal reference
    value     bytea NOT NULL,                                -- PUB   public MLS state, as OpenMLS serialises it
    PRIMARY KEY (group_id, kind, key),
    CHECK (kind BETWEEN 1 AND 6)
);
