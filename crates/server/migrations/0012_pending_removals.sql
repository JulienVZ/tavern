-- SPDX-License-Identifier: AGPL-3.0-or-later

-- The server's removals not committed yet (ADR 0019, sections 6 and 15),
-- one per device of a conversation's group: a revoked device, a device of a
-- disabled account, or one away for longer than TAVERN_DEVICE_INACTIVE_DAYS.
-- The proposals themselves are stored with the group's public state
-- (mls_group_entries); this table says which device each one is for and
-- where it is in the sequence. From that proposal on, the device is cut
-- off: it receives no event of the conversation, reads the sequence up to
-- the proposal and no further, and sends nothing. A row goes when a merged
-- commit removes the leaf, and proposal_seq moves when the server asks
-- again after an external commit.
CREATE TABLE pending_removals (
    conversation_id uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    device_id       uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    leaf_index      integer NOT NULL,
    proposal_seq    bigint NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (conversation_id, device_id),
    CHECK (leaf_index >= 0),
    CHECK (proposal_seq >= 1)
);
CREATE UNIQUE INDEX pending_removals_leaf_idx ON pending_removals (conversation_id, leaf_index);
CREATE INDEX pending_removals_device_idx ON pending_removals (device_id);
