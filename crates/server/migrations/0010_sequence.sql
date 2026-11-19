-- SPDX-License-Identifier: AGPL-3.0-or-later

-- A conversation's sequence (ADR 0019, sections 4 to 7 and 12): commits,
-- application messages and the server's proposals, numbered under the lock
-- of the conversation's row (conversations.last_seq), strictly increasing
-- and without gaps; who receives them; the welcomes of the devices a commit
-- adds; and the idempotency records of sent messages, which outlive them.
-- Acknowledged and expired rows are deleted by the purge (M2, task 9).

-- The devices of each conversation's group, computed by the server from the
-- merged public tree in the transaction that merges a commit, never from
-- what a client says. A device reads the sequence after joined_seq, up to
-- left_seq once it left: the commit that removed it included.
CREATE TABLE conversation_devices (
    conversation_id uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE, -- META
    device_id       uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE, -- META
    leaf_index      integer NOT NULL,                        -- META
    joined_seq      bigint NOT NULL,                         -- META  the commit that added it
    left_seq        bigint,                                  -- META  the commit that removed it
    acked_seq       bigint NOT NULL,                         -- META  delivery cursor
    PRIMARY KEY (conversation_id, device_id),
    CHECK (leaf_index >= 0),
    CHECK (acked_seq >= joined_seq),
    CHECK (left_seq IS NULL OR left_seq >= joined_seq)
);
CREATE UNIQUE INDEX conversation_devices_leaf_idx
    ON conversation_devices (conversation_id, leaf_index) WHERE left_seq IS NULL;
CREATE INDEX conversation_devices_device_idx ON conversation_devices (device_id);

CREATE TABLE messages (
    conversation_id  uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE, -- META
    seq              bigint NOT NULL,                        -- META
    epoch            bigint NOT NULL,                        -- META  the epoch it belongs to (a commit: the one it ends)
    kind             smallint NOT NULL,                      -- META  1 application, 2 commit, 3 proposal
    sender_device_id uuid REFERENCES devices(id) ON DELETE SET NULL, -- META  NULL for the server's proposals
    payload          bytea NOT NULL,                         -- E2EE  kind 1 (MLS PrivateMessage); PUB kinds 2 and 3 (signed PublicMessage)
    created_at       timestamptz NOT NULL DEFAULT now(),     -- META
    expires_at       timestamptz NOT NULL,                   -- META  the retention
    PRIMARY KEY (conversation_id, seq),
    CHECK (seq >= 1),
    CHECK (kind BETWEEN 1 AND 3),
    CHECK (kind <> 3 OR sender_device_id IS NULL)
);
CREATE INDEX messages_expiry_idx ON messages (expires_at);

-- Idempotent sending (ADR 0019, section 7): kept twice the retention, after
-- the message itself is gone, so that a resend always gets the original
-- acknowledgement and is never stored nor delivered twice.
CREATE TABLE sent_messages (
    device_id         uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE, -- META
    client_message_id uuid NOT NULL,                         -- META  chosen by the sending device
    conversation_id   uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE, -- META
    seq               bigint NOT NULL,                       -- META
    sent_at           timestamptz NOT NULL,                  -- META  the acknowledgement's time
    expires_at        timestamptz NOT NULL,                  -- META  twice the retention
    PRIMARY KEY (device_id, client_message_id)
);
CREATE INDEX sent_messages_expiry_idx ON sent_messages (expires_at);

CREATE TABLE welcomes (
    id                  uuid PRIMARY KEY DEFAULT uuidv7(),   -- META
    conversation_id     uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE, -- META
    recipient_device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE, -- META
    payload             bytea NOT NULL,                      -- E2EE  MLS Welcome, encrypted to the recipient's KeyPackage
    created_at          timestamptz NOT NULL DEFAULT now(),  -- META
    expires_at          timestamptz NOT NULL,                -- META  the retention
    acked_at            timestamptz                          -- META  sent again at each connection until set
);
CREATE INDEX welcomes_recipient_idx ON welcomes (recipient_device_id) WHERE acked_at IS NULL;
