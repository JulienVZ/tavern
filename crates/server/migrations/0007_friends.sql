-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Friends and blocks (ADR 0020). One row per pair of users in
-- friendships, whatever its state: at most one request per pair. A request
-- sent to a user who blocks its sender is kept, hidden from that user and
-- shown to its sender only, so that the block is not disclosed; it is
-- deleted when the block is lifted.

CREATE TYPE friendship_status AS ENUM ('pending', 'accepted');

CREATE TABLE friendships (
    user_low      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, -- META  smaller id of the pair
    user_high     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, -- META
    status        friendship_status NOT NULL,                -- META
    requested_by  uuid NOT NULL,                             -- META  who sent the request
    hidden        boolean NOT NULL DEFAULT false,            -- META  sent to a user who blocks its sender: shown to the sender only
    created_at    timestamptz NOT NULL DEFAULT now(),        -- META
    accepted_at   timestamptz,                               -- META
    PRIMARY KEY (user_low, user_high),
    CHECK (user_low < user_high),
    CHECK (requested_by IN (user_low, user_high)),
    CHECK ((status = 'accepted') = (accepted_at IS NOT NULL)),
    CHECK (NOT hidden OR status = 'pending')
);
CREATE INDEX friendships_high_idx ON friendships (user_high);

CREATE TABLE blocks (
    blocker_id  uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, -- META
    blocked_id  uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, -- META
    created_at  timestamptz NOT NULL DEFAULT now(),          -- META
    PRIMARY KEY (blocker_id, blocked_id),
    CHECK (blocker_id <> blocked_id)
);
CREATE INDEX blocks_blocked_idx ON blocks (blocked_id);
