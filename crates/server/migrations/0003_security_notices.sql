-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Security notices: security-relevant events of an account, kept until each
-- of its devices has shown them to the user (ADR 0016).
--
-- A notice is a kind and a date. No free text, no device, no address: the
-- server already knows that these events happened, and stores nothing more.

CREATE TABLE security_notices (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),           -- META
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, -- META  the account concerned
    kind        smallint NOT NULL,                           -- META  enum: TOTP disabled by an admin, password changed, ...
    created_at  timestamptz NOT NULL DEFAULT now()           -- META
);
CREATE INDEX security_notices_user_idx ON security_notices (user_id, created_at);

-- One row per device that dismissed a notice.
CREATE TABLE security_notice_acks (
    notice_id   uuid NOT NULL REFERENCES security_notices(id) ON DELETE CASCADE, -- META
    device_id   uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE, -- META
    acked_at    timestamptz NOT NULL DEFAULT now(),          -- META
    PRIMARY KEY (notice_id, device_id)
);
