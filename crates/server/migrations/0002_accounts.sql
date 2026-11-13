-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Milestone M1: accounts, devices, sessions, invitations.
--
-- Every column is classified in docs/database-schema.md (the comment at the
-- end of each line). No column holds plaintext content, a password or a
-- private key. A test fails if a column exists here without a class there.
--
-- Requires PostgreSQL 18 or newer (uuidv7()).

CREATE TABLE users (
    id                      uuid PRIMARY KEY DEFAULT uuidv7(),  -- META
    handle                  text NOT NULL UNIQUE,            -- META  visible identifier, lower case
    display_name            text NOT NULL,                   -- META  profile, visible in v1 (ADR 0008)
    is_admin                boolean NOT NULL DEFAULT false,  -- META
    opaque_suite            smallint NOT NULL,               -- META  version of the OPAQUE and Argon2id parameters
    opaque_record           bytea NOT NULL,                  -- AUTH  OPAQUE ServerRegistration
    identity_key            bytea NOT NULL,                  -- PUB   account identity key (Ed25519)
    identity_key_wrapped_pw bytea NOT NULL,                  -- WRAP  AIK private key under the OPAQUE export key
    identity_key_wrapped_rk bytea NOT NULL,                  -- WRAP  AIK private key under the recovery key
    totp_secret             bytea,                           -- SRV   encrypted with the instance TOTP key
    totp_enabled_at         timestamptz,                     -- META
    totp_last_step          bigint,                          -- META  last accepted time step, against replay
    storage_quota_bytes     bigint,                          -- META  NULL = instance default
    created_at              timestamptz NOT NULL DEFAULT now(), -- META
    disabled_at             timestamptz,                     -- META
    CONSTRAINT users_handle_format CHECK (handle ~ '^[a-z0-9_.]{2,32}$'),
    CONSTRAINT users_display_name_length CHECK (char_length(display_name) BETWEEN 1 AND 64)
);

CREATE TABLE totp_recovery_codes (
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, -- META
    code_hash   bytea NOT NULL,                              -- HASH
    used_at     timestamptz,                                 -- META
    PRIMARY KEY (user_id, code_hash)
);

CREATE TABLE devices (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),       -- META
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, -- META
    signature_key   bytea NOT NULL UNIQUE,                   -- PUB   MLS leaf signature key (Ed25519)
    certificate     bytea NOT NULL,                          -- PUB   signed by the account identity key
    name_encrypted  bytea,                                   -- E2EE  readable by the user's own devices only
    platform        smallint NOT NULL,                       -- META  windows / macos / linux
    created_at      timestamptz NOT NULL DEFAULT now(),      -- META
    last_seen_at    timestamptz,                             -- META  day precision
    devices_seen_at timestamptz NOT NULL DEFAULT now(),      -- META  enrolments after this instant were not shown to this device yet
    revoked_at      timestamptz                              -- META
);
CREATE INDEX devices_user_idx ON devices (user_id) WHERE revoked_at IS NULL;

CREATE TABLE sessions (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),         -- META
    device_id     uuid NOT NULL UNIQUE REFERENCES devices(id) ON DELETE CASCADE, -- META  one session per device
    token_hash    bytea NOT NULL UNIQUE,                     -- HASH  SHA-256 of the random token
    created_at    timestamptz NOT NULL DEFAULT now(),        -- META
    last_used_at  timestamptz NOT NULL DEFAULT now(),        -- META
    expires_at    timestamptz NOT NULL,                      -- META
    revoked_at    timestamptz                                -- META
);

CREATE TABLE instance_invites (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),          -- META
    code_hash    bytea NOT NULL UNIQUE,                      -- HASH  the code is shown once to the admin
    created_by   uuid REFERENCES users(id) ON DELETE SET NULL, -- META  NULL when created on the host
    grants_admin boolean NOT NULL DEFAULT false,             -- META  only for the bootstrap invite
    max_uses     integer NOT NULL DEFAULT 1,                 -- META
    uses         integer NOT NULL DEFAULT 0,                 -- META
    expires_at   timestamptz,                                -- META
    revoked_at   timestamptz,                                -- META
    created_at   timestamptz NOT NULL DEFAULT now(),         -- META
    CONSTRAINT instance_invites_uses CHECK (uses >= 0 AND uses <= max_uses AND max_uses >= 1)
);

CREATE TABLE instance_invite_uses (
    invite_id   uuid NOT NULL REFERENCES instance_invites(id) ON DELETE CASCADE, -- META
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, -- META
    used_at     timestamptz NOT NULL DEFAULT now(),          -- META
    PRIMARY KEY (invite_id, user_id)
);

-- Instance-level administrative actions: who did what to whom. No free text.
CREATE TABLE admin_audit_log (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),           -- META
    actor_id    uuid REFERENCES users(id) ON DELETE SET NULL, -- META  NULL for actions run on the host
    action      smallint NOT NULL,                           -- META  enum: disable TOTP, disable user, revoke invite, ...
    target_id   uuid,                                        -- META  user or invite concerned
    created_at  timestamptz NOT NULL DEFAULT now()           -- META
);
CREATE INDEX admin_audit_log_created_idx ON admin_audit_log (created_at);
