CREATE TABLE sessions (
    id           TEXT        PRIMARY KEY,
    device_id    TEXT        NOT NULL REFERENCES devices(id),
    user_address TEXT        NOT NULL,
    tx_hash      TEXT        NOT NULL,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_sessions_device_id    ON sessions(device_id);
CREATE INDEX idx_sessions_user_address ON sessions(user_address);

-- V6: session revocation and token metadata support
ALTER TABLE sessions
    ADD COLUMN revoked    BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN revoked_at TIMESTAMPTZ;

CREATE INDEX idx_sessions_revoked ON sessions(revoked);