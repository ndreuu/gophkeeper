CREATE TABLE users (
    id CHAR(32) PRIMARY KEY,
    login VARCHAR(64) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    vault_salt BYTEA NOT NULL CHECK (octet_length(vault_salt) = 16),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    token_hash BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    user_id CHAR(32) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE records (
    user_id CHAR(32) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    id CHAR(32) NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext) BETWEEN 28 AND 12582912),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, id)
);
