-- Core schema, PostgreSQL dialect.
--
-- The column *types* differ from the SQLite schema, the meaning does not.
-- Ids are native UUID rather than BLOB, timestamps are TIMESTAMPTZ rather than
-- RFC 3339 TEXT, and `revoked` is a real BOOLEAN. Every query in the repository
-- layer is still a prepared statement — no SQL is ever built by string
-- concatenation.

CREATE TABLE IF NOT EXISTS users (
    id              UUID        PRIMARY KEY,
    email           TEXT        NOT NULL UNIQUE,
    password_hash   TEXT        NOT NULL,
    role            TEXT        NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    failed_attempts BIGINT      NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL
);

-- Refresh tokens are stored as SHA-256 digests. `family` groups every token
-- descended from one login, so presenting an already-rotated token lets us
-- revoke the whole family (stolen-token reuse detection).
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          UUID        PRIMARY KEY,
    user_id     UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash  TEXT        NOT NULL UNIQUE,
    family      UUID        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    revoked     BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user   ON refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens (family);

CREATE TABLE IF NOT EXISTS notes (
    id         UUID        PRIMARY KEY,
    owner_id   UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    title      TEXT        NOT NULL,
    body       TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notes_owner_created ON notes (owner_id, created_at DESC);
