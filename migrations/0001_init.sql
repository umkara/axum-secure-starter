-- Core schema.
--
-- Ids are stored as BLOB because that is how sqlx encodes `Uuid` for SQLite;
-- timestamps are RFC 3339 TEXT in UTC. Every query in the repository layer is
-- a prepared statement — no SQL is ever built by string concatenation.

CREATE TABLE IF NOT EXISTS users (
    id              BLOB    PRIMARY KEY NOT NULL,
    email           TEXT    NOT NULL UNIQUE,
    password_hash   TEXT    NOT NULL,
    role            TEXT    NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);

-- Refresh tokens are stored as SHA-256 digests. `family` groups every token
-- descended from one login, so presenting an already-rotated token lets us
-- revoke the whole family (stolen-token reuse detection).
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          BLOB    PRIMARY KEY NOT NULL,
    user_id     BLOB    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash  TEXT    NOT NULL UNIQUE,
    family      BLOB    NOT NULL,
    expires_at  TEXT    NOT NULL,
    used_at     TEXT,
    revoked     INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user   ON refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens (family);

CREATE TABLE IF NOT EXISTS notes (
    id         BLOB PRIMARY KEY NOT NULL,
    owner_id   BLOB NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notes_owner_created ON notes (owner_id, created_at DESC);
