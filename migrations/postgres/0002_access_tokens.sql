-- Server-side access tokens, for `APP_TOKEN_FORMAT=opaque`. PostgreSQL dialect;
-- see `migrations/sqlite/0002_access_tokens.sql` for why this table exists.

CREATE TABLE IF NOT EXISTS access_tokens (
    id          UUID        PRIMARY KEY,
    user_id     UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash  TEXT        NOT NULL UNIQUE,
    session     UUID        NOT NULL,
    role        TEXT        NOT NULL CHECK (role IN ('user', 'admin')),
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_access_tokens_user    ON access_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_session ON access_tokens (session);
CREATE INDEX IF NOT EXISTS idx_access_tokens_expiry  ON access_tokens (expires_at);
