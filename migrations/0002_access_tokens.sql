-- Server-side access tokens, for `APP_TOKEN_FORMAT=opaque`.
--
-- The stateless formats put the identity inside the token and pay nothing to
-- verify it; the cost is that a token stays valid until it expires, whatever
-- happens to the account behind it. This table is the other trade: a row per
-- live access token, one lookup per request, and revocation that takes effect
-- on the next request rather than in fifteen minutes.
--
-- Only the SHA-256 digest is stored, exactly as for refresh tokens, so a dump
-- of this table cannot be replayed against the API.
--
-- `session` groups an access token with the refresh-token family it was issued
-- alongside, so logging out one device ends that device's access token without
-- touching the user's other sessions.
CREATE TABLE IF NOT EXISTS access_tokens (
    id          BLOB    PRIMARY KEY NOT NULL,
    user_id     BLOB    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash  TEXT    NOT NULL UNIQUE,
    session     BLOB    NOT NULL,
    role        TEXT    NOT NULL CHECK (role IN ('user', 'admin')),
    expires_at  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_access_tokens_user    ON access_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_session ON access_tokens (session);
CREATE INDEX IF NOT EXISTS idx_access_tokens_expiry  ON access_tokens (expires_at);
