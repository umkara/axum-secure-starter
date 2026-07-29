-- Server-side access tokens, for `APP_TOKEN_FORMAT=opaque`. MySQL dialect; see
-- `migrations/sqlite/0002_access_tokens.sql` for why this table exists.

CREATE TABLE IF NOT EXISTS access_tokens (
    id          BINARY(16)  NOT NULL PRIMARY KEY,
    user_id     BINARY(16)  NOT NULL,
    token_hash  VARCHAR(64)  CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs NOT NULL,
    session     BINARY(16)  NOT NULL,
    role        VARCHAR(16) NOT NULL,
    expires_at  DATETIME(6) NOT NULL,
    created_at  DATETIME(6) NOT NULL,
    UNIQUE KEY uq_access_tokens_hash (token_hash),
    KEY idx_access_tokens_user (user_id),
    KEY idx_access_tokens_session (session),
    KEY idx_access_tokens_expiry (expires_at),
    CONSTRAINT fk_access_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT ck_access_tokens_role CHECK (role IN ('user', 'admin'))
) ENGINE = InnoDB;
