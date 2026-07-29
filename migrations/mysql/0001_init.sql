-- Core schema, MySQL dialect.
--
-- Three differences from the other backends are deliberate, not cosmetic:
--
-- * Ids are `BINARY(16)`, which is how sqlx encodes `Uuid` for MySQL.
-- * Timestamps are `DATETIME(6)`, not `TIMESTAMP`. `TIMESTAMP` cannot represent
--   a moment past 2038, and a refresh-token expiry is a future date.
-- * The columns that must compare exactly — `email` and every `token_hash` —
--   carry `utf8mb4_0900_as_cs`. MySQL's default collation is case-insensitive,
--   and the repository contracts say these are matched exactly; leaving the
--   default would make MySQL disagree with SQLite and PostgreSQL about which
--   values collide. It is `_as_cs` and not the more obvious `_bin` because
--   MySQL sets the protocol BINARY flag on any `_bin` column, which makes sqlx
--   report it as `VARBINARY` and refuse to decode it into a `String`.
--
-- `utf8mb4_0900_as_cs` needs MySQL 8.0.1 or newer. MariaDB has no equivalent
-- name; a MariaDB deployment must edit these two collations (to
-- `utf8mb4_uca1400_as_cs` on 10.10+) before running the migration.
--
-- Indexes are declared inline because MySQL has no `CREATE INDEX IF NOT EXISTS`.

CREATE TABLE IF NOT EXISTS users (
    id              BINARY(16)   NOT NULL PRIMARY KEY,
    email           VARCHAR(320) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs NOT NULL,
    password_hash   TEXT         NOT NULL,
    role            VARCHAR(16)  NOT NULL DEFAULT 'user',
    failed_attempts BIGINT       NOT NULL DEFAULT 0,
    locked_until    DATETIME(6)  NULL,
    created_at      DATETIME(6)  NOT NULL,
    updated_at      DATETIME(6)  NOT NULL,
    UNIQUE KEY uq_users_email (email),
    CONSTRAINT ck_users_role CHECK (role IN ('user', 'admin'))
) ENGINE = InnoDB;

-- Refresh tokens are stored as SHA-256 digests, hex-encoded, so the column is
-- exactly 64 ASCII characters. `family` groups every token descended from one
-- login, so presenting an already-rotated token lets us revoke the whole family
-- (stolen-token reuse detection).
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          BINARY(16)  NOT NULL PRIMARY KEY,
    user_id     BINARY(16)  NOT NULL,
    token_hash  VARCHAR(64)  CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs NOT NULL,
    family      BINARY(16)  NOT NULL,
    expires_at  DATETIME(6) NOT NULL,
    used_at     DATETIME(6) NULL,
    revoked     BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at  DATETIME(6) NOT NULL,
    UNIQUE KEY uq_refresh_tokens_hash (token_hash),
    KEY idx_refresh_tokens_user (user_id),
    KEY idx_refresh_tokens_family (family),
    CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB;

CREATE TABLE IF NOT EXISTS notes (
    id         BINARY(16)  NOT NULL PRIMARY KEY,
    owner_id   BINARY(16)  NOT NULL,
    title      TEXT        NOT NULL,
    body       TEXT        NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    KEY idx_notes_owner_created (owner_id, created_at DESC),
    CONSTRAINT fk_notes_owner FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB;
