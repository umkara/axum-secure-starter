//! The MySQL / MariaDB backend.
//!
//! Dialect notes, so the differences from the other backends are deliberate
//! rather than accidental. Placeholders are `?`, as in SQLite. Ids are
//! `BINARY(16)` — sqlx encodes `Uuid` as raw bytes here, not text — and
//! timestamps are `DATETIME(6)`, chosen over `TIMESTAMP` because a refresh
//! token can outlive 2038.
//!
//! # Two behaviours MySQL does not give for free
//!
//! **There is no `RETURNING`.** Where the other backends write and read in one
//! statement, this one writes and then reads inside a transaction. The
//! transaction is not decoration: without it the read could observe another
//! session's later write, and `insert` would answer with a row it did not
//! create.
//!
//! **`rows_affected` counts changed rows, not matched rows.** Re-saving a note
//! with the title and body it already has changes nothing, so an `UPDATE` that
//! matched the row still reports zero. `update_owned` must distinguish "no such
//! note, or not yours" from "yours, and already said that" — a `SELECT` under
//! the same `WHERE` answers that question and `rows_affected` does not.
//! `mark_used` and `delete_owned` are safe to judge by `rows_affected`, because
//! `NULL` → a timestamp and a deletion are always changes.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::MySqlPool;
use uuid::Uuid;

use crate::{
    domain::{Note, Role, User},
    repository::{
        AccessTokenRepository, ExpiredTokenSweeper, HealthRepository, NoteRepository,
        TokenRepository, UserRepository,
        access_token_repository::{AccessTokenRecord, NewAccessToken},
        error::{RepositoryError, RepositoryResult},
        note_repository::{NewNote, NoteRow},
        sql::{ACCESS_TOKEN_COLUMNS, NOTE_COLUMNS, TOKEN_COLUMNS, USER_COLUMNS},
        token_repository::{NewRefreshToken, RefreshTokenRecord},
        user_repository::{NewUser, UserRow},
    },
};

pub struct MySqlUserRepository {
    pool: MySqlPool,
}

impl MySqlUserRepository {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for MySqlUserRepository {
    async fn insert(&self, user: NewUser) -> RepositoryResult<User> {
        let id = user.id;
        let now = Utc::now();

        let mut tx = self.pool.begin().await.map_err(RepositoryError::from)?;

        // The UNIQUE key on `email` is what enforces the contract on the trait;
        // the conversion in `repository::sql` turns its violation into
        // `Conflict`.
        sqlx::query(
            "INSERT INTO users (id, email, password_hash, role, failed_attempts, created_at, updated_at)
             VALUES (?, ?, ?, ?, 0, ?, ?)",
        )
        .bind(id)
        .bind(user.email)
        .bind(user.password_hash)
        .bind(user.role.as_str())
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(RepositoryError::from)?;

        let row =
            sqlx::query_as::<_, UserRow>(&format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?"))
                .bind(id)
                .fetch_one(&mut *tx)
                .await
                .map_err(RepositoryError::from)?;

        tx.commit().await.map_err(RepositoryError::from)?;

        row.try_into()
    }

    async fn find_by_id(&self, id: Uuid) -> RepositoryResult<Option<User>> {
        let row =
            sqlx::query_as::<_, UserRow>(&format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?"))
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
        row.map(User::try_from).transpose()
    }

    async fn find_by_email(&self, email: &str) -> RepositoryResult<Option<User>> {
        let row = sqlx::query_as::<_, UserRow>(&format!(
            "SELECT {USER_COLUMNS} FROM users WHERE email = ?"
        ))
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        row.map(User::try_from).transpose()
    }

    async fn record_failed_login(
        &self,
        id: Uuid,
        attempts: i64,
        locked_until: Option<DateTime<Utc>>,
    ) -> RepositoryResult<()> {
        sqlx::query(
            "UPDATE users SET failed_attempts = ?, locked_until = ?, updated_at = ? WHERE id = ?",
        )
        .bind(attempts)
        .bind(locked_until)
        .bind(Utc::now())
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn clear_login_failures(&self, id: Uuid) -> RepositoryResult<()> {
        sqlx::query(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?",
        )
        .bind(Utc::now())
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn update_password_hash(&self, id: Uuid, password_hash: &str) -> RepositoryResult<()> {
        sqlx::query("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?")
            .bind(password_hash)
            .bind(Utc::now())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn set_role(&self, id: Uuid, role: Role) -> RepositoryResult<()> {
        sqlx::query("UPDATE users SET role = ?, updated_at = ? WHERE id = ?")
            .bind(role.as_str())
            .bind(Utc::now())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

pub struct MySqlNoteRepository {
    pool: MySqlPool,
}

impl MySqlNoteRepository {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl NoteRepository for MySqlNoteRepository {
    async fn insert(&self, note: NewNote) -> RepositoryResult<Note> {
        let id = note.id;
        let now = Utc::now();

        let mut tx = self.pool.begin().await.map_err(RepositoryError::from)?;

        sqlx::query(
            "INSERT INTO notes (id, owner_id, title, body, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(note.owner_id)
        .bind(note.title)
        .bind(note.body)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(RepositoryError::from)?;

        let row =
            sqlx::query_as::<_, NoteRow>(&format!("SELECT {NOTE_COLUMNS} FROM notes WHERE id = ?"))
                .bind(id)
                .fetch_one(&mut *tx)
                .await
                .map_err(RepositoryError::from)?;

        tx.commit().await.map_err(RepositoryError::from)?;

        Ok(row.into())
    }

    async fn find_owned(&self, id: Uuid, owner_id: Uuid) -> RepositoryResult<Option<Note>> {
        let row = sqlx::query_as::<_, NoteRow>(&format!(
            "SELECT {NOTE_COLUMNS} FROM notes WHERE id = ? AND owner_id = ?"
        ))
        .bind(id)
        .bind(owner_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Note::from))
    }

    async fn list_owned(
        &self,
        owner_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> RepositoryResult<Vec<Note>> {
        let rows = sqlx::query_as::<_, NoteRow>(&format!(
            "SELECT {NOTE_COLUMNS} FROM notes
             WHERE owner_id = ?
             ORDER BY created_at DESC
             LIMIT ? OFFSET ?"
        ))
        .bind(owner_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Note::from).collect())
    }

    async fn count_owned(&self, owner_id: Uuid) -> RepositoryResult<i64> {
        // `COUNT(*)` is BIGINT UNSIGNED in MySQL, which does not decode into
        // `i64`. The cast is what keeps the port's signature the same shape on
        // every backend.
        let count: i64 =
            sqlx::query_scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM notes WHERE owner_id = ?")
                .bind(owner_id)
                .fetch_one(&self.pool)
                .await?;
        Ok(count)
    }

    async fn update_owned(
        &self,
        id: Uuid,
        owner_id: Uuid,
        title: &str,
        body: &str,
    ) -> RepositoryResult<Option<Note>> {
        let mut tx = self.pool.begin().await.map_err(RepositoryError::from)?;

        sqlx::query(
            "UPDATE notes SET title = ?, body = ?, updated_at = ?
             WHERE id = ? AND owner_id = ?",
        )
        .bind(title)
        .bind(body)
        .bind(Utc::now())
        .bind(id)
        .bind(owner_id)
        .execute(&mut *tx)
        .await
        .map_err(RepositoryError::from)?;

        // See the module note: the `SELECT`, not `rows_affected`, is what
        // decides whether the note exists and belongs to this owner.
        let row = sqlx::query_as::<_, NoteRow>(&format!(
            "SELECT {NOTE_COLUMNS} FROM notes WHERE id = ? AND owner_id = ?"
        ))
        .bind(id)
        .bind(owner_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(RepositoryError::from)?;

        tx.commit().await.map_err(RepositoryError::from)?;

        Ok(row.map(Note::from))
    }

    async fn delete_owned(&self, id: Uuid, owner_id: Uuid) -> RepositoryResult<bool> {
        let result = sqlx::query("DELETE FROM notes WHERE id = ? AND owner_id = ?")
            .bind(id)
            .bind(owner_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }
}

pub struct MySqlTokenRepository {
    pool: MySqlPool,
}

impl MySqlTokenRepository {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TokenRepository for MySqlTokenRepository {
    async fn insert(&self, token: NewRefreshToken) -> RepositoryResult<()> {
        sqlx::query(
            "INSERT INTO refresh_tokens (id, user_id, token_hash, family, expires_at, revoked, created_at)
             VALUES (?, ?, ?, ?, ?, FALSE, ?)",
        )
        .bind(token.id)
        .bind(token.user_id)
        .bind(token.token_hash)
        .bind(token.family)
        .bind(token.expires_at)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_by_hash(&self, token_hash: &str) -> RepositoryResult<Option<RefreshTokenRecord>> {
        let row = sqlx::query_as::<_, RefreshTokenRecord>(&format!(
            "SELECT {TOKEN_COLUMNS} FROM refresh_tokens WHERE token_hash = ?"
        ))
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn mark_used(&self, id: Uuid) -> RepositoryResult<bool> {
        // Safe to judge by `rows_affected` despite the module note: `used_at`
        // moves from NULL to a timestamp, which is always a change. The
        // `used_at IS NULL` guard is what makes redemption single-shot — two
        // concurrent refreshes with the same token cannot both match, because
        // InnoDB holds the row lock until the winner commits.
        let result = sqlx::query(
            "UPDATE refresh_tokens SET used_at = ?
             WHERE id = ? AND used_at IS NULL AND revoked = FALSE",
        )
        .bind(Utc::now())
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn revoke_family(&self, family: Uuid) -> RepositoryResult<()> {
        sqlx::query("UPDATE refresh_tokens SET revoked = TRUE WHERE family = ?")
            .bind(family)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: Uuid) -> RepositoryResult<()> {
        sqlx::query("UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl ExpiredTokenSweeper for MySqlTokenRepository {
    async fn delete_expired(&self, now: DateTime<Utc>) -> RepositoryResult<u64> {
        let result = sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < ?")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

pub struct MySqlAccessTokenRepository {
    pool: MySqlPool,
}

impl MySqlAccessTokenRepository {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AccessTokenRepository for MySqlAccessTokenRepository {
    async fn insert(&self, token: NewAccessToken) -> RepositoryResult<()> {
        sqlx::query(
            "INSERT INTO access_tokens (id, user_id, token_hash, session, role, expires_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(token.id)
        .bind(token.user_id)
        .bind(token.token_hash)
        .bind(token.session)
        .bind(token.role)
        .bind(token.expires_at)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_by_hash(&self, token_hash: &str) -> RepositoryResult<Option<AccessTokenRecord>> {
        let row = sqlx::query_as::<_, AccessTokenRecord>(&format!(
            "SELECT {ACCESS_TOKEN_COLUMNS} FROM access_tokens WHERE token_hash = ?"
        ))
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn delete_by_session(&self, session: Uuid) -> RepositoryResult<()> {
        sqlx::query("DELETE FROM access_tokens WHERE session = ?")
            .bind(session)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_all_for_user(&self, user_id: Uuid) -> RepositoryResult<()> {
        sqlx::query("DELETE FROM access_tokens WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl ExpiredTokenSweeper for MySqlAccessTokenRepository {
    async fn delete_expired(&self, now: DateTime<Utc>) -> RepositoryResult<u64> {
        let result = sqlx::query("DELETE FROM access_tokens WHERE expires_at < ?")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

pub struct MySqlHealthRepository {
    pool: MySqlPool,
}

impl MySqlHealthRepository {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl HealthRepository for MySqlHealthRepository {
    async fn ping(&self) -> RepositoryResult<()> {
        // Cheap, and still proves a connection can be acquired and a statement
        // round-tripped — which is what readiness actually means.
        sqlx::query_scalar::<_, i64>("SELECT 1")
            .fetch_one(&self.pool)
            .await?;
        Ok(())
    }
}
