//! The SQLite backend.
//!
//! Dialect notes, so the differences from the other backends are deliberate
//! rather than accidental: placeholders are `?`, `RETURNING` is available on
//! both `INSERT` and `UPDATE`, ids are BLOBs and timestamps RFC 3339 TEXT, and
//! `revoked` is an INTEGER holding 0 or 1.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
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

pub struct SqliteUserRepository {
    pool: SqlitePool,
}

impl SqliteUserRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for SqliteUserRepository {
    async fn insert(&self, user: NewUser) -> RepositoryResult<User> {
        // The UNIQUE index on `email` is what enforces the contract on the
        // trait; the conversion in `repository::sql` turns its violation into
        // `Conflict`.
        let row = sqlx::query_as::<_, UserRow>(&format!(
            "INSERT INTO users (id, email, password_hash, role, failed_attempts, created_at, updated_at)
             VALUES (?, ?, ?, ?, 0, ?, ?)
             RETURNING {USER_COLUMNS}"
        ))
        .bind(user.id)
        .bind(user.email)
        .bind(user.password_hash)
        .bind(user.role.as_str())
        .bind(Utc::now())
        .bind(Utc::now())
        .fetch_one(&self.pool)
        .await
        .map_err(RepositoryError::from)?;

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

pub struct SqliteNoteRepository {
    pool: SqlitePool,
}

impl SqliteNoteRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl NoteRepository for SqliteNoteRepository {
    async fn insert(&self, note: NewNote) -> RepositoryResult<Note> {
        let now = Utc::now();
        let row = sqlx::query_as::<_, NoteRow>(&format!(
            "INSERT INTO notes (id, owner_id, title, body, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)
             RETURNING {NOTE_COLUMNS}"
        ))
        .bind(note.id)
        .bind(note.owner_id)
        .bind(note.title)
        .bind(note.body)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
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
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notes WHERE owner_id = ?")
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
        let row = sqlx::query_as::<_, NoteRow>(&format!(
            "UPDATE notes SET title = ?, body = ?, updated_at = ?
             WHERE id = ? AND owner_id = ?
             RETURNING {NOTE_COLUMNS}"
        ))
        .bind(title)
        .bind(body)
        .bind(Utc::now())
        .bind(id)
        .bind(owner_id)
        .fetch_optional(&self.pool)
        .await?;
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

pub struct SqliteTokenRepository {
    pool: SqlitePool,
}

impl SqliteTokenRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TokenRepository for SqliteTokenRepository {
    async fn insert(&self, token: NewRefreshToken) -> RepositoryResult<()> {
        sqlx::query(
            "INSERT INTO refresh_tokens (id, user_id, token_hash, family, expires_at, revoked, created_at)
             VALUES (?, ?, ?, ?, ?, 0, ?)",
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
        // The `used_at IS NULL` guard is what makes redemption single-shot:
        // two concurrent refreshes with the same token cannot both match.
        let result = sqlx::query(
            "UPDATE refresh_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL AND revoked = 0",
        )
        .bind(Utc::now())
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn revoke_family(&self, family: Uuid) -> RepositoryResult<()> {
        sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE family = ?")
            .bind(family)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: Uuid) -> RepositoryResult<()> {
        sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl ExpiredTokenSweeper for SqliteTokenRepository {
    async fn delete_expired(&self, now: DateTime<Utc>) -> RepositoryResult<u64> {
        let result = sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < ?")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

pub struct SqliteAccessTokenRepository {
    pool: SqlitePool,
}

impl SqliteAccessTokenRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AccessTokenRepository for SqliteAccessTokenRepository {
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
impl ExpiredTokenSweeper for SqliteAccessTokenRepository {
    async fn delete_expired(&self, now: DateTime<Utc>) -> RepositoryResult<u64> {
        let result = sqlx::query("DELETE FROM access_tokens WHERE expires_at < ?")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

pub struct SqliteHealthRepository {
    pool: SqlitePool,
}

impl SqliteHealthRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl HealthRepository for SqliteHealthRepository {
    async fn ping(&self) -> RepositoryResult<()> {
        // Cheap, and still proves a connection can be acquired and a statement
        // round-tripped — which is what readiness actually means.
        sqlx::query_scalar::<_, i64>("SELECT 1")
            .fetch_one(&self.pool)
            .await?;
        Ok(())
    }
}
