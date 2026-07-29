//! The PostgreSQL backend.
//!
//! Dialect notes, so the differences from the other backends are deliberate
//! rather than accidental: placeholders are numbered (`$1`), `RETURNING` is
//! available on both `INSERT` and `UPDATE`, ids are a native `UUID`, timestamps
//! are `TIMESTAMPTZ`, and `revoked` is a real `BOOLEAN` — so the SQLite
//! backend's `revoked = 0` is spelled `revoked = FALSE` here.
//!
//! Numbered placeholders are why these statements are not shared with the
//! SQLite and MySQL ones: a single string with `?` in it would have to be
//! rewritten at run time, and rewriting SQL is exactly the habit the repository
//! layer exists to avoid.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
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

pub struct PostgresUserRepository {
    pool: PgPool,
}

impl PostgresUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PostgresUserRepository {
    async fn insert(&self, user: NewUser) -> RepositoryResult<User> {
        // The UNIQUE constraint on `email` is what enforces the contract on the
        // trait; the conversion in `repository::sql` turns its violation into
        // `Conflict`.
        let row = sqlx::query_as::<_, UserRow>(&format!(
            "INSERT INTO users (id, email, password_hash, role, failed_attempts, created_at, updated_at)
             VALUES ($1, $2, $3, $4, 0, $5, $6)
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
        let row = sqlx::query_as::<_, UserRow>(&format!(
            "SELECT {USER_COLUMNS} FROM users WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(User::try_from).transpose()
    }

    async fn find_by_email(&self, email: &str) -> RepositoryResult<Option<User>> {
        let row = sqlx::query_as::<_, UserRow>(&format!(
            "SELECT {USER_COLUMNS} FROM users WHERE email = $1"
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
            "UPDATE users SET failed_attempts = $1, locked_until = $2, updated_at = $3 WHERE id = $4",
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
            "UPDATE users SET failed_attempts = 0, locked_until = NULL, updated_at = $1 WHERE id = $2",
        )
        .bind(Utc::now())
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn update_password_hash(&self, id: Uuid, password_hash: &str) -> RepositoryResult<()> {
        sqlx::query("UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3")
            .bind(password_hash)
            .bind(Utc::now())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn set_role(&self, id: Uuid, role: Role) -> RepositoryResult<()> {
        sqlx::query("UPDATE users SET role = $1, updated_at = $2 WHERE id = $3")
            .bind(role.as_str())
            .bind(Utc::now())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

pub struct PostgresNoteRepository {
    pool: PgPool,
}

impl PostgresNoteRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl NoteRepository for PostgresNoteRepository {
    async fn insert(&self, note: NewNote) -> RepositoryResult<Note> {
        let now = Utc::now();
        let row = sqlx::query_as::<_, NoteRow>(&format!(
            "INSERT INTO notes (id, owner_id, title, body, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6)
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
            "SELECT {NOTE_COLUMNS} FROM notes WHERE id = $1 AND owner_id = $2"
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
             WHERE owner_id = $1
             ORDER BY created_at DESC
             LIMIT $2 OFFSET $3"
        ))
        .bind(owner_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Note::from).collect())
    }

    async fn count_owned(&self, owner_id: Uuid) -> RepositoryResult<i64> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notes WHERE owner_id = $1")
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
            "UPDATE notes SET title = $1, body = $2, updated_at = $3
             WHERE id = $4 AND owner_id = $5
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
        let result = sqlx::query("DELETE FROM notes WHERE id = $1 AND owner_id = $2")
            .bind(id)
            .bind(owner_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }
}

pub struct PostgresTokenRepository {
    pool: PgPool,
}

impl PostgresTokenRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TokenRepository for PostgresTokenRepository {
    async fn insert(&self, token: NewRefreshToken) -> RepositoryResult<()> {
        sqlx::query(
            "INSERT INTO refresh_tokens (id, user_id, token_hash, family, expires_at, revoked, created_at)
             VALUES ($1, $2, $3, $4, $5, FALSE, $6)",
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
            "SELECT {TOKEN_COLUMNS} FROM refresh_tokens WHERE token_hash = $1"
        ))
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn mark_used(&self, id: Uuid) -> RepositoryResult<bool> {
        // The `used_at IS NULL` guard is what makes redemption single-shot: two
        // concurrent refreshes with the same token cannot both match. Under
        // PostgreSQL's read-committed default the loser re-reads the row after
        // the winner commits and finds `used_at` set, so it updates nothing.
        let result = sqlx::query(
            "UPDATE refresh_tokens SET used_at = $1
             WHERE id = $2 AND used_at IS NULL AND revoked = FALSE",
        )
        .bind(Utc::now())
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn revoke_family(&self, family: Uuid) -> RepositoryResult<()> {
        sqlx::query("UPDATE refresh_tokens SET revoked = TRUE WHERE family = $1")
            .bind(family)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: Uuid) -> RepositoryResult<()> {
        sqlx::query("UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl ExpiredTokenSweeper for PostgresTokenRepository {
    async fn delete_expired(&self, now: DateTime<Utc>) -> RepositoryResult<u64> {
        let result = sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

pub struct PostgresAccessTokenRepository {
    pool: PgPool,
}

impl PostgresAccessTokenRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AccessTokenRepository for PostgresAccessTokenRepository {
    async fn insert(&self, token: NewAccessToken) -> RepositoryResult<()> {
        sqlx::query(
            "INSERT INTO access_tokens (id, user_id, token_hash, session, role, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
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
            "SELECT {ACCESS_TOKEN_COLUMNS} FROM access_tokens WHERE token_hash = $1"
        ))
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn delete_by_session(&self, session: Uuid) -> RepositoryResult<()> {
        sqlx::query("DELETE FROM access_tokens WHERE session = $1")
            .bind(session)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_all_for_user(&self, user_id: Uuid) -> RepositoryResult<()> {
        sqlx::query("DELETE FROM access_tokens WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl ExpiredTokenSweeper for PostgresAccessTokenRepository {
    async fn delete_expired(&self, now: DateTime<Utc>) -> RepositoryResult<u64> {
        let result = sqlx::query("DELETE FROM access_tokens WHERE expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

pub struct PostgresHealthRepository {
    pool: PgPool,
}

impl PostgresHealthRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl HealthRepository for PostgresHealthRepository {
    async fn ping(&self) -> RepositoryResult<()> {
        // Cheap, and still proves a connection can be acquired and a statement
        // round-tripped — which is what readiness actually means.
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await?;
        Ok(())
    }
}
