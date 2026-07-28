//! Storage for server-side access tokens.
//!
//! Only [`crate::security::opaque`] uses this. The stateless formats keep the
//! identity inside the token and never touch a database to verify one; this
//! port exists so that the format which trades that away for revocation has
//! somewhere to put its rows.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, SqlitePool};
use uuid::Uuid;

use crate::repository::error::RepositoryResult;

#[derive(Debug, Clone, FromRow)]
pub struct AccessTokenRecord {
    /// Present for schema fidelity; not read by the application today.
    #[allow(dead_code)]
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    /// The refresh-token family this token was issued alongside.
    #[allow(dead_code)]
    pub session: Uuid,
    pub role: String,
    pub expires_at: DateTime<Utc>,
    #[allow(dead_code)]
    pub created_at: DateTime<Utc>,
}

pub struct NewAccessToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub session: Uuid,
    pub role: String,
    pub expires_at: DateTime<Utc>,
}

/// Access-token storage.
///
/// # Contract
///
/// * **`find_by_hash` matches the stored digest exactly.** Tokens are stored
///   hashed and never in the clear, so there is nothing to normalise.
/// * **Deletion is immediate and idempotent.** A deleted row must not
///   authenticate anybody on the next request; deleting nothing is success.
///   Rows are deleted rather than flagged because a revoked access token has no
///   later use — unlike a refresh token, whose reuse is evidence of theft.
#[async_trait]
pub trait AccessTokenRepository: Send + Sync + 'static {
    async fn insert(&self, token: NewAccessToken) -> RepositoryResult<()>;
    async fn find_by_hash(&self, token_hash: &str) -> RepositoryResult<Option<AccessTokenRecord>>;
    /// Ends one device's session without touching the user's others.
    async fn delete_by_session(&self, session: Uuid) -> RepositoryResult<()>;
    /// Password change, admin action, incident.
    async fn delete_all_for_user(&self, user_id: Uuid) -> RepositoryResult<()>;
}

const ACCESS_TOKEN_COLUMNS: &str = "id, user_id, token_hash, session, role, expires_at, created_at";

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
impl crate::repository::ExpiredTokenSweeper for SqliteAccessTokenRepository {
    async fn delete_expired(&self, now: DateTime<Utc>) -> RepositoryResult<u64> {
        let result = sqlx::query("DELETE FROM access_tokens WHERE expires_at < ?")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}
