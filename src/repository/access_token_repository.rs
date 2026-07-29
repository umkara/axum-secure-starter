//! Storage for server-side access tokens.
//!
//! Only [`crate::security::opaque`] uses this. The stateless formats keep the
//! identity inside the token and never touch a database to verify one; this
//! port exists so that the format which trades that away for revocation has
//! somewhere to put its rows.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::repository::error::RepositoryResult;

#[derive(Debug, Clone, sqlx::FromRow)]
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
