use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::repository::error::RepositoryResult;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RefreshTokenRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub family: Uuid,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub revoked: bool,
    /// Present for schema fidelity; not read by the application today.
    #[allow(dead_code)]
    pub created_at: DateTime<Utc>,
}

impl RefreshTokenRecord {
    /// A token is only usable if it has never been redeemed, has not been
    /// revoked, and has not expired.
    pub fn is_usable_at(&self, now: DateTime<Utc>) -> bool {
        !self.revoked && self.used_at.is_none() && self.expires_at > now
    }
}

pub struct NewRefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub family: Uuid,
    pub expires_at: DateTime<Utc>,
}

/// Refresh-token storage, as a session needs it.
///
/// # Contract
///
/// * **`mark_used` is atomic and single-shot.** It returns `true` for the one
///   caller that redeemed the token and `false` for every other — already
///   redeemed, revoked, or lost a concurrent race. Callers rely on this to
///   detect replay: an implementation that returns `true` twice hands two
///   clients a valid session from one stolen token.
/// * **`find_by_hash` matches the stored digest exactly.** Tokens are stored
///   hashed and never in the clear, so there is nothing to normalise.
/// * **Revocation is idempotent** and silently affects nothing when no rows
///   match.
#[async_trait]
pub trait TokenRepository: Send + Sync + 'static {
    async fn insert(&self, token: NewRefreshToken) -> RepositoryResult<()>;
    async fn find_by_hash(&self, token_hash: &str) -> RepositoryResult<Option<RefreshTokenRecord>>;
    /// Marks a token redeemed. See the atomicity requirement above.
    async fn mark_used(&self, id: Uuid) -> RepositoryResult<bool>;
    /// Revokes every token descended from one login.
    async fn revoke_family(&self, family: Uuid) -> RepositoryResult<()>;
    async fn revoke_all_for_user(&self, user_id: Uuid) -> RepositoryResult<()>;
}

/// Housekeeping, kept separate from [`TokenRepository`] because its only
/// consumer is the background sweep. Handing a janitor the ability to revoke
/// sessions would be granting authority it has no use for.
#[async_trait]
pub trait ExpiredTokenSweeper: Send + Sync + 'static {
    /// Drops rows that can no longer be redeemed. Returns how many went.
    async fn delete_expired(&self, now: DateTime<Utc>) -> RepositoryResult<u64>;
}
