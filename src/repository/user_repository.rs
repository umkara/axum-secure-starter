use anyhow::anyhow;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    domain::{Role, User},
    repository::error::{RepositoryError, RepositoryResult},
};

/// Data to create a new account. The service hashes the password before it
/// reaches here; repositories never see plaintext.
pub struct NewUser {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub role: Role,
}

/// Account storage.
///
/// # Contract
///
/// Every implementation must uphold these, or callers built against one
/// implementation will misbehave against another:
///
/// * **`insert` rejects a duplicate email with [`RepositoryError::Conflict`].**
///   This is load-bearing, not advisory. Services check for an existing account
///   before inserting, but the check and the write are separate steps: two
///   concurrent registrations both pass the check, and only the store can
///   decide. An implementation that lets the second write through creates
///   duplicate accounts; one that fails with a generic error turns a routine
///   conflict into a 500.
/// * **`email` is compared exactly.** Callers normalise (trim, lowercase)
///   before calling, so implementations must not normalise again — doing so
///   would make two callers disagree about which addresses collide.
/// * **Updates to a missing id are not an error.** They affect nothing and
///   return `Ok`; callers that need existence check it explicitly.
#[async_trait]
pub trait UserRepository: Send + Sync + 'static {
    async fn insert(&self, user: NewUser) -> RepositoryResult<User>;
    async fn find_by_id(&self, id: Uuid) -> RepositoryResult<Option<User>>;
    /// `email` must already be normalised by the caller.
    async fn find_by_email(&self, email: &str) -> RepositoryResult<Option<User>>;
    /// Records a failed attempt and, when the caller has decided the threshold
    /// is reached, the moment the lockout expires.
    async fn record_failed_login(
        &self,
        id: Uuid,
        attempts: i64,
        locked_until: Option<DateTime<Utc>>,
    ) -> RepositoryResult<()>;
    async fn clear_login_failures(&self, id: Uuid) -> RepositoryResult<()>;
    async fn update_password_hash(&self, id: Uuid, password_hash: &str) -> RepositoryResult<()>;
    async fn set_role(&self, id: Uuid, role: Role) -> RepositoryResult<()>;
}

/// The stored shape of an account, before it is a [`User`].
///
/// Every backend produces one of these and then converts. `role` is a string
/// here and a [`Role`] in the domain, which is the whole reason the type
/// exists: the encoding belongs to the store, and the conversion is allowed to
/// fail.
///
/// `updated_at` is written on every mutation but never read back — nothing in
/// the domain depends on it — so it is not a field here.
///
/// The `FromRow` derive is generic over the driver, so one row type serves
/// SQLite, PostgreSQL and MySQL; the document backend fills it in by hand.
#[derive(sqlx::FromRow)]
pub(crate) struct UserRow {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub role: String,
    pub failed_attempts: i64,
    pub locked_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl TryFrom<UserRow> for User {
    type Error = RepositoryError;

    fn try_from(row: UserRow) -> Result<Self, Self::Error> {
        // An unparseable role means the column holds something no version of
        // this code writes — a hand-edited row, or a migration that got ahead of
        // the binary. Refusing beats guessing: silently defaulting to `user`
        // would demote an admin, and to `admin` would escalate everyone.
        let role = row.role.parse().map_err(|_| {
            RepositoryError::Backend(anyhow!("unknown role `{}` stored for user", row.role))
        })?;

        Ok(User {
            id: row.id,
            email: row.email,
            password_hash: row.password_hash,
            role,
            failed_attempts: row.failed_attempts,
            locked_until: row.locked_until,
            created_at: row.created_at,
        })
    }
}
