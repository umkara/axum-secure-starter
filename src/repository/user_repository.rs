use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
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

const USER_COLUMNS: &str =
    "id, email, password_hash, role, failed_attempts, locked_until, created_at, updated_at";

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
        // The UNIQUE index on `email` is what enforces the contract above; the
        // conversion in `repository::error` turns its violation into
        // `Conflict`.
        let row = sqlx::query_as::<_, User>(&format!(
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

        Ok(row)
    }

    async fn find_by_id(&self, id: Uuid) -> RepositoryResult<Option<User>> {
        let row =
            sqlx::query_as::<_, User>(&format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?"))
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row)
    }

    async fn find_by_email(&self, email: &str) -> RepositoryResult<Option<User>> {
        let row =
            sqlx::query_as::<_, User>(&format!("SELECT {USER_COLUMNS} FROM users WHERE email = ?"))
                .bind(email)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row)
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
