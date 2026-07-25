//! Accounts and the credentials that prove them.
//!
//! Everything here is about *who someone is*. Nothing here knows what a session
//! is, how long one lasts, or how one is revoked — that belongs to
//! [`crate::service::SessionService`].
//!
//! Threat model owned by this file:
//!   * account enumeration — identical response and identical CPU cost whether
//!     or not the address exists, and whether or not the account is locked;
//!   * online password guessing — per-account lockout after repeated failures.

use std::{sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    config::SecurityConfig,
    domain::{Role, User},
    error::{AppError, AppResult},
    repository::{UserRepository, user_repository::NewUser},
    security::password::CredentialHasher,
};

/// Returned whichever way a duplicate registration is detected — the pre-check
/// or the store's constraint — so the two are indistinguishable.
const DUPLICATE_EMAIL: &str = "email is already registered";

/// Outcome of an admin bootstrap, for start-up logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminBootstrap {
    Created,
    Promoted,
    AlreadyAdmin,
}

pub struct AccountService {
    users: Arc<dyn UserRepository>,
    hasher: Arc<dyn CredentialHasher>,
    max_login_attempts: i64,
    lockout: Duration,
}

impl AccountService {
    pub fn new(
        users: Arc<dyn UserRepository>,
        hasher: Arc<dyn CredentialHasher>,
        config: &SecurityConfig,
    ) -> Self {
        Self {
            users,
            hasher,
            max_login_attempts: config.max_login_attempts,
            lockout: config.lockout_duration,
        }
    }

    /// Registers an account.
    ///
    /// Registration has to report a conflict to be usable at all, so this
    /// endpoint is an enumeration oracle by construction; rate limiting is what
    /// contains it. See the known gaps in the README.
    pub async fn register(&self, email: &str, password: &str) -> AppResult<User> {
        let email = normalise_email(email);
        let password_hash = self.hasher.hash(password.to_owned()).await?;

        if self.users.find_by_email(&email).await?.is_some() {
            return Err(AppError::Conflict(DUPLICATE_EMAIL.into()));
        }

        // The check above is a fast path, not the guarantee. Two concurrent
        // registrations both pass it and the store's constraint decides; both
        // routes must produce the same response, or the race is observable.
        self.users
            .insert(NewUser {
                id: Uuid::new_v4(),
                email,
                password_hash,
                role: Role::User,
            })
            .await
            .map_err(|err| match AppError::from(err) {
                AppError::Conflict(_) => AppError::Conflict(DUPLICATE_EMAIL.into()),
                other => other,
            })
    }

    /// Verifies a credential and returns the account behind it.
    ///
    /// Every failure — unknown address, wrong password, locked account —
    /// produces `Unauthorized` after the same amount of hashing, so neither the
    /// response nor its timing reveals which one occurred.
    pub async fn authenticate(&self, email: &str, password: &str) -> AppResult<User> {
        let email = normalise_email(email);
        let now = Utc::now();

        let Some(user) = self.users.find_by_email(&email).await? else {
            // Spend the same CPU as a real verification before failing.
            self.hasher.verify_dummy(password.to_owned()).await?;
            return Err(AppError::Unauthorized);
        };

        // Verified before the lock is consulted: returning early for a locked
        // account would answer faster than a wrong password, and the lockout
        // itself would become an "this address is registered" oracle.
        let password_matches = self
            .hasher
            .verify(password.to_owned(), user.password_hash.clone())
            .await?;

        if user.is_locked_at(now) {
            tracing::warn!(user_id = %user.id, "login attempt against a locked account");
            return Err(AppError::Unauthorized);
        }

        if !password_matches {
            self.record_failure(&user, now).await?;
            return Err(AppError::Unauthorized);
        }

        if user.failed_attempts > 0 || user.locked_until.is_some() {
            self.users.clear_login_failures(user.id).await?;
        }

        Ok(user)
    }

    /// Loads an account that is still allowed to hold a session.
    pub async fn active(&self, user_id: Uuid) -> AppResult<User> {
        let user = self
            .users
            .find_by_id(user_id)
            .await?
            .ok_or(AppError::Unauthorized)?;

        if user.is_locked_at(Utc::now()) {
            tracing::warn!(user_id = %user.id, "session use while the account is locked");
            return Err(AppError::Unauthorized);
        }

        Ok(user)
    }

    /// Replaces a password, given the current one. Revoking the sessions that
    /// were established with the old password is the caller's job — this
    /// service does not know sessions exist.
    pub async fn change_password(&self, user_id: Uuid, current: &str, new: &str) -> AppResult<()> {
        let user = self
            .users
            .find_by_id(user_id)
            .await?
            .ok_or(AppError::Unauthorized)?;

        if !self
            .hasher
            .verify(current.to_owned(), user.password_hash.clone())
            .await?
        {
            return Err(AppError::Unauthorized);
        }

        let new_hash = self.hasher.hash(new.to_owned()).await?;
        self.users.update_password_hash(user_id, &new_hash).await?;
        Ok(())
    }

    /// Ensures an administrator exists, so the admin routes are reachable on a
    /// fresh deployment. Idempotent: an existing account is promoted in place
    /// and its password is left alone — a bootstrap value must never be able to
    /// overwrite a real credential.
    pub async fn ensure_admin(&self, email: &str, password: &str) -> AppResult<AdminBootstrap> {
        let email = normalise_email(email);

        if let Some(existing) = self.users.find_by_email(&email).await? {
            if existing.role == Role::Admin {
                return Ok(AdminBootstrap::AlreadyAdmin);
            }
            self.users.set_role(existing.id, Role::Admin).await?;
            tracing::warn!(user_id = %existing.id, "existing account promoted to admin");
            return Ok(AdminBootstrap::Promoted);
        }

        let password_hash = self.hasher.hash(password.to_owned()).await?;
        let created = self
            .users
            .insert(NewUser {
                id: Uuid::new_v4(),
                email,
                password_hash,
                role: Role::Admin,
            })
            .await?;

        tracing::warn!(user_id = %created.id, "administrator account created from bootstrap config");
        Ok(AdminBootstrap::Created)
    }

    async fn record_failure(&self, user: &User, now: DateTime<Utc>) -> AppResult<()> {
        let attempts = user.failed_attempts + 1;
        let locked_until = if attempts >= self.max_login_attempts {
            tracing::warn!(user_id = %user.id, attempts, "account locked after repeated failures");
            Some(
                now + chrono::Duration::from_std(self.lockout)
                    .unwrap_or(chrono::Duration::minutes(15)),
            )
        } else {
            None
        };
        self.users
            .record_failed_login(user.id, attempts, locked_until)
            .await?;
        Ok(())
    }
}

/// Emails are compared case-insensitively; storing them normalised keeps the
/// UNIQUE index honest without needing an expression index.
fn normalise_email(raw: &str) -> String {
    raw.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::normalise_email;

    #[test]
    fn normalises_case_and_surrounding_space() {
        assert_eq!(normalise_email("  User@Example.COM "), "user@example.com");
    }
}
