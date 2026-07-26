//! In-memory stand-ins for the collaborators a service depends on.
//!
//! These exist so a test about *policy* — how many failures lock an account,
//! whether a redeemed token can be redeemed again — does not have to pay for
//! Argon2, a database, or an HTTP round trip. The end-to-end suites still
//! exercise the real implementations; these make the fast feedback loop
//! possible without giving that up.
//!
//! Compiled only for tests.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    domain::{Role, User},
    error::{AppError, AppResult},
    repository::{
        ExpiredTokenSweeper, RepositoryError, RepositoryResult, TokenRepository, UserRepository,
        token_repository::{NewRefreshToken, RefreshTokenRecord},
        user_repository::NewUser,
    },
    security::{CredentialHasher, TokenIssuer, jwt::TokenIdentity},
};

/// Hashing that is instant and reversible-by-inspection: the "hash" is the
/// plaintext with a marker. Wrong for production, exactly right for asserting
/// which branch a service took.
pub struct FakeHasher;

#[async_trait]
impl CredentialHasher for FakeHasher {
    async fn hash(&self, plaintext: String) -> AppResult<String> {
        Ok(format!("fake${plaintext}"))
    }

    async fn verify(&self, plaintext: String, stored_hash: String) -> AppResult<bool> {
        Ok(stored_hash == format!("fake${plaintext}"))
    }

    async fn verify_dummy(&self, _plaintext: String) -> AppResult<()> {
        Ok(())
    }
}

/// Issues opaque, unsigned tokens. Signature handling has its own tests; these
/// only need identity to round-trip.
pub struct FakeTokenIssuer;

impl TokenIssuer for FakeTokenIssuer {
    fn issue(&self, user_id: Uuid, role: Role) -> AppResult<String> {
        Ok(format!("{user_id}:{}", role.as_str()))
    }

    fn verify(&self, token: &str) -> AppResult<TokenIdentity> {
        let (id, role) = token.split_once(':').ok_or(AppError::Unauthorized)?;
        Ok(TokenIdentity {
            user_id: id.parse().map_err(|_| AppError::Unauthorized)?,
            role: role.parse().map_err(|_| AppError::Unauthorized)?,
        })
    }

    fn ttl_seconds(&self) -> i64 {
        900
    }
}

#[derive(Default)]
pub struct InMemoryUserRepository {
    users: Mutex<Vec<User>>,
}

impl InMemoryUserRepository {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn find(&self, id: Uuid) -> Option<User> {
        self.users
            .lock()
            .unwrap()
            .iter()
            .find(|u| u.id == id)
            .cloned()
    }
}

#[async_trait]
impl UserRepository for InMemoryUserRepository {
    async fn insert(&self, user: NewUser) -> RepositoryResult<User> {
        let mut users = self.users.lock().unwrap();
        if users.iter().any(|u| u.email == user.email) {
            // Mirrors what the UNIQUE index does, so the race path is reachable
            // here too.
            return Err(RepositoryError::Conflict);
        }

        let now = Utc::now();
        let stored = User {
            id: user.id,
            email: user.email,
            password_hash: user.password_hash,
            role: user.role,
            failed_attempts: 0,
            locked_until: None,
            created_at: now,
        };
        users.push(stored.clone());
        Ok(stored)
    }

    async fn find_by_id(&self, id: Uuid) -> RepositoryResult<Option<User>> {
        Ok(self.find(id))
    }

    async fn find_by_email(&self, email: &str) -> RepositoryResult<Option<User>> {
        Ok(self
            .users
            .lock()
            .unwrap()
            .iter()
            .find(|u| u.email == email)
            .cloned())
    }

    async fn record_failed_login(
        &self,
        id: Uuid,
        attempts: i64,
        locked_until: Option<DateTime<Utc>>,
    ) -> RepositoryResult<()> {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.iter_mut().find(|u| u.id == id) {
            user.failed_attempts = attempts;
            user.locked_until = locked_until;
        }
        Ok(())
    }

    async fn clear_login_failures(&self, id: Uuid) -> RepositoryResult<()> {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.iter_mut().find(|u| u.id == id) {
            user.failed_attempts = 0;
            user.locked_until = None;
        }
        Ok(())
    }

    async fn update_password_hash(&self, id: Uuid, password_hash: &str) -> RepositoryResult<()> {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.iter_mut().find(|u| u.id == id) {
            user.password_hash = password_hash.to_string();
        }
        Ok(())
    }

    async fn set_role(&self, id: Uuid, role: Role) -> RepositoryResult<()> {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.iter_mut().find(|u| u.id == id) {
            user.role = role;
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct InMemoryTokenRepository {
    tokens: Mutex<HashMap<Uuid, RefreshTokenRecord>>,
}

impl InMemoryTokenRepository {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

#[async_trait]
impl TokenRepository for InMemoryTokenRepository {
    async fn insert(&self, token: NewRefreshToken) -> RepositoryResult<()> {
        self.tokens.lock().unwrap().insert(
            token.id,
            RefreshTokenRecord {
                id: token.id,
                user_id: token.user_id,
                token_hash: token.token_hash,
                family: token.family,
                expires_at: token.expires_at,
                used_at: None,
                revoked: false,
                created_at: Utc::now(),
            },
        );
        Ok(())
    }

    async fn find_by_hash(&self, token_hash: &str) -> RepositoryResult<Option<RefreshTokenRecord>> {
        Ok(self
            .tokens
            .lock()
            .unwrap()
            .values()
            .find(|t| t.token_hash == token_hash)
            .cloned())
    }

    async fn mark_used(&self, id: Uuid) -> RepositoryResult<bool> {
        let mut tokens = self.tokens.lock().unwrap();
        match tokens.get_mut(&id) {
            Some(token) if token.used_at.is_none() && !token.revoked => {
                token.used_at = Some(Utc::now());
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn revoke_family(&self, family: Uuid) -> RepositoryResult<()> {
        let mut tokens = self.tokens.lock().unwrap();
        for token in tokens.values_mut().filter(|t| t.family == family) {
            token.revoked = true;
        }
        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: Uuid) -> RepositoryResult<()> {
        let mut tokens = self.tokens.lock().unwrap();
        for token in tokens.values_mut().filter(|t| t.user_id == user_id) {
            token.revoked = true;
        }
        Ok(())
    }
}

#[async_trait]
impl ExpiredTokenSweeper for InMemoryTokenRepository {
    async fn delete_expired(&self, now: DateTime<Utc>) -> RepositoryResult<u64> {
        let mut tokens = self.tokens.lock().unwrap();
        let before = tokens.len();
        tokens.retain(|_, t| t.expires_at >= now);
        Ok((before - tokens.len()) as u64)
    }
}
