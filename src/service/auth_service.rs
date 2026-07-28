//! Authentication use cases.
//!
//! This is a coordinator, not a container of rules. It holds no repositories
//! and makes no policy decisions of its own; it composes [`AccountService`]
//! (who someone is) with [`SessionService`] (what a session may do) into the
//! operations a handler actually performs.
//!
//! The composition is the point. "Log in" is "verify a credential, then start a
//! session"; "change a password" is "replace the credential, then end every
//! session established with the old one". Neither service can express that
//! alone, and neither should have to know about the other.

use std::sync::Arc;

use uuid::Uuid;

use crate::{
    domain::User,
    error::AppResult,
    service::{
        account_service::{AccountService, AdminBootstrap},
        session_service::{AuthTokens, SessionService},
    },
};

pub struct AuthService {
    accounts: Arc<AccountService>,
    sessions: Arc<SessionService>,
}

impl AuthService {
    pub fn new(accounts: Arc<AccountService>, sessions: Arc<SessionService>) -> Self {
        Self { accounts, sessions }
    }

    pub async fn register(&self, email: &str, password: &str) -> AppResult<User> {
        self.accounts.register(email, password).await
    }

    pub async fn login(&self, email: &str, password: &str) -> AppResult<AuthTokens> {
        let user = self.accounts.authenticate(email, password).await?;
        tracing::info!(user_id = %user.id, "login succeeded");
        self.sessions.start(user.id, user.role).await
    }

    /// Rotates a refresh token. The account is re-checked on every rotation, so
    /// a lockout applied after a session started still takes effect.
    pub async fn refresh(&self, presented: &str) -> AppResult<AuthTokens> {
        let redeemed = self.sessions.redeem(presented).await?;
        let user = self.accounts.active(redeemed.user_id).await?;
        self.sessions
            .resume(user.id, user.role, redeemed.family)
            .await
    }

    pub async fn logout(&self, presented: &str) -> AppResult<()> {
        self.sessions.revoke(presented).await
    }

    pub async fn logout_everywhere(&self, user_id: Uuid) -> AppResult<()> {
        self.sessions.revoke_all(user_id).await
    }

    /// Changes a password and ends every session that was established with the
    /// old one — the two halves that must not come apart.
    pub async fn change_password(&self, user_id: Uuid, current: &str, new: &str) -> AppResult<()> {
        self.accounts.change_password(user_id, current, new).await?;
        self.sessions.revoke_all(user_id).await?;

        tracing::info!(user_id = %user_id, "password changed; all sessions revoked");
        Ok(())
    }

    pub async fn ensure_admin(&self, email: &str, password: &str) -> AppResult<AdminBootstrap> {
        self.accounts.ensure_admin(email, password).await
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::AuthService;
    use crate::{
        config::SecurityConfig,
        domain::Role,
        error::AppError,
        service::{
            AccountService, AdminBootstrap, SessionService,
            fakes::{FakeHasher, FakeTokenIssuer, InMemoryTokenRepository, InMemoryUserRepository},
        },
    };

    const PASSWORD: &str = "correct-horse-battery-staple";

    fn service(max_login_attempts: i64) -> AuthService {
        let config = SecurityConfig {
            token_format: crate::config::TokenFormat::Jwt,
            token_private_key: None,
            token_public_key: None,
            jwt_secret: "unused-by-the-fake-issuer-but-long-enough".into(),
            jwt_issuer: "test".into(),
            jwt_audience: "test".into(),
            access_token_ttl: Duration::from_secs(900),
            refresh_token_ttl: Duration::from_secs(3600),
            max_concurrent_hashes: 1,
            max_login_attempts,
            lockout_duration: Duration::from_secs(900),
            cors_allowed_origins: vec![],
            trust_proxy_headers: false,
        };

        let accounts = Arc::new(AccountService::new(
            InMemoryUserRepository::new(),
            Arc::new(FakeHasher),
            &config,
        ));
        let sessions = Arc::new(SessionService::new(
            InMemoryTokenRepository::new(),
            Arc::new(FakeTokenIssuer),
            &config,
        ));

        AuthService::new(accounts, sessions)
    }

    #[tokio::test]
    async fn a_wrong_password_is_refused_and_counted() {
        let auth = service(3);
        auth.register("user@example.com", PASSWORD).await.unwrap();

        for _ in 0..2 {
            let outcome = auth.login("user@example.com", "wrong").await;
            assert!(matches!(outcome, Err(AppError::Unauthorized)));
        }

        // Still under the threshold, so the right password works and the
        // counter resets.
        assert!(auth.login("user@example.com", PASSWORD).await.is_ok());
        assert!(auth.login("user@example.com", "wrong").await.is_err());
        assert!(auth.login("user@example.com", PASSWORD).await.is_ok());
    }

    #[tokio::test]
    async fn the_lockout_threshold_is_enforced_and_stays_invisible() {
        let auth = service(3);
        auth.register("locked@example.com", PASSWORD).await.unwrap();

        for _ in 0..3 {
            let _ = auth.login("locked@example.com", "wrong").await;
        }

        // The correct password now fails, with the same error a completely
        // unknown address produces.
        let locked = auth.login("locked@example.com", PASSWORD).await;
        let unknown = auth.login("nobody@example.com", PASSWORD).await;
        assert!(matches!(locked, Err(AppError::Unauthorized)));
        assert!(matches!(unknown, Err(AppError::Unauthorized)));
    }

    #[tokio::test]
    async fn a_locked_account_cannot_refresh_a_session_started_earlier() {
        let auth = service(2);
        auth.register("locked2@example.com", PASSWORD)
            .await
            .unwrap();
        let session = auth.login("locked2@example.com", PASSWORD).await.unwrap();

        for _ in 0..2 {
            let _ = auth.login("locked2@example.com", "wrong").await;
        }

        // The lock landed after the session existed; rotation re-checks.
        assert!(auth.refresh(&session.refresh_token).await.is_err());
    }

    #[tokio::test]
    async fn a_refresh_token_is_single_use_and_replay_revokes_the_family() {
        let auth = service(5);
        auth.register("rotate@example.com", PASSWORD).await.unwrap();
        let first = auth.login("rotate@example.com", PASSWORD).await.unwrap();

        let second = auth.refresh(&first.refresh_token).await.unwrap();
        assert_ne!(second.refresh_token, first.refresh_token);

        // Replaying the spent token fails...
        assert!(auth.refresh(&first.refresh_token).await.is_err());
        // ...and invalidates the descendant it was rotated into.
        assert!(auth.refresh(&second.refresh_token).await.is_err());
    }

    #[tokio::test]
    async fn logging_out_with_an_unknown_token_reveals_nothing() {
        let auth = service(5);
        assert!(auth.logout("never-issued").await.is_ok());
    }

    #[tokio::test]
    async fn changing_a_password_requires_the_current_one_and_ends_sessions() {
        let auth = service(5);
        let user = auth.register("rekey@example.com", PASSWORD).await.unwrap();
        let session = auth.login("rekey@example.com", PASSWORD).await.unwrap();

        assert!(
            auth.change_password(user.id, "not-the-password", "a-new-long-passphrase")
                .await
                .is_err()
        );

        auth.change_password(user.id, PASSWORD, "a-new-long-passphrase")
            .await
            .unwrap();

        assert!(auth.refresh(&session.refresh_token).await.is_err());
        assert!(auth.login("rekey@example.com", PASSWORD).await.is_err());
        assert!(
            auth.login("rekey@example.com", "a-new-long-passphrase")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_duplicate_registration_is_a_conflict() {
        let auth = service(5);
        auth.register("dupe@example.com", PASSWORD).await.unwrap();

        let outcome = auth.register("dupe@example.com", PASSWORD).await;
        assert!(matches!(outcome, Err(AppError::Conflict(_))));
    }

    #[tokio::test]
    async fn the_admin_bootstrap_promotes_without_touching_the_password() {
        let auth = service(5);
        auth.register("promote@example.com", PASSWORD)
            .await
            .unwrap();

        let outcome = auth
            .ensure_admin("promote@example.com", "a-different-bootstrap-secret")
            .await
            .unwrap();
        assert_eq!(outcome, AdminBootstrap::Promoted);

        // Re-running is a no-op, and the original password still works.
        assert_eq!(
            auth.ensure_admin("promote@example.com", "irrelevant-value")
                .await
                .unwrap(),
            AdminBootstrap::AlreadyAdmin
        );
        let tokens = auth.login("promote@example.com", PASSWORD).await.unwrap();
        assert!(tokens.access_token.ends_with(Role::Admin.as_str()));
    }
}
