//! Access tokens as references to server-side state.
//!
//! One implementation of [`TokenIssuer`], selected by `APP_TOKEN_FORMAT=opaque`.
//!
//! # What this buys, and what it costs
//!
//! Every other format here is stateless: the identity travels inside the token,
//! verification is a signature check, and nothing the server does afterwards can
//! take the token back. A password change, a sacking, a stolen laptop — the
//! token keeps working until it expires. Fifteen minutes is a deliberate cap on
//! that window, but it is a window.
//!
//! This format closes it. The token is 32 bytes of CSPRNG output that means
//! nothing on its own; the identity lives in a row, and deleting the row ends
//! the session on the very next request. The cost is one indexed lookup per
//! authenticated request, and a server that can no longer verify a token
//! without its database.
//!
//! # No cache
//!
//! Caching verified tokens would recover most of that cost, and would silently
//! reintroduce exactly the window this format exists to close: a revocation
//! would take effect when the cache entry expired rather than immediately. A
//! cache here would have to be invalidated on revocation to be honest, which is
//! most of the complexity of not having one. If the lookup is too expensive for
//! your traffic, the stateless formats are the answer, not a stale cache.
//!
//! # The token is stored hashed
//!
//! Only a SHA-256 digest goes in the table, exactly as for refresh tokens, so a
//! dump of the database cannot be replayed against the API.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use crate::{
    config::SecurityConfig,
    domain::Role,
    error::{AppError, AppResult},
    repository::{AccessTokenRepository, access_token_repository::NewAccessToken},
    security::{
        opaque_token,
        token::{TokenIdentity, TokenIssuer},
    },
};

pub(crate) struct OpaqueCodec {
    store: Arc<dyn AccessTokenRepository>,
    ttl: Duration,
}

impl OpaqueCodec {
    pub fn new(config: &SecurityConfig, store: Arc<dyn AccessTokenRepository>) -> Self {
        Self {
            store,
            ttl: config.access_token_ttl,
        }
    }
}

#[async_trait]
impl TokenIssuer for OpaqueCodec {
    fn ttl_seconds(&self) -> i64 {
        self.ttl.as_secs() as i64
    }

    async fn issue(&self, user_id: Uuid, role: Role, session: Uuid) -> AppResult<String> {
        let token = opaque_token::generate();

        let expires_at = Utc::now()
            + chrono::Duration::from_std(self.ttl).map_err(|error| {
                AppError::Internal(anyhow::anyhow!("access ttl out of range: {error}"))
            })?;

        self.store
            .insert(NewAccessToken {
                id: Uuid::new_v4(),
                user_id,
                token_hash: token.digest,
                session,
                role: role.as_str().to_owned(),
                expires_at,
            })
            .await?;

        // The secret is returned once and never stored, so this is the only
        // moment it exists outside the client.
        Ok(token.secret)
    }

    async fn verify(&self, token: &str) -> AppResult<TokenIdentity> {
        let digest = opaque_token::digest_of(token);

        let Some(record) = self.store.find_by_hash(&digest).await? else {
            return Err(AppError::Unauthorized);
        };

        // Constant-time re-check of the value we looked up by, so the lookup
        // path itself cannot be used as a comparison oracle. The refresh path
        // does the same thing for the same reason.
        if !opaque_token::digests_match(&record.token_hash, &digest) {
            return Err(AppError::Unauthorized);
        }

        // Expiry is enforced here rather than left to the sweep: a row the
        // janitor has not reached yet is still an expired token.
        if record.expires_at <= Utc::now() {
            return Err(AppError::Unauthorized);
        }

        // The role is read from the row rather than from anything the client
        // sent, so a role change takes effect on the next request too.
        let role: Role = record.role.parse().map_err(|_| AppError::Unauthorized)?;

        Ok(TokenIdentity {
            user_id: record.user_id,
            role,
        })
    }

    async fn revoke_session(&self, session: Uuid) -> AppResult<()> {
        self.store.delete_by_session(session).await?;
        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: Uuid) -> AppResult<()> {
        self.store.delete_all_for_user(user_id).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::TokenFormat, service::fakes::InMemoryAccessTokenRepository};

    fn config(ttl: Duration) -> SecurityConfig {
        SecurityConfig {
            token_format: TokenFormat::Opaque,
            token_private_key: None,
            token_public_key: None,
            jwt_secret: "unused-by-this-format-but-long-enough".into(),
            jwt_issuer: "bastion-tests".into(),
            jwt_audience: "bastion-tests-api".into(),
            access_token_ttl: ttl,
            refresh_token_ttl: Duration::from_secs(3600),
            max_concurrent_hashes: 1,
            max_login_attempts: 5,
            lockout_duration: Duration::from_secs(900),
            cors_allowed_origins: Vec::new(),
            trust_proxy_headers: false,
        }
    }

    fn codec() -> (OpaqueCodec, Arc<InMemoryAccessTokenRepository>) {
        let store = InMemoryAccessTokenRepository::new();
        (
            OpaqueCodec::new(&config(Duration::from_secs(900)), store.clone()),
            store,
        )
    }

    #[tokio::test]
    async fn a_token_round_trips_and_carries_nothing_by_itself() {
        let (codec, _store) = codec();
        let user = Uuid::new_v4();

        let token = codec
            .issue(user, Role::Admin, Uuid::new_v4())
            .await
            .unwrap();

        // The token is a reference, not a container: nothing about the identity
        // is recoverable from the string.
        assert!(!token.contains(&user.to_string()));
        assert!(!token.contains("admin"));

        let identity = codec.verify(&token).await.unwrap();
        assert_eq!(identity.user_id, user);
        assert_eq!(identity.role, Role::Admin);
    }

    #[tokio::test]
    async fn the_secret_is_never_what_is_stored() {
        let (codec, store) = codec();
        let token = codec
            .issue(Uuid::new_v4(), Role::User, Uuid::new_v4())
            .await
            .unwrap();

        // A dump of the table must not be replayable against the API.
        assert!(
            store.find_by_hash(&token).await.unwrap().is_none(),
            "the token itself must not be a key into storage"
        );
        assert!(
            store
                .find_by_hash(&opaque_token::digest_of(&token))
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn revoking_a_session_ends_that_session_and_no_other() {
        let (codec, store) = codec();
        let user = Uuid::new_v4();
        let phone = Uuid::new_v4();
        let laptop = Uuid::new_v4();

        let on_phone = codec.issue(user, Role::User, phone).await.unwrap();
        let on_laptop = codec.issue(user, Role::User, laptop).await.unwrap();

        codec.revoke_session(phone).await.unwrap();

        // Immediately, not at expiry. This is the whole reason the format
        // exists.
        assert!(codec.verify(&on_phone).await.is_err());
        assert!(
            codec.verify(&on_laptop).await.is_ok(),
            "logging out one device must not end the others"
        );
        assert_eq!(store.live(), 1, "the revoked row is gone, not flagged");
    }

    #[tokio::test]
    async fn revoking_a_user_ends_every_session_they_hold() {
        let (codec, _store) = codec();
        let user = Uuid::new_v4();
        let other = Uuid::new_v4();

        let first = codec.issue(user, Role::User, Uuid::new_v4()).await.unwrap();
        let second = codec.issue(user, Role::User, Uuid::new_v4()).await.unwrap();
        let bystander = codec
            .issue(other, Role::User, Uuid::new_v4())
            .await
            .unwrap();

        codec.revoke_all_for_user(user).await.unwrap();

        assert!(codec.verify(&first).await.is_err());
        assert!(codec.verify(&second).await.is_err());
        assert!(codec.verify(&bystander).await.is_ok());
    }

    #[tokio::test]
    async fn an_expired_row_does_not_authenticate_even_before_it_is_swept() {
        let store = InMemoryAccessTokenRepository::new();
        let codec = OpaqueCodec::new(&config(Duration::from_secs(0)), store.clone());

        let token = codec
            .issue(Uuid::new_v4(), Role::User, Uuid::new_v4())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(1100)).await;

        // The row is still there — the janitor sweeps on its own schedule — so
        // expiry has to be enforced at verification or it is not enforced.
        assert_eq!(store.live(), 1);
        assert!(codec.verify(&token).await.is_err());
    }

    #[tokio::test]
    async fn an_unknown_token_is_refused() {
        let (codec, _store) = codec();

        for token in ["", "not-a-token", &opaque_token::generate().secret] {
            assert!(
                codec.verify(token).await.is_err(),
                "`{token}` authenticated"
            );
        }
    }
}
