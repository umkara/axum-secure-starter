//! Session lifecycle: issuing, rotating, and revoking.
//!
//! Nothing here knows what a password is or how an account proves itself. It is
//! handed an identity that someone else has already established, and it decides
//! what a session made from that identity may do.
//!
//! Threat model owned by this file: refresh-token theft. Tokens are single-use
//! and rotate on every exchange, and redeeming a spent one revokes the whole
//! family, so a stolen copy stops working the moment the real client refreshes.

use std::{sync::Arc, time::Duration};

use chrono::Utc;
use uuid::Uuid;

use crate::{
    config::SecurityConfig,
    domain::Role,
    error::{AppError, AppResult},
    repository::{TokenRepository, token_repository::NewRefreshToken},
    security::{TokenIssuer, opaque_token},
};

/// What a successful authentication hands back to the caller.
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in_seconds: i64,
}

/// A refresh token that has just been spent. The family travels with it so the
/// replacement stays in the same chain.
pub struct RedeemedSession {
    pub user_id: Uuid,
    pub family: Uuid,
}

pub struct SessionService {
    tokens: Arc<dyn TokenRepository>,
    issuer: Arc<dyn TokenIssuer>,
    refresh_ttl: Duration,
}

impl SessionService {
    pub fn new(
        tokens: Arc<dyn TokenRepository>,
        issuer: Arc<dyn TokenIssuer>,
        config: &SecurityConfig,
    ) -> Self {
        Self {
            tokens,
            issuer,
            refresh_ttl: config.refresh_token_ttl,
        }
    }

    /// Begins a new session — a fresh token family.
    pub async fn start(&self, user_id: Uuid, role: Role) -> AppResult<AuthTokens> {
        self.issue(user_id, role, Uuid::new_v4()).await
    }

    /// Spends a refresh token, returning the identity it carried.
    ///
    /// Replay is treated as compromise: a token presented twice revokes every
    /// token descended from the same login, which ends the attacker's session
    /// and the victim's together. That is the intended trade — a forced
    /// re-login beats a silently shared account.
    pub async fn redeem(&self, presented: &str) -> AppResult<RedeemedSession> {
        let digest = opaque_token::digest_of(presented);
        let now = Utc::now();

        let Some(record) = self.tokens.find_by_hash(&digest).await? else {
            return Err(AppError::Unauthorized);
        };

        // Constant-time re-check of the value we looked up by, so the lookup
        // path itself cannot be used as a comparison oracle.
        if !opaque_token::digests_match(&record.token_hash, &digest) {
            return Err(AppError::Unauthorized);
        }

        if !record.is_usable_at(now) {
            if record.used_at.is_some() {
                tracing::warn!(
                    user_id = %record.user_id,
                    family = %record.family,
                    "refresh token reuse detected; revoking token family"
                );
                self.tokens.revoke_family(record.family).await?;
            }
            return Err(AppError::Unauthorized);
        }

        if !self.tokens.mark_used(record.id).await? {
            // Lost a race with a concurrent refresh; treat as reuse.
            self.tokens.revoke_family(record.family).await?;
            return Err(AppError::Unauthorized);
        }

        Ok(RedeemedSession {
            user_id: record.user_id,
            family: record.family,
        })
    }

    /// Continues an existing chain after a successful redemption.
    pub async fn resume(&self, user_id: Uuid, role: Role, family: Uuid) -> AppResult<AuthTokens> {
        self.issue(user_id, role, family).await
    }

    /// Ends one session. An unknown token reports success, so the endpoint
    /// cannot be used to test whether a token is valid.
    pub async fn revoke(&self, presented: &str) -> AppResult<()> {
        let digest = opaque_token::digest_of(presented);
        if let Some(record) = self.tokens.find_by_hash(&digest).await? {
            self.tokens.revoke_family(record.family).await?;
            // A stateless access token outlives this call by up to its TTL;
            // a stored one does not. Which of those you get is the format
            // decision, made once in configuration.
            self.issuer.revoke_session(record.family).await?;
        }
        Ok(())
    }

    /// Ends every session for a user: password change, admin action, incident.
    pub async fn revoke_all(&self, user_id: Uuid) -> AppResult<()> {
        self.tokens.revoke_all_for_user(user_id).await?;
        self.issuer.revoke_all_for_user(user_id).await?;
        Ok(())
    }

    async fn issue(&self, user_id: Uuid, role: Role, family: Uuid) -> AppResult<AuthTokens> {
        // The family travels into the access token as well, so a format that
        // stores its tokens can end this device's session and no other.
        let access_token = self.issuer.issue(user_id, role, family).await?;
        let refresh = opaque_token::generate();

        let expires_at = Utc::now()
            + chrono::Duration::from_std(self.refresh_ttl).map_err(|e| {
                AppError::Internal(anyhow::anyhow!("refresh ttl out of range: {e}"))
            })?;

        self.tokens
            .insert(NewRefreshToken {
                id: Uuid::new_v4(),
                user_id,
                token_hash: refresh.digest,
                family,
                expires_at,
            })
            .await?;

        Ok(AuthTokens {
            access_token,
            refresh_token: refresh.secret,
            expires_in_seconds: self.issuer.ttl_seconds(),
        })
    }
}
