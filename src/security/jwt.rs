//! Access tokens as HS256 JWTs.
//!
//! One implementation of [`TokenIssuer`], selected by
//! `APP_TOKEN_FORMAT=jwt`, which is the default. The trait and the identity it
//! produces live in [`super::token`]; nothing outside this file needs to know a
//! JWT is what went over the wire.
//!
//! Access tokens are short-lived and stateless. Long-lived sessions are carried
//! by opaque refresh tokens (see `service::auth_service`), never by long JWT
//! expiries — that way a compromised access token expires on its own, and a
//! compromised refresh token can be revoked server-side.

use std::time::Duration;

use anyhow::anyhow;
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use async_trait::async_trait;

use crate::{
    config::SecurityConfig,
    domain::Role,
    error::{AppError, AppResult},
    security::token::{TokenIdentity, TokenIssuer},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject: the user id.
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nbf: i64,
    /// Unique token id, useful for correlating logs and for future revocation.
    pub jti: String,
    pub role: String,
}

/// Verifies the signature *and* the registered claims, then hands back a typed
/// identity. Anything that fails validation collapses to `Unauthorized` so the
/// client learns nothing about *why* the token was rejected.
pub(crate) struct JwtCodec {
    encoding: EncodingKey,
    decoding: DecodingKey,
    validation: Validation,
    issuer: String,
    audience: String,
    ttl: Duration,
}

impl JwtCodec {
    pub fn new(config: &SecurityConfig) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[config.jwt_issuer.as_str()]);
        validation.set_audience(&[config.jwt_audience.as_str()]);
        validation.set_required_spec_claims(&["exp", "nbf", "iss", "aud", "sub"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.validate_aud = true;
        // Only HS256 is accepted. Leaving the list open would allow an attacker
        // to pick a weaker algorithm than the one we sign with.
        validation.algorithms = vec![Algorithm::HS256];
        // Small allowance for clock drift between nodes.
        validation.leeway = 5;

        Self {
            encoding: EncodingKey::from_secret(config.jwt_secret.as_bytes()),
            decoding: DecodingKey::from_secret(config.jwt_secret.as_bytes()),
            validation,
            issuer: config.jwt_issuer.clone(),
            audience: config.jwt_audience.clone(),
            ttl: config.access_token_ttl,
        }
    }
}

#[async_trait]
impl TokenIssuer for JwtCodec {
    fn ttl_seconds(&self) -> i64 {
        self.ttl.as_secs() as i64
    }

    async fn issue(&self, user_id: Uuid, role: Role, session: Uuid) -> AppResult<String> {
        // A JWT carries no session reference: nothing can be revoked with it,
        // so recording which session it belongs to would only be decoration.
        let _ = session;
        let now = Utc::now().timestamp();
        let claims = Claims {
            sub: user_id.to_string(),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            iat: now,
            nbf: now,
            exp: now + self.ttl_seconds(),
            jti: Uuid::new_v4().to_string(),
            role: role.as_str().to_string(),
        };

        encode(&Header::new(Algorithm::HS256), &claims, &self.encoding)
            .map_err(|e| AppError::Internal(anyhow!("failed to sign access token: {e}")))
    }

    async fn verify(&self, token: &str) -> AppResult<TokenIdentity> {
        let data = decode::<Claims>(token, &self.decoding, &self.validation)
            .map_err(|_| AppError::Unauthorized)?;

        let user_id = Uuid::parse_str(&data.claims.sub).map_err(|_| AppError::Unauthorized)?;
        let role: Role = data
            .claims
            .role
            .parse()
            .map_err(|_| AppError::Unauthorized)?;

        Ok(TokenIdentity { user_id, role })
    }
}
