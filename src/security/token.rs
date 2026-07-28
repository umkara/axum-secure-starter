//! What an access token is, independent of how it is written.
//!
//! The format an access token happens to use is a deployment decision, not an
//! application one. Everything above this module — the extractor, the session
//! service, the handlers — deals in [`TokenIssuer`] and [`TokenIdentity`] and
//! never learns whether the string on the wire is a JWT, a PASETO, or a
//! reference to a row in a table.
//!
//! [`issuer_for`] is the one place that maps a configured
//! [`TokenFormat`](crate::config::TokenFormat) to an implementation. Adding a
//! format means adding a module beside this one and an arm to that match; it
//! does not mean touching anything that *uses* tokens.

use std::sync::Arc;

use uuid::Uuid;

use crate::{config::SecurityConfig, config::TokenFormat, domain::Role, error::AppResult};

/// A verified caller, recovered from a token.
///
/// Deliberately small. Whatever a format can carry, this is what the
/// application is entitled to act on — anything richer would push
/// authorisation decisions into the token format, where they cannot be
/// reviewed alongside the rules they affect.
#[derive(Debug, Clone)]
pub struct TokenIdentity {
    pub user_id: Uuid,
    pub role: Role,
}

/// What the rest of the application needs from access tokens.
///
/// Depending on this rather than on a concrete codec keeps the services free of
/// any particular token format, and lets a test substitute an issuer that does
/// not sign anything.
///
/// `verify` returns [`AppError::Unauthorized`](crate::error::AppError) for every
/// kind of failure — expired, forged, wrong audience, malformed. A client
/// learns that its token was refused and nothing about why.
pub trait TokenIssuer: Send + Sync + 'static {
    fn issue(&self, user_id: Uuid, role: Role) -> AppResult<String>;
    fn verify(&self, token: &str) -> AppResult<TokenIdentity>;
    /// Lifetime advertised to clients as `expires_in`.
    fn ttl_seconds(&self) -> i64;
}

/// Builds the issuer the configuration asks for.
///
/// Infallible by the time it runs: the format was parsed and validated in
/// [`crate::config`], which is where an unusable value stops the server.
pub fn issuer_for(config: &SecurityConfig) -> Arc<dyn TokenIssuer> {
    match config.token_format {
        TokenFormat::Jwt => Arc::new(super::jwt::JwtCodec::new(config)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn config(secret: &str) -> SecurityConfig {
        SecurityConfig {
            token_format: TokenFormat::Jwt,
            jwt_secret: secret.into(),
            jwt_issuer: "bastion-tests".into(),
            jwt_audience: "bastion-tests-api".into(),
            access_token_ttl: Duration::from_secs(900),
            refresh_token_ttl: Duration::from_secs(3600),
            max_concurrent_hashes: 1,
            max_login_attempts: 5,
            lockout_duration: Duration::from_secs(900),
            cors_allowed_origins: Vec::new(),
            trust_proxy_headers: false,
        }
    }

    #[test]
    fn the_configured_format_round_trips_through_the_trait() {
        let issuer = issuer_for(&config("a-secret-long-enough-for-the-validator"));
        let user = Uuid::new_v4();

        let token = issuer.issue(user, Role::User).unwrap();
        let identity = issuer.verify(&token).unwrap();

        assert_eq!(identity.user_id, user);
        assert_eq!(identity.role, Role::User);
        assert_eq!(issuer.ttl_seconds(), 900);
    }

    #[test]
    fn an_issuer_built_from_another_key_refuses_the_token() {
        let ours = issuer_for(&config("a-secret-long-enough-for-the-validator"));
        let theirs = issuer_for(&config("a-different-secret-of-sufficient-length"));

        let token = theirs.issue(Uuid::new_v4(), Role::Admin).unwrap();

        // The seam must not become a place where verification is skipped: an
        // issuer built here still checks what its format promises.
        assert!(ours.verify(&token).is_err());
    }
}
