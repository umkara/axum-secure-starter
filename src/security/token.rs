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
        TokenFormat::PasetoLocal => Arc::new(super::paseto::PasetoLocalCodec::new(config)),
        TokenFormat::PasetoPublic => Arc::new(super::paseto::PasetoPublicCodec::new(config)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Every format the factory can build. A new arm in `issuer_for` without a
    /// new entry here is a format nothing tests.
    const FORMATS: [TokenFormat; 3] = [
        TokenFormat::Jwt,
        TokenFormat::PasetoLocal,
        TokenFormat::PasetoPublic,
    ];

    /// A configuration carrying whatever key material the format needs: the
    /// shared secret for the symmetric formats, the supplied pair for the
    /// asymmetric one. Passing the pair in rather than generating it here is
    /// what lets a test hold the key material still and vary only the format.
    fn config_for(format: TokenFormat, secret: &str, keys: &(Vec<u8>, Vec<u8>)) -> SecurityConfig {
        SecurityConfig {
            token_format: format,
            token_private_key: Some(keys.0.clone()),
            token_public_key: Some(keys.1.clone()),
            ..config(secret)
        }
    }

    fn key_pair() -> (Vec<u8>, Vec<u8>) {
        crate::security::paseto::generate_key_pair().unwrap()
    }

    fn config(secret: &str) -> SecurityConfig {
        SecurityConfig {
            token_format: TokenFormat::Jwt,
            token_private_key: None,
            token_public_key: None,
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
    fn every_format_round_trips_through_the_trait() {
        let keys = key_pair();

        for format in FORMATS {
            let issuer = issuer_for(&config_for(
                format,
                "a-secret-long-enough-for-the-validator",
                &keys,
            ));
            let user = Uuid::new_v4();

            let token = issuer.issue(user, Role::User).unwrap();
            let identity = issuer.verify(&token).unwrap();

            assert_eq!(identity.user_id, user, "{format}");
            assert_eq!(identity.role, Role::User, "{format}");
            assert_eq!(issuer.ttl_seconds(), 900, "{format}");
        }
    }

    #[test]
    fn no_format_accepts_a_token_built_from_another_key() {
        for format in FORMATS {
            // Different key material on both sides, whichever kind the format
            // uses: a different shared secret, or a different key pair.
            let ours = issuer_for(&config_for(
                format,
                "a-secret-long-enough-for-the-validator",
                &key_pair(),
            ));
            let theirs = issuer_for(&config_for(
                format,
                "a-different-secret-of-sufficient-length",
                &key_pair(),
            ));

            let token = theirs.issue(Uuid::new_v4(), Role::Admin).unwrap();

            // The seam must not become a place where verification is skipped:
            // an issuer built here still checks what its format promises.
            assert!(ours.verify(&token).is_err(), "{format}");
        }
    }

    #[test]
    fn no_format_accepts_a_token_written_in_another_one() {
        let secret = "a-secret-long-enough-for-the-validator";
        let keys = key_pair();

        for ours in FORMATS {
            let issuer = issuer_for(&config_for(ours, secret, &keys));

            for theirs in FORMATS.into_iter().filter(|other| *other != ours) {
                // Same key material, same issuer, same audience: only the
                // format differs. Switching APP_TOKEN_FORMAT must invalidate
                // the tokens already in circulation rather than half-accept
                // them.
                let foreign = issuer_for(&config_for(theirs, secret, &keys))
                    .issue(Uuid::new_v4(), Role::Admin)
                    .unwrap();

                assert!(
                    issuer.verify(&foreign).is_err(),
                    "a {theirs} token authenticated against {ours}"
                );
            }
        }
    }
}
