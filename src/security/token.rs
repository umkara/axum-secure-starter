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

use async_trait::async_trait;
use uuid::Uuid;

use crate::{
    config::SecurityConfig, config::TokenFormat, domain::Role, error::AppResult,
    repository::AccessTokenRepository,
};

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
///
/// The methods are async because one implementation reaches storage to answer
/// them. The stateless formats do not await anything, and the cost of the
/// indirection is not measurable next to the signature check they do instead.
#[async_trait]
pub trait TokenIssuer: Send + Sync + 'static {
    /// `session` is the refresh-token family this access token belongs to. A
    /// stateless format has no use for it; a stored one needs it to end a
    /// single device's session without touching the user's others.
    async fn issue(&self, user_id: Uuid, role: Role, session: Uuid) -> AppResult<String>;
    async fn verify(&self, token: &str) -> AppResult<TokenIdentity>;
    /// Lifetime advertised to clients as `expires_in`.
    fn ttl_seconds(&self) -> i64;

    /// Ends one session's access tokens, on logout.
    ///
    /// Does nothing by default, and that default is the honest answer for a
    /// stateless format: there is no record to remove, and the token stays
    /// valid until it expires. Choosing such a format *is* choosing that.
    async fn revoke_session(&self, session: Uuid) -> AppResult<()> {
        let _ = session;
        Ok(())
    }

    /// Ends every access token a user holds: password change, admin action,
    /// incident. Does nothing by default, for the same reason.
    async fn revoke_all_for_user(&self, user_id: Uuid) -> AppResult<()> {
        let _ = user_id;
        Ok(())
    }
}

/// Builds the issuer the configuration asks for.
///
/// Infallible by the time it runs: the format was parsed and validated in
/// [`crate::config`], which is where an unusable value stops the server.
///
/// `access_tokens` is handed in whether or not the chosen format uses it. The
/// alternative — building the store only for the format that needs one — would
/// put a conditional in the wiring, and the wiring is the one place worth
/// keeping boring.
pub fn issuer_for(
    config: &SecurityConfig,
    access_tokens: Arc<dyn AccessTokenRepository>,
) -> Arc<dyn TokenIssuer> {
    match config.token_format {
        TokenFormat::Jwt => Arc::new(super::jwt::JwtCodec::new(config)),
        TokenFormat::PasetoLocal => Arc::new(super::paseto::PasetoLocalCodec::new(config)),
        TokenFormat::PasetoPublic => Arc::new(super::paseto::PasetoPublicCodec::new(config)),
        TokenFormat::Opaque => Arc::new(super::opaque::OpaqueCodec::new(config, access_tokens)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Every format the factory can build. A new arm in `issuer_for` without a
    /// new entry here is a format nothing tests.
    const FORMATS: [TokenFormat; 4] = [
        TokenFormat::Jwt,
        TokenFormat::PasetoLocal,
        TokenFormat::PasetoPublic,
        TokenFormat::Opaque,
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

    /// Every format is built through the same factory, so each one is handed a
    /// store — the three stateless formats simply never touch it.
    fn issuer(config: &SecurityConfig) -> Arc<dyn TokenIssuer> {
        issuer_for(
            config,
            crate::service::fakes::InMemoryAccessTokenRepository::new(),
        )
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

    #[tokio::test]
    async fn every_format_round_trips_through_the_trait() {
        let keys = key_pair();

        for format in FORMATS {
            let issuer = issuer(&config_for(
                format,
                "a-secret-long-enough-for-the-validator",
                &keys,
            ));
            let user = Uuid::new_v4();

            let token = issuer
                .issue(user, Role::User, Uuid::new_v4())
                .await
                .unwrap();
            let identity = issuer.verify(&token).await.unwrap();

            assert_eq!(identity.user_id, user, "{format}");
            assert_eq!(identity.role, Role::User, "{format}");
            assert_eq!(issuer.ttl_seconds(), 900, "{format}");
        }
    }

    #[tokio::test]
    async fn no_format_accepts_a_token_built_from_another_key() {
        // The opaque format is excluded on purpose: its tokens are references
        // rather than anything derived from a key, and two issuers with
        // separate stores is the case `no_format_accepts_a_token_written_in_another_one`
        // already covers.
        for format in FORMATS.into_iter().filter(|f| *f != TokenFormat::Opaque) {
            // Different key material on both sides, whichever kind the format
            // uses: a different shared secret, or a different key pair.
            let ours = issuer(&config_for(
                format,
                "a-secret-long-enough-for-the-validator",
                &key_pair(),
            ));
            let theirs = issuer(&config_for(
                format,
                "a-different-secret-of-sufficient-length",
                &key_pair(),
            ));

            let token = theirs
                .issue(Uuid::new_v4(), Role::Admin, Uuid::new_v4())
                .await
                .unwrap();

            // The seam must not become a place where verification is skipped:
            // an issuer built here still checks what its format promises.
            assert!(ours.verify(&token).await.is_err(), "{format}");
        }
    }

    #[tokio::test]
    async fn no_format_accepts_a_token_written_in_another_one() {
        let secret = "a-secret-long-enough-for-the-validator";
        let keys = key_pair();

        for ours in FORMATS {
            let ours_issuer = issuer(&config_for(ours, secret, &keys));

            for theirs in FORMATS.into_iter().filter(|other| *other != ours) {
                // Same key material, same issuer, same audience: only the
                // format differs. Switching APP_TOKEN_FORMAT must invalidate
                // the tokens already in circulation rather than half-accept
                // them.
                let foreign = issuer(&config_for(theirs, secret, &keys))
                    .issue(Uuid::new_v4(), Role::Admin, Uuid::new_v4())
                    .await
                    .unwrap();

                assert!(
                    ours_issuer.verify(&foreign).await.is_err(),
                    "a {theirs} token authenticated against {ours}"
                );
            }
        }
    }
}
