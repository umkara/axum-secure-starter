//! Access tokens as PASETO v4.local.
//!
//! One implementation of [`TokenIssuer`], selected by
//! `APP_TOKEN_FORMAT=paseto-local`.
//!
//! # Why this format exists alongside the JWT one
//!
//! A JWT names its own algorithm in a header the recipient has to be careful
//! not to trust. That is a footgun with a long history — `alg=none`, RS256
//! verified as HS256 against the public key — and `security::jwt` closes it by
//! pinning the accepted algorithm to one value. PASETO removes the choice
//! instead of guarding it: a `v4.local.` token is XChaCha20-Poly1305 with a
//! BLAKE2b tag, by definition of the version, and there is no field an attacker
//! can edit to negotiate anything weaker.
//!
//! `local` also means the payload is *encrypted*, not merely signed. A JWT's
//! claims are base64, readable by anything that handles the token; these are
//! not. That matters less for a user id and a role than it would for richer
//! claims, but it is the direction to be wrong in.
//!
//! # The key
//!
//! v4.local needs exactly 32 bytes, and `APP_JWT_SECRET` is an arbitrary-length
//! string, so the key is derived: `SHA-256(domain || secret)`. The domain string
//! makes this key unusable as any other, so the same secret feeding two formats
//! never produces the same key twice.
//!
//! # Clock skew
//!
//! `pasetors` validates `exp`, `nbf` and `iat` exactly, with no leeway — where
//! the JWT codec allows five seconds. Tokens are minted and verified by the same
//! process here, so there is no skew to allow for. Split issuing from verifying
//! across hosts and that becomes a real consideration.

use std::time::Duration;

use pasetors::{
    Local, Public,
    claims::{Claims, ClaimsValidationRules},
    keys::{AsymmetricKeyPair, AsymmetricPublicKey, AsymmetricSecretKey, Generate, SymmetricKey},
    local, public,
    token::UntrustedToken,
    version4::V4,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    config::SecurityConfig,
    domain::Role,
    error::{AppError, AppResult},
    security::token::{TokenIdentity, TokenIssuer},
};

/// Domain separation for the derived key. Changing this string invalidates
/// every token in circulation, which is the point: it is what keeps a key
/// derived here from being the key derived anywhere else.
const KEY_DOMAIN: &[u8] = b"bastion:paseto:v4.local:key:v1";

/// The role travels as a custom claim. PASETO reserves the registered names
/// and leaves the rest alone, so this cannot collide with one of them.
const ROLE_CLAIM: &str = "role";

pub(crate) struct PasetoLocalCodec {
    key: SymmetricKey<V4>,
    issuer: String,
    audience: String,
    ttl: Duration,
}

impl PasetoLocalCodec {
    pub fn new(config: &SecurityConfig) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(KEY_DOMAIN);
        hasher.update(config.jwt_secret.as_bytes());
        let derived = hasher.finalize();

        // A SHA-256 digest is 32 bytes, which is exactly what v4.local wants,
        // so this cannot fail for any secret the configuration accepted.
        let key = SymmetricKey::<V4>::from(derived.as_slice())
            .expect("a 32-byte digest is a valid v4.local key");

        Self {
            key,
            issuer: config.jwt_issuer.clone(),
            audience: config.jwt_audience.clone(),
            ttl: config.access_token_ttl,
        }
    }

    /// Issuer and audience are checked on every token, exactly as the JWT codec
    /// checks them: a token minted for another service must not be accepted
    /// here just because it decrypts.
    fn validation_rules(&self) -> ClaimsValidationRules {
        let mut rules = ClaimsValidationRules::new();
        rules.validate_issuer_with(&self.issuer);
        rules.validate_audience_with(&self.audience);
        rules
    }
}

impl TokenIssuer for PasetoLocalCodec {
    fn ttl_seconds(&self) -> i64 {
        self.ttl.as_secs() as i64
    }

    fn issue(&self, user_id: Uuid, role: Role) -> AppResult<String> {
        let claims = claims_for(user_id, role, &self.issuer, &self.audience, self.ttl)?;
        local::encrypt(&self.key, &claims, None, None).map_err(internal)
    }

    fn verify(&self, token: &str) -> AppResult<TokenIdentity> {
        // Every failure below collapses to `Unauthorized`. A client learns that
        // its token was refused and never which step refused it — the header
        // was wrong, the tag did not check out, the audience belonged to
        // somebody else — because that difference is a decryption oracle.
        let untrusted =
            UntrustedToken::<Local, V4>::try_from(token).map_err(|_| AppError::Unauthorized)?;

        let trusted = local::decrypt(&self.key, &untrusted, &self.validation_rules(), None, None)
            .map_err(|_| AppError::Unauthorized)?;

        identity_from(trusted.payload_claims().ok_or(AppError::Unauthorized)?)
    }
}

/// Access tokens as PASETO v4.public: Ed25519 signatures.
///
/// The difference from [`PasetoLocalCodec`] is who can do what. A shared secret
/// lets every holder both mint and verify, so a resource server that only needs
/// to check tokens has to be trusted to issue them too. A key pair splits that:
/// the private key stays here, the public key can be handed to anything that
/// verifies, and a leak of the verifying half forges nothing.
///
/// The payload is signed, not encrypted — claims are readable, as in a JWT.
/// That is inherent to the purpose: a verifier that cannot read the token
/// cannot act on it.
pub(crate) struct PasetoPublicCodec {
    signing: AsymmetricSecretKey<V4>,
    verifying: AsymmetricPublicKey<V4>,
    issuer: String,
    audience: String,
    ttl: Duration,
}

impl PasetoPublicCodec {
    /// # Panics
    ///
    /// If the key pair is absent or the wrong length. Neither is reachable:
    /// [`crate::config`] refuses to produce a configuration naming this format
    /// without a decoded, length-checked pair, and that refusal is what stops
    /// the server.
    pub fn new(config: &SecurityConfig) -> Self {
        let private = config
            .token_private_key
            .as_deref()
            .expect("paseto-public requires a private key; config validates this");
        let public = config
            .token_public_key
            .as_deref()
            .expect("paseto-public requires a public key; config validates this");

        Self {
            signing: AsymmetricSecretKey::<V4>::from(private)
                .expect("a 64-byte key is a valid v4.public signing key"),
            verifying: AsymmetricPublicKey::<V4>::from(public)
                .expect("a 32-byte key is a valid v4.public verifying key"),
            issuer: config.jwt_issuer.clone(),
            audience: config.jwt_audience.clone(),
            ttl: config.access_token_ttl,
        }
    }

    fn validation_rules(&self) -> ClaimsValidationRules {
        let mut rules = ClaimsValidationRules::new();
        rules.validate_issuer_with(&self.issuer);
        rules.validate_audience_with(&self.audience);
        rules
    }
}

impl TokenIssuer for PasetoPublicCodec {
    fn ttl_seconds(&self) -> i64 {
        self.ttl.as_secs() as i64
    }

    fn issue(&self, user_id: Uuid, role: Role) -> AppResult<String> {
        let claims = claims_for(user_id, role, &self.issuer, &self.audience, self.ttl)?;
        public::sign(&self.signing, &claims, None, None).map_err(internal)
    }

    fn verify(&self, token: &str) -> AppResult<TokenIdentity> {
        let untrusted =
            UntrustedToken::<Public, V4>::try_from(token).map_err(|_| AppError::Unauthorized)?;

        let trusted = public::verify(
            &self.verifying,
            &untrusted,
            &self.validation_rules(),
            None,
            None,
        )
        .map_err(|_| AppError::Unauthorized)?;

        identity_from(trusted.payload_claims().ok_or(AppError::Unauthorized)?)
    }
}

/// A fresh Ed25519 key pair as raw bytes: the 64-byte private key and the
/// 32-byte public one.
///
/// Exists because the alternative is telling operators to extract a raw seed
/// from a PEM file, which is the kind of instruction that gets a public key
/// pasted into the private slot.
pub fn generate_key_pair() -> AppResult<(Vec<u8>, Vec<u8>)> {
    let pair = AsymmetricKeyPair::<V4>::generate().map_err(internal)?;
    Ok((
        pair.secret.as_bytes().to_vec(),
        pair.public.as_bytes().to_vec(),
    ))
}

/// The claims both PASETO codecs put in a token. One function so the two cannot
/// drift into carrying different things.
fn claims_for(
    user_id: Uuid,
    role: Role,
    issuer: &str,
    audience: &str,
    ttl: Duration,
) -> AppResult<Claims> {
    // Sets `iat` and `nbf` to now and `exp` to now + ttl.
    let mut claims = Claims::new_expires_in(&ttl).map_err(internal)?;
    claims.subject(&user_id.to_string()).map_err(internal)?;
    claims.issuer(issuer).map_err(internal)?;
    claims.audience(audience).map_err(internal)?;
    claims
        .token_identifier(&Uuid::new_v4().to_string())
        .map_err(internal)?;
    claims
        .add_additional(ROLE_CLAIM, role.as_str())
        .map_err(internal)?;
    Ok(claims)
}

/// Reads the identity out of claims that have already been validated.
fn identity_from(claims: &Claims) -> AppResult<TokenIdentity> {
    let user_id = claims
        .get_claim("sub")
        .and_then(|value| value.as_str())
        .ok_or(AppError::Unauthorized)?
        .parse::<Uuid>()
        .map_err(|_| AppError::Unauthorized)?;

    let role = claims
        .get_claim(ROLE_CLAIM)
        .and_then(|value| value.as_str())
        .ok_or(AppError::Unauthorized)?
        .parse::<Role>()
        .map_err(|_| AppError::Unauthorized)?;

    Ok(TokenIdentity { user_id, role })
}

/// Minting failures are ours, not the client's: a claim that will not serialise
/// or a clock that overflowed is a bug here, so it becomes a 500 with the cause
/// logged rather than a 401 blaming the caller.
fn internal(error: pasetors::errors::Error) -> AppError {
    AppError::Internal(anyhow::anyhow!("paseto operation failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(secret: &str) -> SecurityConfig {
        SecurityConfig {
            token_format: crate::config::TokenFormat::PasetoLocal,
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

    const SECRET: &str = "a-secret-long-enough-for-the-validator";

    #[test]
    fn a_token_round_trips_and_announces_its_version() {
        let codec = PasetoLocalCodec::new(&config(SECRET));
        let user = Uuid::new_v4();

        let token = codec.issue(user, Role::Admin).unwrap();
        assert!(
            token.starts_with("v4.local."),
            "the version and purpose are part of the token, not a header: {token}"
        );

        let identity = codec.verify(&token).unwrap();
        assert_eq!(identity.user_id, user);
        assert_eq!(identity.role, Role::Admin);
    }

    #[test]
    fn the_payload_is_not_readable() {
        let codec = PasetoLocalCodec::new(&config(SECRET));
        let user = Uuid::new_v4();
        let token = codec.issue(user, Role::Admin).unwrap();

        // Unlike a JWT, whose claims are base64 and readable by anything that
        // handles the token.
        assert!(
            !token.contains(&user.to_string()) && !token.contains("admin"),
            "the claims must not be legible in the token: {token}"
        );
    }

    #[test]
    fn another_key_cannot_read_or_forge_one() {
        let ours = PasetoLocalCodec::new(&config(SECRET));
        let theirs = PasetoLocalCodec::new(&config("a-different-secret-of-sufficient-length"));

        let token = theirs.issue(Uuid::new_v4(), Role::Admin).unwrap();
        assert!(ours.verify(&token).is_err());
    }

    #[test]
    fn a_token_minted_for_another_service_is_refused() {
        let ours = PasetoLocalCodec::new(&config(SECRET));

        let mut other_audience = config(SECRET);
        other_audience.jwt_audience = "somebody-elses-api".into();
        let theirs = PasetoLocalCodec::new(&other_audience);

        // Same key, so it decrypts. The claims are what refuse it.
        let token = theirs.issue(Uuid::new_v4(), Role::User).unwrap();
        assert!(
            ours.verify(&token).is_err(),
            "decrypting is not the same as being addressed to us"
        );

        let mut other_issuer = config(SECRET);
        other_issuer.jwt_issuer = "somebody-else".into();
        let token = PasetoLocalCodec::new(&other_issuer)
            .issue(Uuid::new_v4(), Role::User)
            .unwrap();
        assert!(ours.verify(&token).is_err());
    }

    #[test]
    fn an_expired_token_is_refused() {
        let mut expiring = config(SECRET);
        expiring.access_token_ttl = Duration::from_secs(0);
        let codec = PasetoLocalCodec::new(&expiring);

        let token = codec.issue(Uuid::new_v4(), Role::User).unwrap();
        std::thread::sleep(Duration::from_millis(1100));

        assert!(codec.verify(&token).is_err(), "exp is enforced");
    }

    #[test]
    fn a_jwt_is_not_a_paseto() {
        let codec = PasetoLocalCodec::new(&config(SECRET));

        // Format confusion in the other direction is what `jwt.rs` pins by
        // fixing its algorithm list; this is the same check from this side.
        let jwt = crate::security::jwt::JwtCodec::new(&config(SECRET))
            .issue(Uuid::new_v4(), Role::Admin)
            .unwrap();

        assert!(
            codec.verify(&jwt).is_err(),
            "a token of another format must not authenticate anybody"
        );
    }

    fn public_config(keys: &(Vec<u8>, Vec<u8>)) -> SecurityConfig {
        SecurityConfig {
            token_format: crate::config::TokenFormat::PasetoPublic,
            token_private_key: Some(keys.0.clone()),
            token_public_key: Some(keys.1.clone()),
            ..config(SECRET)
        }
    }

    #[test]
    fn a_signed_token_round_trips_and_announces_its_version() {
        let keys = generate_key_pair().unwrap();
        let codec = PasetoPublicCodec::new(&public_config(&keys));
        let user = Uuid::new_v4();

        let token = codec.issue(user, Role::User).unwrap();
        assert!(token.starts_with("v4.public."), "{token}");

        let identity = codec.verify(&token).unwrap();
        assert_eq!(identity.user_id, user);
        assert_eq!(identity.role, Role::User);
    }

    #[test]
    fn verifying_needs_only_the_public_half() {
        let minting = generate_key_pair().unwrap();
        let unrelated = generate_key_pair().unwrap();

        let issuer = PasetoPublicCodec::new(&public_config(&minting));

        // A verifier that holds the minting public key but somebody else's
        // private key still accepts the token. That is the whole point of the
        // format: verification is not evidence of the ability to mint.
        let verifier = PasetoPublicCodec::new(&public_config(&(unrelated.0, minting.1.clone())));

        let token = issuer.issue(Uuid::new_v4(), Role::Admin).unwrap();
        assert!(verifier.verify(&token).is_ok());
    }

    #[test]
    fn a_token_signed_by_another_key_pair_is_refused() {
        let ours = PasetoPublicCodec::new(&public_config(&generate_key_pair().unwrap()));
        let theirs = PasetoPublicCodec::new(&public_config(&generate_key_pair().unwrap()));

        let token = theirs.issue(Uuid::new_v4(), Role::Admin).unwrap();
        assert!(ours.verify(&token).is_err());
    }

    #[test]
    fn the_signed_payload_is_readable_and_that_is_expected() {
        let keys = generate_key_pair().unwrap();
        let codec = PasetoPublicCodec::new(&public_config(&keys));
        let user = Uuid::new_v4();

        let token = codec.issue(user, Role::Admin).unwrap();

        // Signed, not encrypted: the claims are legible, as in a JWT. A
        // verifier that cannot read a token cannot act on it, so this is
        // inherent to the purpose rather than a shortcoming — but it is the
        // reason not to reach for this format when the claims are sensitive.
        let payload = token.trim_start_matches("v4.public.");
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            payload.split('.').next().unwrap(),
        )
        .unwrap();
        let text = String::from_utf8_lossy(&decoded);
        assert!(
            text.contains(&user.to_string()) && text.contains("admin"),
            "the claims are meant to be readable here: {text}"
        );
    }

    #[test]
    fn a_local_token_is_not_a_public_one() {
        let keys = generate_key_pair().unwrap();
        let signed = PasetoPublicCodec::new(&public_config(&keys));
        let encrypted = PasetoLocalCodec::new(&config(SECRET));

        let local = encrypted.issue(Uuid::new_v4(), Role::Admin).unwrap();
        assert!(
            signed.verify(&local).is_err(),
            "the purpose is part of the token, and it is checked"
        );

        let public = signed.issue(Uuid::new_v4(), Role::Admin).unwrap();
        assert!(encrypted.verify(&public).is_err());
    }

    #[test]
    fn a_generated_pair_is_the_length_the_format_requires() {
        let (private, public) = generate_key_pair().unwrap();

        // The config validator checks these lengths on the way in; if
        // generation ever produced something else, the server would refuse the
        // keys it had just printed.
        assert_eq!(private.len(), 64);
        assert_eq!(public.len(), 32);

        // Two calls must not produce the same key.
        let (other_private, _) = generate_key_pair().unwrap();
        assert_ne!(private, other_private);
    }

    #[test]
    fn a_truncated_or_edited_token_is_refused() {
        let codec = PasetoLocalCodec::new(&config(SECRET));
        let token = codec.issue(Uuid::new_v4(), Role::User).unwrap();

        assert!(codec.verify(&token[..token.len() - 4]).is_err());
        assert!(codec.verify(&format!("{token}tampered")).is_err());
        assert!(
            codec
                .verify(&token.replace("v4.local.", "v4.public."))
                .is_err()
        );
        assert!(codec.verify("").is_err());
    }
}
