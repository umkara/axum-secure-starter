//! Application configuration, loaded from the environment.
//!
//! Configuration is read once at start-up and then treated as immutable. Any
//! value that would weaken the security posture of the server (short signing
//! keys, wildcard CORS, disabled TLS in production) is rejected here rather
//! than at the point of use, so a misconfigured server fails to boot instead
//! of failing open at runtime.

use std::{env, net::SocketAddr, path::PathBuf, str::FromStr, time::Duration};

use thiserror::Error;

/// Minimum length of the JWT signing key. HS256 keys shorter than the hash
/// output add no security, so anything below 32 bytes is refused.
const MIN_JWT_SECRET_LEN: usize = 32;

/// Matches the minimum enforced on ordinary registrations.
const MIN_ADMIN_PASSWORD_LEN: usize = 12;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("environment variable `{0}` is required but was not set")]
    Missing(&'static str),
    #[error("environment variable `{name}` is invalid: {reason}")]
    Invalid { name: &'static str, reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Development,
    Production,
}

impl Environment {
    pub fn is_production(self) -> bool {
        matches!(self, Environment::Production)
    }
}

impl FromStr for Environment {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "dev" | "development" | "local" => Ok(Environment::Development),
            "prod" | "production" => Ok(Environment::Production),
            other => Err(format!(
                "expected `development` or `production`, got `{other}`"
            )),
        }
    }
}

/// How access tokens are written and read.
///
/// The application never branches on this — [`crate::security::token`] turns it
/// into an implementation once, at start-up. It exists so that the token format
/// is a deployment decision rather than a code change, and so that changing it
/// is one reviewed line rather than a refactor.
///
/// Non-exhaustive because more formats are coming; matching on it exhaustively
/// downstream would make each addition a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum TokenFormat {
    /// HS256 JWT. The default, and what every version before 0.4 issued.
    #[default]
    Jwt,
    /// PASETO v4.local: XChaCha20-Poly1305, with the version rather than a
    /// header deciding the cryptography, and an encrypted payload.
    PasetoLocal,
    /// PASETO v4.public: Ed25519 signatures. Anyone holding the public key can
    /// verify a token; only the holder of the private key can mint one.
    PasetoPublic,
}

impl TokenFormat {
    /// The accepted spellings, for error messages. Keep in step with
    /// [`TokenFormat::from_str`].
    const SUPPORTED: &'static str = "`jwt`, `paseto-local`, `paseto-public`";

    /// Whether this format is signed with a key pair rather than a shared
    /// secret, and so needs [`SecurityConfig::token_private_key`] and
    /// [`SecurityConfig::token_public_key`].
    pub fn needs_key_pair(self) -> bool {
        matches!(self, TokenFormat::PasetoPublic)
    }
}

impl std::fmt::Display for TokenFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenFormat::Jwt => f.write_str("jwt"),
            TokenFormat::PasetoLocal => f.write_str("paseto-local"),
            TokenFormat::PasetoPublic => f.write_str("paseto-public"),
        }
    }
}

impl FromStr for TokenFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "jwt" => Ok(TokenFormat::Jwt),
            // `paseto` alone is deliberately not accepted: it will be ambiguous
            // the moment the public variant lands, and a deployment should not
            // silently change which one it runs when that happens.
            "paseto-local" | "v4.local" => Ok(TokenFormat::PasetoLocal),
            "paseto-public" | "v4.public" => Ok(TokenFormat::PasetoPublic),
            other => Err(format!(
                "expected one of {}, got `{other}`",
                TokenFormat::SUPPORTED
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub addr: SocketAddr,
    /// Maximum accepted request body, in bytes.
    pub body_limit_bytes: usize,
    /// Whole-request deadline. Handlers exceeding it get a 408.
    pub request_timeout: Duration,
    /// Ceiling on requests processed at the same time; sheds load beyond it.
    pub max_concurrency: usize,
    /// Ceiling on open connections. Bounds file descriptors against clients
    /// that hold sockets without completing a request.
    pub max_connections: usize,
    /// Deadline for a client to finish sending request headers. This is the
    /// slowloris control: the request timeout cannot help before a request
    /// exists.
    pub header_read_timeout: Duration,
    /// Deadline for completing the TLS handshake.
    pub tls_handshake_timeout: Duration,
    /// Ceiling on concurrent HTTP/2 streams per connection. Streams are cheap
    /// for a client to open and cancel, so the connection limit alone does not
    /// bound the work one peer can request.
    pub max_concurrent_streams: u32,
    /// Time allowed for in-flight requests to finish during shutdown.
    pub shutdown_grace: Duration,
    /// Directory of prebuilt frontend assets to serve. When set, anything not
    /// matching an API route is served from here, with unknown paths falling
    /// back to `index.html` so client-side routing works.
    pub static_dir: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// One-time administrator seed. Present only when both variables are set.
#[derive(Clone)]
pub struct BootstrapAdmin {
    pub email: String,
    pub password: String,
}

impl std::fmt::Debug for BootstrapAdmin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapAdmin")
            .field("email", &self.email)
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub acquire_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Seconds required to replenish one request slot (global limiter).
    pub global_per_second: u64,
    pub global_burst: u32,
    /// Stricter bucket applied to the authentication endpoints.
    pub auth_per_second: u64,
    pub auth_burst: u32,
}

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// How access tokens are written and read. Refresh tokens are unaffected —
    /// they are opaque and server-side whatever this says.
    pub token_format: TokenFormat,
    /// Ed25519 signing key, 64 raw bytes, for the formats that sign rather than
    /// share a secret. Decoded and length-checked at start-up, so a codec built
    /// from it can treat it as valid.
    pub token_private_key: Option<Vec<u8>>,
    /// Ed25519 verifying key, 32 raw bytes. Safe to publish — that is the point
    /// of the format that uses it.
    pub token_public_key: Option<Vec<u8>>,
    pub jwt_secret: String,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub access_token_ttl: Duration,
    pub refresh_token_ttl: Duration,
    /// How many password hashes may run at once. Each reserves 19 MiB and a
    /// core; an unauthenticated request triggers one, so this is the ceiling on
    /// what a login flood can consume.
    pub max_concurrent_hashes: usize,
    /// Consecutive failed logins before the account is temporarily locked.
    pub max_login_attempts: i64,
    pub lockout_duration: Duration,
    /// Exact origins allowed by CORS. Empty disables cross-origin requests.
    pub cors_allowed_origins: Vec<String>,
    /// Trust `X-Forwarded-For` when identifying clients for rate limiting.
    /// Only enable when a trusted reverse proxy sets the header.
    pub trust_proxy_headers: bool,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub environment: Environment,
    pub server: ServerConfig,
    pub tls: Option<TlsConfig>,
    pub database: DatabaseConfig,
    pub security: SecurityConfig,
    pub rate_limit: RateLimitConfig,
    pub bootstrap_admin: Option<BootstrapAdmin>,
}

impl ServerConfig {
    fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            addr: parse_or("APP_BIND_ADDR", "127.0.0.1:8443".parse().unwrap())?,
            body_limit_bytes: parse_or("APP_BODY_LIMIT_BYTES", 256 * 1024)?,
            request_timeout: seconds("APP_REQUEST_TIMEOUT_SECS", 15)?,
            max_concurrency: parse_or("APP_MAX_CONCURRENCY", 1024usize)?,
            max_connections: parse_or("APP_MAX_CONNECTIONS", 4096usize)?,
            header_read_timeout: seconds("APP_HEADER_READ_TIMEOUT_SECS", 10)?,
            tls_handshake_timeout: seconds("APP_TLS_HANDSHAKE_TIMEOUT_SECS", 10)?,
            max_concurrent_streams: parse_or("APP_MAX_CONCURRENT_STREAMS", 128u32)?,
            shutdown_grace: seconds("APP_SHUTDOWN_GRACE_SECS", 20)?,
            static_dir: env::var("APP_STATIC_DIR").ok().map(PathBuf::from),
        })
    }
}

impl TlsConfig {
    /// Both paths or neither. Half-configured TLS is a mistake worth refusing
    /// rather than silently serving plaintext.
    fn from_env() -> Result<Option<Self>, ConfigError> {
        match (
            env::var("APP_TLS_CERT_PATH").ok(),
            env::var("APP_TLS_KEY_PATH").ok(),
        ) {
            (Some(cert), Some(key)) => Ok(Some(Self {
                cert_path: PathBuf::from(cert),
                key_path: PathBuf::from(key),
            })),
            (None, None) => Ok(None),
            _ => Err(ConfigError::Invalid {
                name: "APP_TLS_CERT_PATH",
                reason: "APP_TLS_CERT_PATH and APP_TLS_KEY_PATH must be set together".into(),
            }),
        }
    }
}

impl DatabaseConfig {
    fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            url: env::var("APP_DATABASE_URL")
                .unwrap_or_else(|_| "sqlite://data/app.db?mode=rwc".to_string()),
            max_connections: parse_or("APP_DATABASE_MAX_CONNECTIONS", 16u32)?,
            acquire_timeout: seconds("APP_DATABASE_ACQUIRE_TIMEOUT_SECS", 5)?,
        })
    }
}

impl SecurityConfig {
    fn from_env() -> Result<Self, ConfigError> {
        let jwt_secret =
            env::var("APP_JWT_SECRET").map_err(|_| ConfigError::Missing("APP_JWT_SECRET"))?;
        if jwt_secret.len() < MIN_JWT_SECRET_LEN {
            return Err(ConfigError::Invalid {
                name: "APP_JWT_SECRET",
                reason: format!("must be at least {MIN_JWT_SECRET_LEN} bytes"),
            });
        }

        let cors_allowed_origins = env::var("APP_CORS_ALLOWED_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();

        if cors_allowed_origins.iter().any(|o| o == "*") {
            return Err(ConfigError::Invalid {
                name: "APP_CORS_ALLOWED_ORIGINS",
                reason: "wildcard origins are not allowed; list exact origins".into(),
            });
        }

        let token_format: TokenFormat = parse_or("APP_TOKEN_FORMAT", TokenFormat::default())?;

        // Decoded and measured here rather than where they are used: a key that
        // is the wrong length should stop the server, not the first login.
        let token_private_key = key_bytes(
            "APP_TOKEN_PRIVATE_KEY",
            ED25519_PRIVATE_KEY_LEN,
            "an Ed25519 private key",
        )?;
        let token_public_key = key_bytes(
            "APP_TOKEN_PUBLIC_KEY",
            ED25519_PUBLIC_KEY_LEN,
            "an Ed25519 public key",
        )?;

        if token_format.needs_key_pair() {
            if token_private_key.is_none() {
                return Err(ConfigError::Missing("APP_TOKEN_PRIVATE_KEY"));
            }
            if token_public_key.is_none() {
                return Err(ConfigError::Missing("APP_TOKEN_PUBLIC_KEY"));
            }
        }

        Ok(Self {
            token_format,
            token_private_key,
            token_public_key,
            jwt_secret,
            jwt_issuer: env::var("APP_JWT_ISSUER").unwrap_or_else(|_| "bastion".into()),
            jwt_audience: env::var("APP_JWT_AUDIENCE").unwrap_or_else(|_| "bastion-api".into()),
            access_token_ttl: seconds("APP_ACCESS_TOKEN_TTL_SECS", 900)?,
            refresh_token_ttl: seconds("APP_REFRESH_TOKEN_TTL_SECS", 60 * 60 * 24 * 14)?,
            max_concurrent_hashes: parse_or(
                "APP_MAX_CONCURRENT_HASHES",
                crate::security::password::default_limit(),
            )?,
            max_login_attempts: parse_or("APP_MAX_LOGIN_ATTEMPTS", 5i64)?,
            lockout_duration: seconds("APP_LOCKOUT_SECS", 900)?,
            cors_allowed_origins,
            trust_proxy_headers: parse_or("APP_TRUST_PROXY_HEADERS", false)?,
        })
    }
}

impl RateLimitConfig {
    fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            global_per_second: parse_or("APP_RATE_LIMIT_PER_SECOND", 1u64)?,
            global_burst: parse_or("APP_RATE_LIMIT_BURST", 60u32)?,
            auth_per_second: parse_or("APP_AUTH_RATE_LIMIT_PER_SECOND", 5u64)?,
            auth_burst: parse_or("APP_AUTH_RATE_LIMIT_BURST", 5u32)?,
        })
    }
}

impl BootstrapAdmin {
    fn from_env() -> Result<Option<Self>, ConfigError> {
        match (
            env::var("APP_BOOTSTRAP_ADMIN_EMAIL").ok(),
            env::var("APP_BOOTSTRAP_ADMIN_PASSWORD").ok(),
        ) {
            (Some(email), Some(password)) => {
                if password.len() < MIN_ADMIN_PASSWORD_LEN {
                    return Err(ConfigError::Invalid {
                        name: "APP_BOOTSTRAP_ADMIN_PASSWORD",
                        reason: format!("must be at least {MIN_ADMIN_PASSWORD_LEN} characters"),
                    });
                }
                Ok(Some(Self { email, password }))
            }
            (None, None) => Ok(None),
            _ => Err(ConfigError::Invalid {
                name: "APP_BOOTSTRAP_ADMIN_EMAIL",
                reason:
                    "APP_BOOTSTRAP_ADMIN_EMAIL and APP_BOOTSTRAP_ADMIN_PASSWORD must be set together"
                        .into(),
            }),
        }
    }
}

impl AppConfig {
    /// Reads configuration from the process environment.
    ///
    /// Each section parses and validates itself; this function only assembles
    /// them and applies the rules that span sections — the ones no single
    /// section can see.
    pub fn from_env() -> Result<Self, ConfigError> {
        let environment: Environment = parse_or("APP_ENV", Environment::Development)?;
        let tls = TlsConfig::from_env()?;

        // Cross-section rule: TLS is optional in development and mandatory in
        // production. Neither `TlsConfig` nor `Environment` can decide that on
        // its own.
        if environment.is_production() && tls.is_none() {
            return Err(ConfigError::Invalid {
                name: "APP_TLS_CERT_PATH",
                reason: "TLS is mandatory when APP_ENV=production".into(),
            });
        }

        Ok(Self {
            environment,
            server: ServerConfig::from_env()?,
            tls,
            database: DatabaseConfig::from_env()?,
            security: SecurityConfig::from_env()?,
            rate_limit: RateLimitConfig::from_env()?,
            bootstrap_admin: BootstrapAdmin::from_env()?,
        })
    }
}

/// Raw Ed25519 key lengths. The private form is the seed followed by the public
/// key, which is what PASETO v4.public expects and what `ed25519` libraries
/// generally hand out.
const ED25519_PRIVATE_KEY_LEN: usize = 64;
const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Reads a base64 key of an exact length.
///
/// Accepts standard and URL-safe alphabets, padded or not, because a key gets
/// copied between a terminal, a secret manager and a deployment manifest, and
/// which of those re-encodes it is not the operator's problem to remember.
fn key_bytes(
    name: &'static str,
    expected: usize,
    what: &str,
) -> Result<Option<Vec<u8>>, ConfigError> {
    let Some(raw) = env::var(name).ok().map(|value| value.trim().to_owned()) else {
        return Ok(None);
    };
    if raw.is_empty() {
        return Ok(None);
    }

    decode_key(name, &raw, expected, what).map(Some)
}

/// The decoding half of [`key_bytes`], split out so it can be tested without
/// touching the process environment.
fn decode_key(
    name: &'static str,
    raw: &str,
    expected: usize,
    what: &str,
) -> Result<Vec<u8>, ConfigError> {
    use base64::{
        Engine,
        engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    };

    let decoded = [
        STANDARD.decode(raw),
        STANDARD_NO_PAD.decode(raw),
        URL_SAFE.decode(raw),
        URL_SAFE_NO_PAD.decode(raw),
    ]
    .into_iter()
    .find_map(Result::ok)
    .ok_or(ConfigError::Invalid {
        name,
        reason: "must be base64".into(),
    })?;

    if decoded.len() != expected {
        // The length is the only check worth making here: it catches the two
        // mistakes that actually happen — pasting the wrong half of a key pair,
        // and pasting a PEM instead of raw bytes.
        return Err(ConfigError::Invalid {
            name,
            reason: format!(
                "must decode to {expected} bytes ({what}), got {}",
                decoded.len()
            ),
        });
    }

    Ok(decoded)
}

/// Reads a duration given in whole seconds.
fn seconds(name: &'static str, default: u64) -> Result<Duration, ConfigError> {
    Ok(Duration::from_secs(parse_or(name, default)?))
}

/// Parses an environment variable, falling back to `default` when unset.
fn parse_or<T>(name: &'static str, default: T) -> Result<T, ConfigError>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    match env::var(name) {
        Err(_) => Ok(default),
        Ok(raw) => raw.trim().parse::<T>().map_err(|e| ConfigError::Invalid {
            name,
            reason: e.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Parsing is tested directly rather than through the environment: under
    // edition 2024 `set_var` is unsafe, and a test that sets a variable while
    // other tests run in parallel is racy.

    #[test]
    fn the_token_format_defaults_to_the_one_every_earlier_version_issued() {
        assert_eq!(TokenFormat::default(), TokenFormat::Jwt);
    }

    #[test]
    fn a_token_format_is_read_case_and_space_insensitively() {
        for raw in ["jwt", "JWT", "  Jwt  "] {
            assert_eq!(raw.parse::<TokenFormat>().unwrap(), TokenFormat::Jwt);
        }
    }

    #[test]
    fn a_key_is_read_in_whichever_base64_alphabet_it_arrives_in() {
        use base64::{
            Engine,
            engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
        };

        // Bytes that encode differently in the two alphabets, so this would
        // pass by accident if only one were tried.
        let key: Vec<u8> = (0..32u8).map(|byte| byte.wrapping_mul(9)).collect();

        for encoded in [
            STANDARD.encode(&key),
            STANDARD_NO_PAD.encode(&key),
            URL_SAFE.encode(&key),
            URL_SAFE_NO_PAD.encode(&key),
        ] {
            let decoded = decode_key("APP_TOKEN_PUBLIC_KEY", &encoded, 32, "a key")
                .unwrap_or_else(|error| panic!("`{encoded}` was refused: {error}"));
            assert_eq!(decoded, key);
        }
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused_with_both_lengths_named() {
        use base64::{Engine, engine::general_purpose::STANDARD};

        // The mistake this catches is pasting the public key into the private
        // slot, which is a valid base64 string of the wrong size.
        let public_half = STANDARD.encode([7u8; 32]);

        let rejected = decode_key(
            "APP_TOKEN_PRIVATE_KEY",
            &public_half,
            64,
            "an Ed25519 private key",
        )
        .unwrap_err()
        .to_string();

        assert!(rejected.contains("64"), "{rejected}");
        assert!(rejected.contains("32"), "{rejected}");
    }

    #[test]
    fn something_that_is_not_base64_is_refused() {
        let rejected = decode_key(
            "APP_TOKEN_PUBLIC_KEY",
            "-----BEGIN PRIVATE KEY-----",
            32,
            "a key",
        )
        .unwrap_err()
        .to_string();
        assert!(rejected.contains("base64"), "{rejected}");
    }

    #[test]
    fn only_the_signing_formats_need_a_key_pair() {
        assert!(TokenFormat::PasetoPublic.needs_key_pair());
        assert!(!TokenFormat::Jwt.needs_key_pair());
        assert!(!TokenFormat::PasetoLocal.needs_key_pair());
    }

    #[test]
    fn an_unknown_token_format_names_the_ones_that_exist() {
        // A typo must stop the server rather than fall back to a default: a
        // deployment that asked for one format and silently got another is the
        // failure this setting exists to prevent.
        let rejected = "paseto".parse::<TokenFormat>().unwrap_err();
        assert!(
            rejected.contains(TokenFormat::SUPPORTED),
            "the error must list what is accepted: {rejected}"
        );
    }
}
