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
}

impl TokenFormat {
    /// The accepted spellings, for error messages. Keep in step with
    /// [`TokenFormat::from_str`].
    const SUPPORTED: &'static str = "jwt";
}

impl std::fmt::Display for TokenFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenFormat::Jwt => f.write_str("jwt"),
        }
    }
}

impl FromStr for TokenFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "jwt" => Ok(TokenFormat::Jwt),
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

        Ok(Self {
            token_format: parse_or("APP_TOKEN_FORMAT", TokenFormat::default())?,
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
