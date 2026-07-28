//! Test harness: boots the real router on an ephemeral port against a
//! throwaway database, so tests exercise the same middleware stack as
//! production rather than a stripped-down lookalike.
//!
//! Each test binary compiles this module separately, so anything used by only
//! one of them looks dead to the others.
#![allow(dead_code)]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum_server::Handle;
use bastion::{
    config::{
        AppConfig, BootstrapAdmin, DatabaseConfig, Environment, RateLimitConfig, SecurityConfig,
        ServerConfig,
    },
    db,
    plugin::Registry,
    repository::Repositories,
    server,
    service::AuthService,
    state::AppState,
};
use serde_json::Value;
use tempfile::TempDir;

/// The signing key the harness configures. Attack tests use it to forge
/// tokens that are correctly signed but otherwise malformed.
pub const TEST_JWT_SECRET: &str = "test-secret-that-is-long-enough-to-pass-validation";
pub const TEST_JWT_ISSUER: &str = "bastion-tests";
pub const TEST_JWT_AUDIENCE: &str = "bastion-tests-api";

pub struct TestApp {
    pub base_url: String,
    pub client: reqwest::Client,
    pub addr: SocketAddr,
    pub db_path: std::path::PathBuf,
    /// Kept so tests can call services directly, not only over HTTP.
    pub state: AppState,
    /// Held so the temporary database directory outlives the test.
    _tempdir: TempDir,
}

impl TestApp {
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn state_auth(&self) -> &AuthService {
        self.state.auth()
    }
}

/// Overridable knobs so a test can, for example, drive the lockout policy
/// without waiting for production thresholds.
pub struct TestOptions {
    pub max_login_attempts: i64,
    pub body_limit_bytes: usize,
    pub request_timeout: Duration,
    pub max_connections: usize,
    pub header_read_timeout: Duration,
    pub bootstrap_admin: Option<(String, String)>,
    pub cors_allowed_origins: Vec<String>,
    pub max_concurrent_hashes: usize,
    pub static_dir: Option<std::path::PathBuf>,
    /// Defaults to effectively unlimited, because almost every test would
    /// otherwise spend its budget on requests it does not care about. The rate
    /// limit tests set this deliberately.
    pub rate_limit: RateLimitConfig,
    /// The plugins the spawned server runs. Defaults to the shipped set, so
    /// tests exercise what production runs; a test that cares sets its own.
    pub plugins: Registry,
}

/// Effectively unlimited. `per_second` is a replenish *period* in
/// `tower_governor`, so a large burst with a slow period means the tests that
/// are not about rate limiting never reach it.
pub fn unlimited_rate_limit() -> RateLimitConfig {
    RateLimitConfig {
        global_per_second: 1,
        global_burst: 100_000,
        auth_per_second: 1,
        auth_burst: 100_000,
    }
}

impl Default for TestOptions {
    fn default() -> Self {
        Self {
            max_login_attempts: 5,
            body_limit_bytes: 256 * 1024,
            request_timeout: Duration::from_secs(15),
            max_connections: 512,
            header_read_timeout: Duration::from_secs(10),
            bootstrap_admin: None,
            cors_allowed_origins: vec![],
            max_concurrent_hashes: 4,
            static_dir: None,
            rate_limit: unlimited_rate_limit(),
            plugins: Registry::builtin(),
        }
    }
}

pub async fn spawn() -> TestApp {
    spawn_with(TestOptions::default()).await
}

pub async fn spawn_with(options: TestOptions) -> TestApp {
    let plugins = options.plugins;
    let tempdir = tempfile::tempdir().expect("failed to create a temporary directory");
    let db_path = tempdir.path().join("test.db");

    let config = AppConfig {
        environment: Environment::Development,
        server: ServerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            body_limit_bytes: options.body_limit_bytes,
            request_timeout: options.request_timeout,
            max_concurrency: 256,
            max_connections: options.max_connections,
            header_read_timeout: options.header_read_timeout,
            tls_handshake_timeout: Duration::from_secs(10),
            max_concurrent_streams: 128,
            shutdown_grace: Duration::from_secs(1),
            static_dir: options.static_dir.clone(),
        },
        tls: None,
        database: DatabaseConfig {
            url: format!("sqlite://{}?mode=rwc", db_path.display()),
            max_connections: 4,
            acquire_timeout: Duration::from_secs(5),
        },
        security: SecurityConfig {
            jwt_secret: TEST_JWT_SECRET.into(),
            jwt_issuer: TEST_JWT_ISSUER.into(),
            jwt_audience: TEST_JWT_AUDIENCE.into(),
            access_token_ttl: Duration::from_secs(900),
            refresh_token_ttl: Duration::from_secs(3600),
            max_concurrent_hashes: options.max_concurrent_hashes,
            max_login_attempts: options.max_login_attempts,
            lockout_duration: Duration::from_secs(900),
            cors_allowed_origins: options.cors_allowed_origins.clone(),
            trust_proxy_headers: false,
        },
        rate_limit: options.rate_limit.clone(),
        bootstrap_admin: options
            .bootstrap_admin
            .map(|(email, password)| BootstrapAdmin { email, password }),
    };

    let config = Arc::new(config);
    let pool = db::connect(&config.database)
        .await
        .expect("failed to prepare the test database");
    let state = AppState::new(config.clone(), Repositories::sqlite(pool));

    if let Some(bootstrap) = &config.bootstrap_admin {
        state
            .auth()
            .ensure_admin(&bootstrap.email, &bootstrap.password)
            .await
            .expect("failed to seed the bootstrap administrator");
    }

    let listener =
        server::bind("127.0.0.1:0".parse().unwrap()).expect("failed to bind a test port");
    let addr = listener
        .local_addr()
        .expect("bound listener has no address");

    // Served through the same entry point the binary uses, so the acceptor and
    // the connection deadlines under test are the ones that ship.
    let served_state = state.clone();
    tokio::spawn(async move {
        server::serve(listener, served_state, plugins, Handle::new())
            .await
            .expect("test server stopped unexpectedly");
    });

    TestApp {
        addr,
        state,
        db_path,
        base_url: format!("http://{addr}"),
        client: reqwest::Client::builder()
            // Redirects would mask a routing mistake.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build the test HTTP client"),
        _tempdir: tempdir,
    }
}

/// Registers an account and returns its token pair.
pub async fn register_and_login(app: &TestApp, email: &str, password: &str) -> (String, String) {
    let response = app
        .client
        .post(app.url("/api/v1/auth/register"))
        .json(&serde_json::json!({ "email": email, "password": password }))
        .send()
        .await
        .expect("register request failed");
    assert_eq!(response.status(), 201, "registration should succeed");

    login(app, email, password).await
}

pub async fn login(app: &TestApp, email: &str, password: &str) -> (String, String) {
    let response = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({ "email": email, "password": password }))
        .send()
        .await
        .expect("login request failed");
    assert_eq!(response.status(), 200, "login should succeed");

    let body: Value = response.json().await.expect("login response was not JSON");
    (
        body["access_token"].as_str().unwrap().to_string(),
        body["refresh_token"].as_str().unwrap().to_string(),
    )
}
