//! Wiring. Concrete implementations are chosen once, here, and everything
//! downstream depends only on the traits — the closest Rust analogue of a
//! container assembling beans at start-up.
//!
//! The fields are private on purpose. When the connection pool was public, a
//! handler reached past the repositories and ran SQL directly; the compiler had
//! no opinion, because nothing forbade it. Accessors expose the collaborators a
//! layer is entitled to and nothing else, so the layering rule is enforced
//! rather than merely documented.

use std::sync::Arc;

use crate::{
    config::AppConfig,
    repository::{HealthRepository, Repositories},
    security::{CredentialHasher, TokenIssuer, password::Argon2Hasher, token},
    service::{AccountService, AuthService, NoteService, SessionService, TokenJanitor},
};

/// Shared, immutable application state. Cloning is refcount-only.
#[derive(Clone)]
pub struct AppState {
    config: Arc<AppConfig>,
    token_issuer: Arc<dyn TokenIssuer>,
    auth: Arc<AuthService>,
    notes: Arc<NoteService>,
    janitor: Arc<TokenJanitor>,
    health: Arc<dyn HealthRepository>,
}

impl AppState {
    /// Wires the services over an already-chosen set of repositories. Which
    /// database backs them is decided by whoever built the [`Repositories`], not
    /// here — this function names no concrete store.
    pub fn new(config: Arc<AppConfig>, repos: Repositories) -> Self {
        // The configured format is turned into an implementation here and
        // nowhere else; everything downstream sees only the trait.
        let token_issuer = token::issuer_for(&config.security);
        let hasher: Arc<dyn CredentialHasher> =
            Arc::new(Argon2Hasher::new(config.security.max_concurrent_hashes));

        let accounts = Arc::new(AccountService::new(repos.users, hasher, &config.security));
        let sessions = Arc::new(SessionService::new(
            repos.tokens,
            token_issuer.clone(),
            &config.security,
        ));

        let auth = Arc::new(AuthService::new(accounts, sessions));
        let notes = Arc::new(NoteService::new(repos.notes));
        let janitor = Arc::new(TokenJanitor::new(repos.sweeper));
        let health = repos.health;

        Self {
            config,
            token_issuer,
            auth,
            notes,
            janitor,
            health,
        }
    }

    /// Assembles state from parts. Tests use this to substitute fakes for the
    /// slow or stateful collaborators.
    pub fn from_parts(
        config: Arc<AppConfig>,
        token_issuer: Arc<dyn TokenIssuer>,
        auth: Arc<AuthService>,
        notes: Arc<NoteService>,
        janitor: Arc<TokenJanitor>,
        health: Arc<dyn HealthRepository>,
    ) -> Self {
        Self {
            config,
            token_issuer,
            auth,
            notes,
            janitor,
            health,
        }
    }

    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    pub fn config_handle(&self) -> Arc<AppConfig> {
        self.config.clone()
    }

    /// Used by the authentication extractor to verify bearer tokens.
    pub fn tokens(&self) -> &dyn TokenIssuer {
        self.token_issuer.as_ref()
    }

    pub fn auth(&self) -> &AuthService {
        &self.auth
    }

    pub fn notes(&self) -> &NoteService {
        &self.notes
    }

    /// The scheduled token sweep. Separate from `auth()` so a background job
    /// cannot reach session revocation.
    pub fn janitor(&self) -> &TokenJanitor {
        &self.janitor
    }

    pub fn health(&self) -> &dyn HealthRepository {
        self.health.as_ref()
    }
}
