//! The persistence ports the application needs, gathered into one value.
//!
//! This exists so that choosing a backend and wiring the services are two
//! separate decisions. `AppState` takes a [`Repositories`] and never learns
//! which database produced it; a second backend adds a constructor here and
//! changes nothing in `state.rs`.

use std::sync::Arc;

use sqlx::SqlitePool;

use crate::repository::{
    AccessTokenRepository, ExpiredTokenSweeper, HealthRepository, NoteRepository,
    SqliteAccessTokenRepository, SqliteHealthRepository, SqliteNoteRepository,
    SqliteTokenRepository, SqliteUserRepository, TokenRepository, UserRepository,
};

/// One resolved implementation of every persistence port. Cloning is
/// refcount-only.
#[derive(Clone)]
pub struct Repositories {
    pub users: Arc<dyn UserRepository>,
    pub notes: Arc<dyn NoteRepository>,
    pub tokens: Arc<dyn TokenRepository>,
    /// Only the opaque access-token format reads this, but it is wired
    /// unconditionally: which format runs is a configuration decision, and the
    /// wiring should not have to know about it.
    pub access_tokens: Arc<dyn AccessTokenRepository>,
    /// Every table with rows that expire. The janitor sweeps all of them, so
    /// adding a table with a lifetime means adding it here and nowhere else.
    pub sweepers: Vec<Arc<dyn ExpiredTokenSweeper>>,
    pub health: Arc<dyn HealthRepository>,
}

impl Repositories {
    /// The SQLite set. This is the only place that names every concrete
    /// repository type, which is what keeps the choice of database confined to
    /// the persistence layer.
    pub fn sqlite(pool: SqlitePool) -> Self {
        // One SQLite type satisfies both token interfaces; the services still
        // see only the slice each of them needs.
        let token_store = Arc::new(SqliteTokenRepository::new(pool.clone()));
        let access_store = Arc::new(SqliteAccessTokenRepository::new(pool.clone()));

        Self {
            users: Arc::new(SqliteUserRepository::new(pool.clone())),
            notes: Arc::new(SqliteNoteRepository::new(pool.clone())),
            tokens: token_store.clone(),
            access_tokens: access_store.clone(),
            sweepers: vec![token_store, access_store],
            health: Arc::new(SqliteHealthRepository::new(pool)),
        }
    }
}
