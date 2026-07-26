//! The persistence ports the application needs, gathered into one value.
//!
//! This exists so that choosing a backend and wiring the services are two
//! separate decisions. `AppState` takes a [`Repositories`] and never learns
//! which database produced it; a second backend adds a constructor here and
//! changes nothing in `state.rs`.

use std::sync::Arc;

use sqlx::SqlitePool;

use crate::repository::{
    ExpiredTokenSweeper, HealthRepository, NoteRepository, SqliteHealthRepository,
    SqliteNoteRepository, SqliteTokenRepository, SqliteUserRepository, TokenRepository,
    UserRepository,
};

/// One resolved implementation of every persistence port. Cloning is
/// refcount-only.
#[derive(Clone)]
pub struct Repositories {
    pub users: Arc<dyn UserRepository>,
    pub notes: Arc<dyn NoteRepository>,
    pub tokens: Arc<dyn TokenRepository>,
    pub sweeper: Arc<dyn ExpiredTokenSweeper>,
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

        Self {
            users: Arc::new(SqliteUserRepository::new(pool.clone())),
            notes: Arc::new(SqliteNoteRepository::new(pool.clone())),
            tokens: token_store.clone(),
            sweeper: token_store,
            health: Arc::new(SqliteHealthRepository::new(pool)),
        }
    }
}
