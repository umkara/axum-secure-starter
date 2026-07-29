//! The persistence ports the application needs, gathered into one value.
//!
//! This exists so that choosing a backend and wiring the services are two
//! separate decisions. `AppState` takes a [`Repositories`] and never learns
//! which database produced it.
//!
//! # Where a backend is chosen
//!
//! [`Repositories::connect`] is the only place in the crate that maps a
//! [`Backend`] to concrete types. `main` and the test harness ask for a
//! `Repositories` and get one; neither names SQLite, PostgreSQL, MySQL or
//! MongoDB, so neither has to change when a backend is added. Adding one means
//! a new module beside this file and one new arm below — and because [`Backend`]
//! is an enum, the compiler refuses to let that arm be forgotten.

use std::sync::Arc;

use crate::{
    config::{Backend, DatabaseConfig},
    repository::{
        AccessTokenRepository, ExpiredTokenSweeper, HealthRepository, NoteRepository,
        TokenRepository, UserRepository,
    },
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
    /// Opens the configured store and returns the ports backed by it.
    ///
    /// The backend was decided when the configuration was validated, so there
    /// is no url sniffing here and no way to reach this with a backend the
    /// binary cannot serve: [`Backend::from_url`] already refused that at
    /// start-up. The `unreachable!` arms are that guarantee written down — a
    /// backend whose feature is off cannot be the value of `config.backend`.
    pub async fn connect(config: &DatabaseConfig) -> anyhow::Result<Self> {
        match config.backend {
            #[cfg(feature = "sqlite")]
            Backend::Sqlite => Ok(Self::sqlite(crate::db::sqlite::connect(config).await?)),
            #[cfg(not(feature = "sqlite"))]
            Backend::Sqlite => unreachable!("configuration rejects a backend that is not compiled"),

            #[cfg(feature = "postgres")]
            Backend::Postgres => Ok(Self::postgres(crate::db::postgres::connect(config).await?)),
            #[cfg(not(feature = "postgres"))]
            Backend::Postgres => {
                unreachable!("configuration rejects a backend that is not compiled")
            }

            #[cfg(feature = "mysql")]
            Backend::MySql => Ok(Self::mysql(crate::db::mysql::connect(config).await?)),
            #[cfg(not(feature = "mysql"))]
            Backend::MySql => unreachable!("configuration rejects a backend that is not compiled"),

            #[cfg(feature = "mongodb")]
            Backend::Mongo => Ok(Self::mongo(crate::db::mongo::connect(config).await?)),
            #[cfg(not(feature = "mongodb"))]
            Backend::Mongo => unreachable!("configuration rejects a backend that is not compiled"),
        }
    }

    /// The SQLite set.
    #[cfg(feature = "sqlite")]
    pub fn sqlite(pool: sqlx::SqlitePool) -> Self {
        use crate::repository::sqlite::*;

        // One type satisfies both token interfaces; the services still see only
        // the slice each of them needs.
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

    /// The PostgreSQL set.
    #[cfg(feature = "postgres")]
    pub fn postgres(pool: sqlx::PgPool) -> Self {
        use crate::repository::postgres::*;

        let token_store = Arc::new(PostgresTokenRepository::new(pool.clone()));
        let access_store = Arc::new(PostgresAccessTokenRepository::new(pool.clone()));

        Self {
            users: Arc::new(PostgresUserRepository::new(pool.clone())),
            notes: Arc::new(PostgresNoteRepository::new(pool.clone())),
            tokens: token_store.clone(),
            access_tokens: access_store.clone(),
            sweepers: vec![token_store, access_store],
            health: Arc::new(PostgresHealthRepository::new(pool)),
        }
    }

    /// The MySQL / MariaDB set.
    #[cfg(feature = "mysql")]
    pub fn mysql(pool: sqlx::MySqlPool) -> Self {
        use crate::repository::mysql::*;

        let token_store = Arc::new(MySqlTokenRepository::new(pool.clone()));
        let access_store = Arc::new(MySqlAccessTokenRepository::new(pool.clone()));

        Self {
            users: Arc::new(MySqlUserRepository::new(pool.clone())),
            notes: Arc::new(MySqlNoteRepository::new(pool.clone())),
            tokens: token_store.clone(),
            access_tokens: access_store.clone(),
            sweepers: vec![token_store, access_store],
            health: Arc::new(MySqlHealthRepository::new(pool)),
        }
    }

    /// The MongoDB set. Read `repository::mongo`'s module documentation before
    /// choosing it: it is the one backend that differs in kind rather than in
    /// dialect.
    #[cfg(feature = "mongodb")]
    pub fn mongo(database: mongodb::Database) -> Self {
        use crate::repository::mongo::*;

        let token_store = Arc::new(MongoTokenRepository::new(&database));
        let access_store = Arc::new(MongoAccessTokenRepository::new(&database));

        Self {
            users: Arc::new(MongoUserRepository::new(&database)),
            notes: Arc::new(MongoNoteRepository::new(&database)),
            tokens: token_store.clone(),
            access_tokens: access_store.clone(),
            sweepers: vec![token_store, access_store],
            health: Arc::new(MongoHealthRepository::new(database)),
        }
    }
}
