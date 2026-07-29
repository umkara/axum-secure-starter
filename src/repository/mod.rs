//! Persistence.
//!
//! Each aggregate is a trait — a port — plus one implementation per backend.
//! Services depend on the trait, tests substitute a fake, and a deployment
//! picks a store with `APP_DATABASE_URL`.
//!
//! ```text
//! user_repository.rs        the port, its contract, and the stored shape
//! note_repository.rs        ditto
//! token_repository.rs       ditto
//! access_token_repository.rs
//! health_repository.rs
//!
//! sql.rs      what the three SQL backends share: columns, error translation
//! sqlite.rs   ─┐
//! postgres.rs  ├─ one module per backend, each behind its cargo feature
//! mysql.rs     │
//! mongo.rs    ─┘
//!
//! set.rs      the one place that maps a backend to concrete types
//! ```
//!
//! The traits carry a **# Contract** section, and it is not decoration. With one
//! implementation those paragraphs described what the code happened to do; with
//! four they are the specification every backend has to meet, and
//! `tests/backends.rs` runs the same suite against each. Where a store cannot
//! provide something for free — MySQL has no `RETURNING`, MongoDB has no
//! foreign keys — the backend module says how it makes up the difference.

pub mod access_token_repository;
pub mod error;
pub mod health_repository;
pub mod note_repository;
pub mod set;
pub mod token_repository;
pub mod user_repository;

#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
pub(crate) mod sql;

#[cfg(feature = "mongodb")]
pub mod mongo;
#[cfg(feature = "mysql")]
pub mod mysql;
#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "sqlite")]
pub mod sqlite;

pub use access_token_repository::AccessTokenRepository;
pub use error::{RepositoryError, RepositoryResult};
pub use health_repository::HealthRepository;
pub use note_repository::NoteRepository;
pub use set::Repositories;
pub use token_repository::{ExpiredTokenSweeper, TokenRepository};
pub use user_repository::UserRepository;

#[cfg(feature = "mongodb")]
pub use mongo::{
    MongoAccessTokenRepository, MongoHealthRepository, MongoNoteRepository, MongoTokenRepository,
    MongoUserRepository,
};
#[cfg(feature = "mysql")]
pub use mysql::{
    MySqlAccessTokenRepository, MySqlHealthRepository, MySqlNoteRepository, MySqlTokenRepository,
    MySqlUserRepository,
};
#[cfg(feature = "postgres")]
pub use postgres::{
    PostgresAccessTokenRepository, PostgresHealthRepository, PostgresNoteRepository,
    PostgresTokenRepository, PostgresUserRepository,
};
#[cfg(feature = "sqlite")]
pub use sqlite::{
    SqliteAccessTokenRepository, SqliteHealthRepository, SqliteNoteRepository,
    SqliteTokenRepository, SqliteUserRepository,
};
