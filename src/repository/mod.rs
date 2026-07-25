//! Persistence. Each repository is a trait plus a SQLite implementation, so
//! services depend on the contract and tests can substitute a fake.

pub mod error;
pub mod health_repository;
pub mod note_repository;
pub mod token_repository;
pub mod user_repository;

pub use error::{RepositoryError, RepositoryResult};
pub use health_repository::{HealthRepository, SqliteHealthRepository};
pub use note_repository::{NoteRepository, SqliteNoteRepository};
pub use token_repository::{ExpiredTokenSweeper, SqliteTokenRepository, TokenRepository};
pub use user_repository::{SqliteUserRepository, UserRepository};
