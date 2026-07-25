//! The failure vocabulary of the persistence layer.
//!
//! Repositories speak this, not `sqlx::Error` and not `AppError`. That keeps
//! the dependency pointing inward: the shared error type no longer has to know
//! what database library exists, and an implementation backed by something
//! other than SQL has a language to fail in.

use thiserror::Error;

pub type RepositoryResult<T> = Result<T, RepositoryError>;

#[derive(Debug, Error)]
pub enum RepositoryError {
    /// A uniqueness constraint rejected the write. Callers surface this as a
    /// conflict; see the contract on `UserRepository::insert` for why the
    /// distinction matters.
    #[error("the record already exists")]
    Conflict,

    /// The store was reachable but the operation failed. Always logged, never
    /// shown to a client.
    #[error(transparent)]
    Backend(#[from] anyhow::Error),
}

impl From<sqlx::Error> for RepositoryError {
    fn from(err: sqlx::Error) -> Self {
        match &err {
            // The database is the real arbiter of uniqueness: services check
            // first, but that check and the write are two steps, and under
            // concurrency only the constraint decides.
            sqlx::Error::Database(cause) if cause.is_unique_violation() => {
                RepositoryError::Conflict
            }
            _ => RepositoryError::Backend(anyhow::Error::new(err).context("database failure")),
        }
    }
}
