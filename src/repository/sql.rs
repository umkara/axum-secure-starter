//! What the three SQL backends share.
//!
//! SQLite, PostgreSQL and MySQL differ in dialect — placeholders, `RETURNING`,
//! how a boolean is spelled — but not in schema. The column lists and the
//! error translation live here so a dialect module contains only its dialect,
//! and so a fourth SQL backend inherits both by importing this module.
//!
//! Everything below is compiled only when at least one SQL driver is. A build
//! carrying just the document backend never sees `sqlx::Error` at all.

use crate::repository::error::RepositoryError;

// `updated_at` is written on every mutation but never selected: nothing in the
// domain reads it, so including it would only mean carrying a field around.
pub(crate) const USER_COLUMNS: &str =
    "id, email, password_hash, role, failed_attempts, locked_until, created_at";

pub(crate) const NOTE_COLUMNS: &str = "id, owner_id, title, body, created_at, updated_at";

pub(crate) const TOKEN_COLUMNS: &str =
    "id, user_id, token_hash, family, expires_at, used_at, revoked, created_at";

pub(crate) const ACCESS_TOKEN_COLUMNS: &str =
    "id, user_id, token_hash, session, role, expires_at, created_at";

impl From<sqlx::Error> for RepositoryError {
    fn from(err: sqlx::Error) -> Self {
        match &err {
            // The database is the real arbiter of uniqueness: services check
            // first, but that check and the write are two steps, and under
            // concurrency only the constraint decides. `is_unique_violation`
            // reads each driver's own code — 2067 on SQLite, 23505 on
            // PostgreSQL, 1062 on MySQL — so all three agree on `Conflict`
            // without this module naming any of them.
            sqlx::Error::Database(cause) if cause.is_unique_violation() => {
                RepositoryError::Conflict
            }
            _ => RepositoryError::Backend(anyhow::Error::new(err).context("database failure")),
        }
    }
}
