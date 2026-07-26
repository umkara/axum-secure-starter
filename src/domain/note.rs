use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

/// A note owned by exactly one user. Ownership is enforced in the service
/// layer and in every repository query, so a leaked id is not enough to read
/// or modify someone else's note.
///
/// Deliberately free of database derives: the mapping from a stored row lives
/// with the implementation that produced it (`NoteRow` in the repository), so
/// a second backend adds a row type rather than another annotation here.
#[derive(Debug, Clone, Serialize)]
pub struct Note {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub title: String,
    pub body: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
