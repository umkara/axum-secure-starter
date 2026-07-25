use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

/// A note owned by exactly one user. Ownership is enforced in the service
/// layer and in every repository query, so a leaked id is not enough to read
/// or modify someone else's note.
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct Note {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub title: String,
    pub body: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
