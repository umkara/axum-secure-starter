use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{domain::Note, repository::error::RepositoryResult};

pub struct NewNote {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub title: String,
    pub body: String,
}

/// Note storage.
///
/// # Contract
///
/// **Every method is scoped by owner, and that scoping is the authorisation
/// check.** An implementation that ignores `owner_id` — or treats it as a hint
/// — turns a leaked identifier into a read or a delete of someone else's data.
/// The service layer checks ownership too; both layers are required, because
/// either one alone is a single point of failure.
#[async_trait]
pub trait NoteRepository: Send + Sync + 'static {
    async fn insert(&self, note: NewNote) -> RepositoryResult<Note>;
    /// Scoped by owner on purpose: knowing an id is not authorisation.
    async fn find_owned(&self, id: Uuid, owner_id: Uuid) -> RepositoryResult<Option<Note>>;
    async fn list_owned(
        &self,
        owner_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> RepositoryResult<Vec<Note>>;
    async fn count_owned(&self, owner_id: Uuid) -> RepositoryResult<i64>;
    async fn update_owned(
        &self,
        id: Uuid,
        owner_id: Uuid,
        title: &str,
        body: &str,
    ) -> RepositoryResult<Option<Note>>;
    async fn delete_owned(&self, id: Uuid, owner_id: Uuid) -> RepositoryResult<bool>;
}

/// The stored shape of a note, kept separate from [`Note`] so the domain type
/// carries no `sqlx` derives. The two are field-for-field today; the point is
/// that they are free to diverge — a column rename or a packed representation
/// changes only the row type and the backend that produces it.
#[derive(sqlx::FromRow)]
pub(crate) struct NoteRow {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub title: String,
    pub body: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Infallible on purpose: every conversion here is a move. A row that needed
// validation would be a sign the column types had drifted from the domain, and
// should fail loudly in `TryFrom` instead.
impl From<NoteRow> for Note {
    fn from(row: NoteRow) -> Self {
        Note {
            id: row.id,
            owner_id: row.owner_id,
            title: row.title,
            body: row.body,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}
