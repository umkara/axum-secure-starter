use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, SqlitePool};
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

const NOTE_COLUMNS: &str = "id, owner_id, title, body, created_at, updated_at";

/// The SQLite shape of a note, kept separate from [`Note`] so the domain type
/// carries no `sqlx` derives. The two are field-for-field today; the point is
/// that they are free to diverge — a column rename, a packed representation or
/// a second backend's row type changes only this file.
#[derive(FromRow)]
struct NoteRow {
    id: Uuid,
    owner_id: Uuid,
    title: String,
    body: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
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

pub struct SqliteNoteRepository {
    pool: SqlitePool,
}

impl SqliteNoteRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl NoteRepository for SqliteNoteRepository {
    async fn insert(&self, note: NewNote) -> RepositoryResult<Note> {
        let now = Utc::now();
        let row = sqlx::query_as::<_, NoteRow>(&format!(
            "INSERT INTO notes (id, owner_id, title, body, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)
             RETURNING {NOTE_COLUMNS}"
        ))
        .bind(note.id)
        .bind(note.owner_id)
        .bind(note.title)
        .bind(note.body)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.into())
    }

    async fn find_owned(&self, id: Uuid, owner_id: Uuid) -> RepositoryResult<Option<Note>> {
        let row = sqlx::query_as::<_, NoteRow>(&format!(
            "SELECT {NOTE_COLUMNS} FROM notes WHERE id = ? AND owner_id = ?"
        ))
        .bind(id)
        .bind(owner_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Note::from))
    }

    async fn list_owned(
        &self,
        owner_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> RepositoryResult<Vec<Note>> {
        let rows = sqlx::query_as::<_, NoteRow>(&format!(
            "SELECT {NOTE_COLUMNS} FROM notes
             WHERE owner_id = ?
             ORDER BY created_at DESC
             LIMIT ? OFFSET ?"
        ))
        .bind(owner_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Note::from).collect())
    }

    async fn count_owned(&self, owner_id: Uuid) -> RepositoryResult<i64> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notes WHERE owner_id = ?")
            .bind(owner_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(count)
    }

    async fn update_owned(
        &self,
        id: Uuid,
        owner_id: Uuid,
        title: &str,
        body: &str,
    ) -> RepositoryResult<Option<Note>> {
        let row = sqlx::query_as::<_, NoteRow>(&format!(
            "UPDATE notes SET title = ?, body = ?, updated_at = ?
             WHERE id = ? AND owner_id = ?
             RETURNING {NOTE_COLUMNS}"
        ))
        .bind(title)
        .bind(body)
        .bind(Utc::now())
        .bind(id)
        .bind(owner_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Note::from))
    }

    async fn delete_owned(&self, id: Uuid, owner_id: Uuid) -> RepositoryResult<bool> {
        let result = sqlx::query("DELETE FROM notes WHERE id = ? AND owner_id = ?")
            .bind(id)
            .bind(owner_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }
}
