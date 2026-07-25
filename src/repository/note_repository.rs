use async_trait::async_trait;
use chrono::Utc;
use sqlx::SqlitePool;
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
        let row = sqlx::query_as::<_, Note>(&format!(
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
        Ok(row)
    }

    async fn find_owned(&self, id: Uuid, owner_id: Uuid) -> RepositoryResult<Option<Note>> {
        let row = sqlx::query_as::<_, Note>(&format!(
            "SELECT {NOTE_COLUMNS} FROM notes WHERE id = ? AND owner_id = ?"
        ))
        .bind(id)
        .bind(owner_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn list_owned(
        &self,
        owner_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> RepositoryResult<Vec<Note>> {
        let rows = sqlx::query_as::<_, Note>(&format!(
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
        Ok(rows)
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
        let row = sqlx::query_as::<_, Note>(&format!(
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
        Ok(row)
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
