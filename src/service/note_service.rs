//! Note business rules. Ownership is applied here and again in SQL, so a bug
//! in one layer alone cannot expose another user's data.

use std::sync::Arc;

use uuid::Uuid;

use crate::{
    domain::Note,
    error::{AppError, AppResult},
    repository::{NoteRepository, note_repository::NewNote},
};

/// Upper bound on page size, enforced regardless of what the client asks for,
/// so a single request cannot pull the whole table.
pub const MAX_PAGE_SIZE: i64 = 100;
pub const DEFAULT_PAGE_SIZE: i64 = 20;

pub struct Page<T> {
    pub items: Vec<T>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

pub struct NoteService {
    notes: Arc<dyn NoteRepository>,
}

impl NoteService {
    pub fn new(notes: Arc<dyn NoteRepository>) -> Self {
        Self { notes }
    }

    pub async fn create(&self, owner_id: Uuid, title: String, body: String) -> AppResult<Note> {
        self.notes
            .insert(NewNote {
                id: Uuid::new_v4(),
                owner_id,
                title,
                body,
            })
            .await
            .map_err(AppError::from)
    }

    pub async fn get(&self, id: Uuid, owner_id: Uuid) -> AppResult<Note> {
        self.notes
            .find_owned(id, owner_id)
            .await?
            .ok_or(AppError::NotFound)
    }

    pub async fn list(
        &self,
        owner_id: Uuid,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> AppResult<Page<Note>> {
        let limit = limit.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);
        let offset = offset.unwrap_or(0).max(0);

        let items = self.notes.list_owned(owner_id, limit, offset).await?;
        let total = self.notes.count_owned(owner_id).await?;

        Ok(Page {
            items,
            total,
            limit,
            offset,
        })
    }

    pub async fn update(
        &self,
        id: Uuid,
        owner_id: Uuid,
        title: String,
        body: String,
    ) -> AppResult<Note> {
        self.notes
            .update_owned(id, owner_id, &title, &body)
            .await?
            .ok_or(AppError::NotFound)
    }

    /// Deleting something you do not own reports 404, not 403: a 403 would
    /// confirm the id exists.
    pub async fn delete(&self, id: Uuid, owner_id: Uuid) -> AppResult<()> {
        if self.notes.delete_owned(id, owner_id).await? {
            Ok(())
        } else {
            Err(AppError::NotFound)
        }
    }
}
