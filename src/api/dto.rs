//! Wire contracts.
//!
//! Requests and responses are separate types from domain entities on purpose:
//! adding a field to `User` must never silently start leaking it, and rename
//! of a column must never break clients.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use crate::{
    domain::{Note, Role, User},
    service::Page,
};

/// Long enough to resist guessing, capped so a huge input cannot be used to
/// burn CPU in Argon2 (the hash cost grows with input length).
const PASSWORD_MIN: u64 = 12;
const PASSWORD_MAX: u64 = 128;

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email(message = "must be a valid email address"), length(max = 254))]
    pub email: String,
    #[validate(length(
        min = "PASSWORD_MIN",
        max = "PASSWORD_MAX",
        message = "password must be between 12 and 128 characters"
    ))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(length(min = 1, max = 254))]
    pub email: String,
    #[validate(length(min = 1, max = "PASSWORD_MAX"))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RefreshRequest {
    #[validate(length(min = 1, max = 512))]
    pub refresh_token: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ChangePasswordRequest {
    #[validate(length(min = 1, max = "PASSWORD_MAX"))]
    pub current_password: String,
    #[validate(length(
        min = "PASSWORD_MIN",
        max = "PASSWORD_MAX",
        message = "password must be between 12 and 128 characters"
    ))]
    pub new_password: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            role: user.role,
            created_at: user.created_at,
        }
    }
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpsertNoteRequest {
    #[validate(length(min = 1, max = 200, message = "title must be 1-200 characters"))]
    pub title: String,
    #[validate(length(max = 20_000, message = "body must be at most 20000 characters"))]
    pub body: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct PaginationQuery {
    #[validate(range(min = 1, max = 100))]
    pub limit: Option<i64>,
    #[validate(range(min = 0))]
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct NoteResponse {
    pub id: Uuid,
    pub title: String,
    pub body: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Note> for NoteResponse {
    fn from(note: Note) -> Self {
        Self {
            id: note.id,
            title: note.title,
            body: note.body,
            created_at: note.created_at,
            updated_at: note.updated_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PageResponse<T> {
    pub items: Vec<T>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

impl<D, T: From<D>> From<Page<D>> for PageResponse<T> {
    fn from(page: Page<D>) -> Self {
        Self {
            items: page.items.into_iter().map(T::from).collect(),
            total: page.total,
            limit: page.limit,
            offset: page.offset,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
}
