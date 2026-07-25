//! Note CRUD. Every handler takes [`CurrentUser`], so authorisation is part of
//! the signature rather than something a reviewer has to spot.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use crate::{
    api::{
        dto::{NoteResponse, PageResponse, PaginationQuery, UpsertNoteRequest},
        extract::{ValidatedJson, ValidatedQuery},
    },
    error::AppResult,
    security::CurrentUser,
    state::AppState,
};

pub async fn create(
    State(state): State<AppState>,
    user: CurrentUser,
    ValidatedJson(payload): ValidatedJson<UpsertNoteRequest>,
) -> AppResult<Response> {
    let note = state
        .notes()
        .create(user.id, payload.title, payload.body)
        .await?;
    Ok((StatusCode::CREATED, Json(NoteResponse::from(note))).into_response())
}

pub async fn list(
    State(state): State<AppState>,
    user: CurrentUser,
    ValidatedQuery(page): ValidatedQuery<PaginationQuery>,
) -> AppResult<Json<PageResponse<NoteResponse>>> {
    let result = state.notes().list(user.id, page.limit, page.offset).await?;
    Ok(Json(result.into()))
}

pub async fn get(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<NoteResponse>> {
    let note = state.notes().get(id, user.id).await?;
    Ok(Json(note.into()))
}

pub async fn update(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
    ValidatedJson(payload): ValidatedJson<UpsertNoteRequest>,
) -> AppResult<Json<NoteResponse>> {
    let note = state
        .notes()
        .update(id, user.id, payload.title, payload.body)
        .await?;
    Ok(Json(note.into()))
}

pub async fn delete(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> AppResult<StatusCode> {
    state.notes().delete(id, user.id).await?;
    Ok(StatusCode::NO_CONTENT)
}
