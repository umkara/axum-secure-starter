//! Authentication endpoints. Handlers translate DTOs to service calls and back
//! — no policy decisions live here.

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::{
    api::{
        dto::{
            ChangePasswordRequest, LoginRequest, RefreshRequest, RegisterRequest, TokenResponse,
            UserResponse,
        },
        extract::ValidatedJson,
    },
    error::AppResult,
    security::CurrentUser,
    service::AuthTokens,
    state::AppState,
};

impl From<AuthTokens> for TokenResponse {
    fn from(tokens: AuthTokens) -> Self {
        Self {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            token_type: "Bearer",
            expires_in: tokens.expires_in_seconds,
        }
    }
}

pub async fn register(
    State(state): State<AppState>,
    ValidatedJson(payload): ValidatedJson<RegisterRequest>,
) -> AppResult<Response> {
    let user = state
        .auth()
        .register(&payload.email, &payload.password)
        .await?;
    Ok((StatusCode::CREATED, Json(UserResponse::from(user))).into_response())
}

pub async fn login(
    State(state): State<AppState>,
    ValidatedJson(payload): ValidatedJson<LoginRequest>,
) -> AppResult<Json<TokenResponse>> {
    let tokens = state
        .auth()
        .login(&payload.email, &payload.password)
        .await?;
    Ok(Json(tokens.into()))
}

pub async fn refresh(
    State(state): State<AppState>,
    ValidatedJson(payload): ValidatedJson<RefreshRequest>,
) -> AppResult<Json<TokenResponse>> {
    let tokens = state.auth().refresh(&payload.refresh_token).await?;
    Ok(Json(tokens.into()))
}

pub async fn logout(
    State(state): State<AppState>,
    ValidatedJson(payload): ValidatedJson<RefreshRequest>,
) -> AppResult<StatusCode> {
    state.auth().logout(&payload.refresh_token).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn change_password(
    State(state): State<AppState>,
    user: CurrentUser,
    ValidatedJson(payload): ValidatedJson<ChangePasswordRequest>,
) -> AppResult<StatusCode> {
    state
        .auth()
        .change_password(user.id, &payload.current_password, &payload.new_password)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
