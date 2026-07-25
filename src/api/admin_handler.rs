//! Administrative endpoints.
//!
//! Every handler here takes [`AdminUser`], so the role check happens during
//! extraction — before any handler body runs, and impossible to omit.

use axum::{
    extract::{Path, State},
    http::StatusCode,
};
use uuid::Uuid;

use crate::{error::AppResult, security::AdminUser, state::AppState};

/// Revokes every refresh token for an account: the break-glass control for a
/// suspected compromise. Access tokens already issued still run out their few
/// remaining minutes, which is the trade made by keeping them stateless.
pub async fn revoke_sessions(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(user_id): Path<Uuid>,
) -> AppResult<StatusCode> {
    state.auth().logout_everywhere(user_id).await?;
    tracing::warn!(
        actor = %admin.0.id,
        target = %user_id,
        "administrator revoked all sessions for a user"
    );
    Ok(StatusCode::NO_CONTENT)
}
