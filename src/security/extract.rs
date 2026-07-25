//! Authentication extractors.
//!
//! Putting authentication in an extractor rather than in a middleware means a
//! handler that needs an identity *cannot compile* without asking for one —
//! there is no way to forget the check on a new route.

use axum::{
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts},
};
use uuid::Uuid;

use crate::{domain::Role, error::AppError, state::AppState};

/// An authenticated caller. Presence of this type proves a valid, unexpired,
/// correctly-scoped access token was supplied.
#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub id: Uuid,
    pub role: Role,
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or(AppError::Unauthorized)?
            .to_str()
            .map_err(|_| AppError::Unauthorized)?;

        // Scheme match is case-insensitive per RFC 7235; the token is not.
        let token = header
            .split_once(' ')
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Bearer"))
            .map(|(_, token)| token.trim())
            .filter(|token| !token.is_empty())
            .ok_or(AppError::Unauthorized)?;

        let identity = state.tokens().verify(token)?;

        Ok(CurrentUser {
            id: identity.user_id,
            role: identity.role,
        })
    }
}

/// An authenticated caller that also holds the admin role.
#[derive(Debug, Clone)]
pub struct AdminUser(pub CurrentUser);

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let user = CurrentUser::from_request_parts(parts, state).await?;
        if user.role != Role::Admin {
            return Err(AppError::Forbidden);
        }
        Ok(AdminUser(user))
    }
}
