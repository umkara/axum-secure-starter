//! Unified error type and its HTTP representation.
//!
//! Every fallible layer converts into [`AppError`]. Only [`AppError`] knows how
//! to turn a failure into a response, which keeps the wire format consistent
//! and — importantly — keeps internal detail (SQL text, panic messages, file
//! paths) out of client-visible bodies. Internal causes are logged instead.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Serialize)]
pub struct FieldError {
    pub field: String,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("request validation failed")]
    Validation(Vec<FieldError>),

    #[error("malformed request: {0}")]
    BadRequest(String),

    /// Authentication is missing, malformed, or expired.
    #[error("authentication required")]
    Unauthorized,

    /// Authenticated, but not permitted to perform the action.
    #[error("insufficient permissions")]
    Forbidden,

    #[error("resource not found")]
    NotFound,

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("payload too large")]
    PayloadTooLarge,

    #[error("service unavailable")]
    Unavailable,

    /// Anything unexpected. The cause is logged, never returned.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl AppError {
    fn status(&self) -> StatusCode {
        match self {
            AppError::Validation(_) | AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Forbidden => StatusCode::FORBIDDEN,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            AppError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Stable, machine-readable code. Clients branch on this, not on prose.
    fn code(&self) -> &'static str {
        match self {
            AppError::Validation(_) => "validation_failed",
            AppError::BadRequest(_) => "bad_request",
            AppError::Unauthorized => "unauthorized",
            AppError::Forbidden => "forbidden",
            AppError::NotFound => "not_found",
            AppError::Conflict(_) => "conflict",
            AppError::PayloadTooLarge => "payload_too_large",
            AppError::Unavailable => "service_unavailable",
            AppError::Internal(_) => "internal_error",
        }
    }

    /// Client-facing message. Deliberately vague for anything that could leak
    /// implementation detail or help an attacker enumerate accounts.
    fn public_message(&self) -> String {
        match self {
            AppError::Internal(_) => "an internal error occurred".to_string(),
            other => other.to_string(),
        }
    }
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<Vec<FieldError>>,
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();

        if let AppError::Internal(cause) = &self {
            // Full chain goes to the log, never to the client.
            tracing::error!(error = ?cause, "unhandled internal error");
        } else if status.is_client_error() {
            tracing::debug!(error = %self, "request rejected");
        }

        let details = match &self {
            AppError::Validation(fields) => Some(
                fields
                    .iter()
                    .map(|f| FieldError {
                        field: f.field.clone(),
                        message: f.message.clone(),
                    })
                    .collect(),
            ),
            _ => None,
        };

        let body = ErrorEnvelope {
            error: ErrorBody {
                code: self.code(),
                message: self.public_message(),
                details,
            },
        };

        (status, Json(body)).into_response()
    }
}

impl From<crate::repository::RepositoryError> for AppError {
    fn from(err: crate::repository::RepositoryError) -> Self {
        use crate::repository::RepositoryError;

        match err {
            // A uniqueness violation is a client-visible conflict, not a server
            // fault: losing a concurrent race must not look like an internal
            // error.
            RepositoryError::Conflict => AppError::Conflict("resource already exists".into()),
            RepositoryError::Backend(cause) => AppError::Internal(cause),
        }
    }
}

impl From<validator::ValidationErrors> for AppError {
    fn from(errors: validator::ValidationErrors) -> Self {
        let fields = errors
            .field_errors()
            .into_iter()
            .flat_map(|(field, errs)| {
                errs.iter()
                    .map(|e| FieldError {
                        field: field.to_string(),
                        message: e
                            .message
                            .as_ref()
                            .map(|m| m.to_string())
                            .unwrap_or_else(|| e.code.to_string()),
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        AppError::Validation(fields)
    }
}

pub type AppResult<T> = Result<T, AppError>;
