//! Request extractors that fail into [`AppError`] instead of axum's default
//! plaintext rejections — one error shape for the whole API.

use axum::{
    Json,
    extract::{FromRequest, Query, Request, rejection::JsonRejection},
};
use serde::de::DeserializeOwned;
use validator::Validate;

use crate::error::AppError;

/// JSON body that is deserialised *and* validated before a handler sees it.
/// Handlers therefore never work with unvalidated input.
pub struct ValidatedJson<T>(pub T);

impl<S, T> FromRequest<S> for ValidatedJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Validate,
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state)
            .await
            .map_err(|rejection| match rejection {
                JsonRejection::JsonDataError(e) => AppError::BadRequest(e.body_text()),
                JsonRejection::JsonSyntaxError(_) => AppError::BadRequest("malformed JSON".into()),
                JsonRejection::MissingJsonContentType(_) => {
                    AppError::BadRequest("expected `content-type: application/json`".into())
                }
                JsonRejection::BytesRejection(_) => AppError::PayloadTooLarge,
                _ => AppError::BadRequest("could not read request body".into()),
            })?;

        value.validate()?;
        Ok(ValidatedJson(value))
    }
}

/// Query string that is deserialised and validated.
pub struct ValidatedQuery<T>(pub T);

impl<S, T> FromRequest<S> for ValidatedQuery<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Validate,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Query(value) = Query::<T>::from_request(req, state)
            .await
            .map_err(|e| AppError::BadRequest(e.body_text()))?;
        value.validate()?;
        Ok(ValidatedQuery(value))
    }
}
