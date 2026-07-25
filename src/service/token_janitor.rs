//! Background sweep of refresh tokens that can no longer be redeemed.
//!
//! Its own type, with its own dependency, for two reasons. It is not an
//! authentication use case — nobody is being authenticated — and it needs only
//! the ability to delete expired rows. Reaching it through the auth service
//! would have handed a scheduled job the power to revoke live sessions, which
//! is authority it has no use for.

use std::sync::Arc;

use chrono::Utc;

use crate::{error::AppResult, repository::ExpiredTokenSweeper};

pub struct TokenJanitor {
    tokens: Arc<dyn ExpiredTokenSweeper>,
}

impl TokenJanitor {
    pub fn new(tokens: Arc<dyn ExpiredTokenSweeper>) -> Self {
        Self { tokens }
    }

    /// Removes rows past their expiry. Returns how many were removed, so the
    /// caller can log something meaningful only when there was something to do.
    pub async fn purge_expired(&self) -> AppResult<u64> {
        let removed = self.tokens.delete_expired(Utc::now()).await?;
        Ok(removed)
    }
}
