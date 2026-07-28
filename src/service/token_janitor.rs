//! Background sweep of tokens that can no longer be used — refresh tokens,
//! and the access tokens the opaque format stores.
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
    tables: Vec<Arc<dyn ExpiredTokenSweeper>>,
}

impl TokenJanitor {
    pub fn new(tables: Vec<Arc<dyn ExpiredTokenSweeper>>) -> Self {
        Self { tables }
    }

    /// Removes rows past their expiry. Returns how many were removed, so the
    /// caller can log something meaningful only when there was something to do.
    pub async fn purge_expired(&self) -> AppResult<u64> {
        let now = Utc::now();
        let mut removed = 0;
        for table in &self.tables {
            removed += table.delete_expired(now).await?;
        }
        Ok(removed)
    }
}
