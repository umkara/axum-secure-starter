use async_trait::async_trait;

use crate::repository::error::RepositoryResult;

/// Liveness of the persistence layer.
///
/// This exists so the readiness probe can ask "is the database reachable?"
/// without the HTTP layer holding a connection pool or writing SQL. The rule
/// the whole structure rests on — `api` does not know SQL — is not worth
/// breaking for one query.
#[async_trait]
pub trait HealthRepository: Send + Sync + 'static {
    async fn ping(&self) -> RepositoryResult<()>;
}
