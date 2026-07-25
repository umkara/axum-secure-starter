use async_trait::async_trait;
use sqlx::SqlitePool;

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

pub struct SqliteHealthRepository {
    pool: SqlitePool,
}

impl SqliteHealthRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl HealthRepository for SqliteHealthRepository {
    async fn ping(&self) -> RepositoryResult<()> {
        // Cheap, and still proves a connection can be acquired and a statement
        // round-tripped — which is what readiness actually means.
        sqlx::query_scalar::<_, i64>("SELECT 1")
            .fetch_one(&self.pool)
            .await?;
        Ok(())
    }
}
