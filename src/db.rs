//! Database bootstrap: connection pool plus schema migration.

use std::str::FromStr;

use anyhow::Context;
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};

use crate::config::DatabaseConfig;

/// Opens the pool and brings the schema up to date.
///
/// Foreign keys are off by default in SQLite and must be enabled per
/// connection; without them the `ON DELETE CASCADE` rules in the schema are
/// silently ignored, which would leave orphaned tokens behind after a user is
/// removed.
pub async fn connect(config: &DatabaseConfig) -> anyhow::Result<SqlitePool> {
    let options = SqliteConnectOptions::from_str(&config.url)
        .with_context(|| format!("invalid database url: {}", config.url))?
        .create_if_missing(true)
        .foreign_keys(true)
        // WAL gives concurrent readers alongside a writer; NORMAL is the
        // recommended durability level to pair with it.
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(config.acquire_timeout);

    // Captured before the options are consumed; used to narrow file
    // permissions once SQLite has created the files.
    let options_filename = options.get_filename().to_path_buf();

    let pool = SqlitePoolOptions::new()
        .max_connections(config.max_connections)
        .acquire_timeout(config.acquire_timeout)
        .connect_with(options)
        .await
        .context("failed to open database pool")?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("failed to apply database migrations")?;

    restrict_permissions(&options_filename);

    Ok(pool)
}

/// Narrows the database files to owner-only.
///
/// SQLite creates them with the process umask, which on a typical host means
/// world-readable. The contents are not catastrophic on their own — passwords
/// are Argon2 hashes and refresh tokens are digests — but note bodies are
/// plaintext, and there is no reason for another local account to read any of
/// it. The `-wal` and `-shm` sidecars need the same treatment: they hold
/// recently written pages.
#[cfg(unix)]
fn restrict_permissions(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;

    // In-memory databases have no file to protect.
    if path.as_os_str().is_empty() || path == std::path::Path::new(":memory:") {
        return;
    }

    for candidate in [
        path.to_path_buf(),
        sidecar(path, "-wal"),
        sidecar(path, "-shm"),
    ] {
        if !candidate.exists() {
            continue;
        }
        if let Err(err) =
            std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600))
        {
            // Worth knowing about, but not worth refusing to serve over.
            tracing::warn!(
                path = %candidate.display(),
                error = %err,
                "could not restrict database file permissions"
            );
        }
    }
}

#[cfg(unix)]
fn sidecar(path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    std::path::PathBuf::from(name)
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &std::path::Path) {
    // Windows ACLs are inherited from the containing directory; there is no
    // portable mode bit to narrow here.
}
