//! Database bootstrap: open a handle, then bring the schema up to date.
//!
//! One module per backend, each compiled only when its driver is. They share a
//! shape rather than an interface — a SQLite pool, a PostgreSQL pool and a
//! MongoDB database handle have nothing useful in common as types — and the
//! single place that knows which one to open is
//! [`crate::repository::Repositories::connect`].
//!
//! Every module here does two things and stops: it opens the handle and it
//! makes the schema current. Nothing in this file knows what a user or a token
//! is; that is the repository layer's business.

#[cfg(feature = "sqlite")]
pub mod sqlite {
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
    /// silently ignored, which would leave orphaned tokens behind after a user
    /// is removed.
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

        sqlx::migrate!("./migrations/sqlite")
            .run(&pool)
            .await
            .context("failed to apply database migrations")?;

        restrict_permissions(&options_filename);

        Ok(pool)
    }

    /// Narrows the database files to owner-only.
    ///
    /// SQLite creates them with the process umask, which on a typical host
    /// means world-readable. The contents are not catastrophic on their own —
    /// passwords are Argon2 hashes and refresh tokens are digests — but note
    /// bodies are plaintext, and there is no reason for another local account
    /// to read any of it. The `-wal` and `-shm` sidecars need the same
    /// treatment: they hold recently written pages.
    ///
    /// The networked backends have no equivalent, and need none: their files
    /// belong to the database server, not to this process.
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
}

#[cfg(feature = "postgres")]
pub mod postgres {
    use anyhow::Context;
    use sqlx::postgres::{PgPool, PgPoolOptions};

    use crate::config::DatabaseConfig;

    /// Opens the pool and brings the schema up to date.
    ///
    /// There is no `create_if_missing` equivalent: creating a database is a
    /// privileged, one-off act, and a server that silently created one would
    /// hide a typo in `APP_DATABASE_URL` behind an empty schema.
    pub async fn connect(config: &DatabaseConfig) -> anyhow::Result<PgPool> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(config.acquire_timeout)
            .connect(&config.url)
            .await
            .context("failed to open database pool")?;

        sqlx::migrate!("./migrations/postgres")
            .run(&pool)
            .await
            .context("failed to apply database migrations")?;

        Ok(pool)
    }
}

#[cfg(feature = "mysql")]
pub mod mysql {
    use anyhow::Context;
    use sqlx::mysql::{MySqlPool, MySqlPoolOptions};

    use crate::config::DatabaseConfig;

    /// Opens the pool and brings the schema up to date. See the PostgreSQL note
    /// on why the database itself is never created here.
    pub async fn connect(config: &DatabaseConfig) -> anyhow::Result<MySqlPool> {
        let pool = MySqlPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(config.acquire_timeout)
            .connect(&config.url)
            .await
            .context("failed to open database pool")?;

        sqlx::migrate!("./migrations/mysql")
            .run(&pool)
            .await
            .context("failed to apply database migrations")?;

        Ok(pool)
    }
}

#[cfg(feature = "mongodb")]
pub mod mongo {
    use anyhow::{Context, anyhow};
    use mongodb::{Client, Database, options::ClientOptions};

    use crate::{config::DatabaseConfig, repository};

    /// Opens the client and creates the indexes the repository contracts rely
    /// on. Index creation is this backend's migration step, so a failure here
    /// stops start-up exactly as a failed SQL migration does.
    ///
    /// The database name comes from the url and is not defaulted. A url without
    /// one is a configuration error rather than a silent write into `test`, for
    /// the same reason [`crate::config::Backend::from_url`] refuses a
    /// schemeless url.
    pub async fn connect(config: &DatabaseConfig) -> anyhow::Result<Database> {
        let mut options = ClientOptions::parse(&config.url)
            .await
            .with_context(|| format!("invalid database url: {}", config.url))?;

        options.max_pool_size = Some(config.max_connections);
        options.server_selection_timeout = Some(config.acquire_timeout);
        options.connect_timeout = Some(config.acquire_timeout);

        let name = options.default_database.clone().ok_or_else(|| {
            anyhow!("the mongodb url must name a database, as in mongodb://host:27017/bastion")
        })?;

        let database = Client::with_options(options)
            .context("failed to open the mongodb client")?
            .database(&name);

        repository::mongo::ensure_indexes(&database)
            .await
            .context("failed to create mongodb indexes")?;

        Ok(database)
    }
}
