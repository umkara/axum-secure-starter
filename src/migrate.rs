//! Copying a SQLite store into a PostgreSQL one.
//!
//! Changing `APP_DATABASE_URL` from `sqlite://` to `postgres://` points the
//! server at an *empty* schema. Every account, password hash, refresh-token
//! family and note stays behind in the file, and nothing brings them across —
//! Argon2 hashes exist nowhere else, so a deployment that switches without this
//! step has locked out every user permanently. That is what this module is for.
//!
//! # Why it does not go through the repository ports
//!
//! [`crate::repository`] is the seam between the application and a store, and
//! using it here would be the tidier-looking choice. It cannot work. The ports
//! are shaped for an application that creates records *now*: `UserRepository::
//! insert` sets `created_at` to the current time and `failed_attempts` to zero,
//! and `TokenRepository::insert` has no way to say a token was already redeemed
//! or revoked. Round-tripping through them would silently reset lockout
//! counters and resurrect spent refresh tokens — the second of which is a
//! security regression, not a cosmetic one. So this module reads and writes
//! columns directly, and is the one place outside `repository` that does.
//!
//! # What makes it safe to run against production
//!
//! * **The source is opened read-only.** A bug here cannot damage the database
//!   you still depend on.
//! * **The target must be empty.** Refusing beats merging: a half-populated
//!   target usually means an earlier attempt died, and appending to it would
//!   produce duplicates or a confusing constraint failure instead of a clear
//!   message.
//! * **Everything happens in one transaction.** A failure at the last row
//!   leaves the target exactly as empty as it started, so a retry is just a
//!   retry.
//! * **Counts are verified before the commit**, inside the same transaction, so
//!   a mismatch aborts rather than reports.
//! * **[`Plan::dry_run`] does the entire copy and then rolls back**, which
//!   exercises every constraint the real run would hit without keeping
//!   anything.
//!
//! # What it deliberately does not do
//!
//! It does not stop the server. A migration taken while Bastion is still
//! writing to the SQLite file will miss whatever is written after its snapshot
//! — most visibly, sessions created mid-copy. Stop the service first; the
//! function cannot check that for you.

use anyhow::{Context, bail};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, QueryBuilder, Row, SqlitePool, Transaction};
use uuid::Uuid;

/// Rows are sent in batches of this many. PostgreSQL caps a statement at 65535
/// bind parameters; the widest table here binds eight per row, so this leaves
/// an order of magnitude of headroom.
const BATCH: usize = 1_000;

/// What a migration moved, per table.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    pub users: u64,
    pub notes: u64,
    pub refresh_tokens: u64,
    pub access_tokens: u64,
}

impl Report {
    pub fn total(&self) -> u64 {
        self.users + self.notes + self.refresh_tokens + self.access_tokens
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} users, {} notes, {} refresh tokens, {} access tokens",
            self.users, self.notes, self.refresh_tokens, self.access_tokens
        )
    }
}

/// How to run the copy.
#[derive(Debug, Clone, Copy, Default)]
pub struct Plan {
    /// Do the whole copy, verify it, then roll back. The report is what a real
    /// run would have moved.
    pub dry_run: bool,
}

// The source rows. These are not the types in `repository`: those omit
// `updated_at`, because no caller reads it — but a migration is not a caller,
// and dropping a column because the application ignores it would be silent data
// loss.

#[derive(sqlx::FromRow)]
struct UserRow {
    id: Uuid,
    email: String,
    password_hash: String,
    role: String,
    failed_attempts: i64,
    locked_until: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct NoteRow {
    id: Uuid,
    owner_id: Uuid,
    title: String,
    body: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct RefreshTokenRow {
    id: Uuid,
    user_id: Uuid,
    token_hash: String,
    family: Uuid,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
    revoked: bool,
    created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct AccessTokenRow {
    id: Uuid,
    user_id: Uuid,
    token_hash: String,
    session: Uuid,
    role: String,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

/// Copies every row from the SQLite database at `from` into the PostgreSQL
/// database at `to`.
///
/// The target's schema is created by the same migrator the server uses, so the
/// two can never drift. See the module documentation for the guarantees.
pub async fn sqlite_to_postgres(from: &str, to: &str, plan: Plan) -> anyhow::Result<Report> {
    let source = open_source(from).await?;
    let target = open_target(to).await?;

    let report = copy(&source, &target, plan).await;

    // Closing the pools rather than leaving them to drop lets SQLite release
    // the file promptly, which matters when the caller is about to move it.
    source.close().await;
    target.close().await;

    report
}

/// Opens the SQLite file read-only, and refuses to create one.
///
/// `create_if_missing` stays off on purpose: a typo in the path would otherwise
/// produce an empty database, a migration that reports zero rows, and a
/// perfectly successful-looking run that moved nothing.
async fn open_source(url: &str) -> anyhow::Result<SqlitePool> {
    use std::str::FromStr;

    let options = sqlx::sqlite::SqliteConnectOptions::from_str(url)
        .with_context(|| format!("invalid source url: {url}"))?
        .create_if_missing(false)
        .read_only(true);

    sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .with_context(|| format!("could not open the source database at {url}"))
}

/// Opens the target and brings its schema up to date, exactly as the server
/// would on start-up.
async fn open_target(url: &str) -> anyhow::Result<PgPool> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(url)
        .await
        .with_context(|| format!("could not open the target database at {url}"))?;

    sqlx::migrate!("./migrations/postgres")
        .run(&pool)
        .await
        .context("could not apply the PostgreSQL migrations to the target")?;

    Ok(pool)
}

async fn copy(source: &SqlitePool, target: &PgPool, plan: Plan) -> anyhow::Result<Report> {
    let mut tx = target.begin().await.context("could not begin on target")?;

    ensure_empty(&mut tx).await?;

    // Users first: notes and both token tables carry foreign keys to them, and
    // the PostgreSQL schema enforces those.
    let report = Report {
        users: copy_users(source, &mut tx).await?,
        notes: copy_notes(source, &mut tx).await?,
        refresh_tokens: copy_refresh_tokens(source, &mut tx).await?,
        access_tokens: copy_access_tokens(source, &mut tx).await?,
    };

    verify(&mut tx, &report).await?;

    if plan.dry_run {
        tx.rollback().await.context("could not roll back")?;
    } else {
        tx.commit().await.context("could not commit")?;
    }

    Ok(report)
}

/// Refuses a target that already holds rows.
///
/// Appending to a partly-populated target is never what the operator wants: it
/// either duplicates a previous run or fails on a constraint several thousand
/// rows later, and both are worse than stopping now with a sentence saying so.
async fn ensure_empty(tx: &mut Transaction<'_, Postgres>) -> anyhow::Result<()> {
    for table in ["users", "notes", "refresh_tokens", "access_tokens"] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&mut **tx)
            .await
            .with_context(|| format!("could not count {table} on the target"))?;

        if count != 0 {
            bail!(
                "the target is not empty: {table} already holds {count} row(s). \
                 Drop and recreate the database, or point at a fresh one."
            );
        }
    }
    Ok(())
}

/// Reads back what was written, inside the same transaction, before anything is
/// committed. A count that disagrees means a row was dropped somewhere between
/// the read and the write, and the copy is abandoned rather than reported.
async fn verify(tx: &mut Transaction<'_, Postgres>, report: &Report) -> anyhow::Result<()> {
    for (table, expected) in [
        ("users", report.users),
        ("notes", report.notes),
        ("refresh_tokens", report.refresh_tokens),
        ("access_tokens", report.access_tokens),
    ] {
        let found: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&mut **tx)
            .await
            .with_context(|| format!("could not verify {table}"))?;

        if found as u64 != expected {
            bail!("{table}: read {expected} row(s) from SQLite but the target holds {found}");
        }
    }
    Ok(())
}

async fn copy_users(
    source: &SqlitePool,
    tx: &mut Transaction<'_, Postgres>,
) -> anyhow::Result<u64> {
    let rows = sqlx::query_as::<_, UserRow>(
        "SELECT id, email, password_hash, role, failed_attempts, locked_until, created_at, updated_at
         FROM users ORDER BY created_at",
    )
    .fetch_all(source)
    .await
    .context("could not read users")?;

    for chunk in rows.chunks(BATCH) {
        let mut query = QueryBuilder::<Postgres>::new(
            "INSERT INTO users (id, email, password_hash, role, failed_attempts, locked_until, created_at, updated_at) ",
        );
        query.push_values(chunk, |mut row, user| {
            row.push_bind(user.id)
                .push_bind(&user.email)
                .push_bind(&user.password_hash)
                .push_bind(&user.role)
                .push_bind(user.failed_attempts)
                .push_bind(user.locked_until)
                .push_bind(user.created_at)
                .push_bind(user.updated_at);
        });
        query
            .build()
            .execute(&mut **tx)
            .await
            .context("could not write users")?;
    }

    Ok(rows.len() as u64)
}

async fn copy_notes(
    source: &SqlitePool,
    tx: &mut Transaction<'_, Postgres>,
) -> anyhow::Result<u64> {
    let rows = sqlx::query_as::<_, NoteRow>(
        "SELECT id, owner_id, title, body, created_at, updated_at FROM notes ORDER BY created_at",
    )
    .fetch_all(source)
    .await
    .context("could not read notes")?;

    for chunk in rows.chunks(BATCH) {
        let mut query = QueryBuilder::<Postgres>::new(
            "INSERT INTO notes (id, owner_id, title, body, created_at, updated_at) ",
        );
        query.push_values(chunk, |mut row, note| {
            row.push_bind(note.id)
                .push_bind(note.owner_id)
                .push_bind(&note.title)
                .push_bind(&note.body)
                .push_bind(note.created_at)
                .push_bind(note.updated_at);
        });
        query
            .build()
            .execute(&mut **tx)
            .await
            .context("could not write notes")?;
    }

    Ok(rows.len() as u64)
}

/// `used_at` and `revoked` are carried across exactly.
///
/// This is the table where fidelity is a security property rather than a nicety.
/// A spent refresh token that arrives unspent is a replay the server would
/// honour, and a revoked family that arrives clean undoes a revocation somebody
/// performed deliberately.
async fn copy_refresh_tokens(
    source: &SqlitePool,
    tx: &mut Transaction<'_, Postgres>,
) -> anyhow::Result<u64> {
    let rows = sqlx::query_as::<_, RefreshTokenRow>(
        "SELECT id, user_id, token_hash, family, expires_at, used_at, revoked, created_at
         FROM refresh_tokens ORDER BY created_at",
    )
    .fetch_all(source)
    .await
    .context("could not read refresh tokens")?;

    for chunk in rows.chunks(BATCH) {
        let mut query = QueryBuilder::<Postgres>::new(
            "INSERT INTO refresh_tokens (id, user_id, token_hash, family, expires_at, used_at, revoked, created_at) ",
        );
        query.push_values(chunk, |mut row, token| {
            row.push_bind(token.id)
                .push_bind(token.user_id)
                .push_bind(&token.token_hash)
                .push_bind(token.family)
                .push_bind(token.expires_at)
                .push_bind(token.used_at)
                .push_bind(token.revoked)
                .push_bind(token.created_at);
        });
        query
            .build()
            .execute(&mut **tx)
            .await
            .context("could not write refresh tokens")?;
    }

    Ok(rows.len() as u64)
}

async fn copy_access_tokens(
    source: &SqlitePool,
    tx: &mut Transaction<'_, Postgres>,
) -> anyhow::Result<u64> {
    // Absent unless the deployment ran `APP_TOKEN_FORMAT=opaque`, and empty is
    // the normal case rather than a warning.
    let rows = sqlx::query_as::<_, AccessTokenRow>(
        "SELECT id, user_id, token_hash, session, role, expires_at, created_at
         FROM access_tokens ORDER BY created_at",
    )
    .fetch_all(source)
    .await
    .context("could not read access tokens")?;

    for chunk in rows.chunks(BATCH) {
        let mut query = QueryBuilder::<Postgres>::new(
            "INSERT INTO access_tokens (id, user_id, token_hash, session, role, expires_at, created_at) ",
        );
        query.push_values(chunk, |mut row, token| {
            row.push_bind(token.id)
                .push_bind(token.user_id)
                .push_bind(&token.token_hash)
                .push_bind(token.session)
                .push_bind(&token.role)
                .push_bind(token.expires_at)
                .push_bind(token.created_at);
        });
        query
            .build()
            .execute(&mut **tx)
            .await
            .context("could not write access tokens")?;
    }

    Ok(rows.len() as u64)
}

/// A one-line summary of what the source holds, for the operator to sanity-check
/// against before committing to anything.
pub async fn survey(from: &str) -> anyhow::Result<Report> {
    let source = open_source(from).await?;

    let mut report = Report::default();
    for (table, slot) in [
        ("users", &mut report.users),
        ("notes", &mut report.notes),
        ("refresh_tokens", &mut report.refresh_tokens),
        ("access_tokens", &mut report.access_tokens),
    ] {
        let row = sqlx::query(&format!("SELECT COUNT(*) AS n FROM {table}"))
            .fetch_one(&source)
            .await
            .with_context(|| format!("could not count {table} in the source"))?;
        *slot = row.get::<i64, _>("n") as u64;
    }

    source.close().await;
    Ok(report)
}
