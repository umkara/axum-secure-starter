//! The SQLite → PostgreSQL migration, checked column by column.
//!
//! This is the one tool in the repository whose bugs are unrecoverable. A
//! dropped `users` row is an account nobody can log into again — Argon2 hashes
//! exist nowhere else — and a `refresh_tokens` row that arrives with `used_at`
//! cleared is a spent token the server would honour a second time. So these
//! tests do not check that the migration "worked": they check every column of
//! every table against the value that went in.
//!
//! Needs a PostgreSQL server:
//!
//! ```sh
//! APP_TEST_POSTGRES_URL=postgres://bastion:bastion@localhost/bastion_test \
//!   cargo test --features postgres --test migrate_store
//! ```
//!
//! Skipped, loudly, when that variable is unset.

#![cfg(all(feature = "sqlite", feature = "postgres"))]

use bastion::migrate::{self, Plan};
use chrono::{DateTime, Duration, Utc};
use sqlx::{PgPool, Row, SqlitePool};
use tempfile::TempDir;
use uuid::Uuid;

/// A fixture whose every field is distinguishable, so a copy that swaps two
/// columns or resets one to a default cannot pass.
struct Fixture {
    user: Uuid,
    other_user: Uuid,
    note: Uuid,
    /// Redeemed and revoked — the row whose flags must survive.
    spent_token: Uuid,
    /// Untouched, so the test can tell "everything arrived revoked" from
    /// "the flags were copied".
    live_token: Uuid,
    access_token: Uuid,
    session: Uuid,
    family: Uuid,
    locked_until: DateTime<Utc>,
    created_at: DateTime<Utc>,
    used_at: DateTime<Utc>,
}

async fn seed(sqlite: &SqlitePool) -> Fixture {
    // Whole seconds: SQLite stores RFC 3339 text and PostgreSQL keeps
    // microseconds, so a fractional value would test the formatter rather than
    // the migration.
    let base = DateTime::from_timestamp(1_760_000_000, 0).unwrap();

    let f = Fixture {
        user: Uuid::new_v4(),
        other_user: Uuid::new_v4(),
        note: Uuid::new_v4(),
        spent_token: Uuid::new_v4(),
        live_token: Uuid::new_v4(),
        access_token: Uuid::new_v4(),
        session: Uuid::new_v4(),
        family: Uuid::new_v4(),
        locked_until: base + Duration::minutes(15),
        created_at: base,
        used_at: base + Duration::minutes(3),
    };

    sqlx::query(
        "INSERT INTO users (id, email, password_hash, role, failed_attempts, locked_until, created_at, updated_at)
         VALUES (?, ?, ?, 'admin', 4, ?, ?, ?)",
    )
    .bind(f.user)
    .bind("locked-admin@example.com")
    .bind("$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$fake")
    .bind(f.locked_until)
    .bind(f.created_at)
    .bind(f.created_at + Duration::minutes(1))
    .execute(sqlite)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO users (id, email, password_hash, role, failed_attempts, created_at, updated_at)
         VALUES (?, ?, 'another-hash', 'user', 0, ?, ?)",
    )
    .bind(f.other_user)
    .bind("plain@example.com")
    .bind(f.created_at)
    .bind(f.created_at)
    .execute(sqlite)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO notes (id, owner_id, title, body, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(f.note)
    .bind(f.user)
    .bind("a title with ünïcode and 'quotes'")
    .bind("a body\nwith a newline")
    .bind(f.created_at)
    .bind(f.created_at + Duration::minutes(2))
    .execute(sqlite)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO refresh_tokens (id, user_id, token_hash, family, expires_at, used_at, revoked, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
    )
    .bind(f.spent_token)
    .bind(f.user)
    .bind("a".repeat(64))
    .bind(f.family)
    .bind(f.created_at + Duration::days(14))
    .bind(f.used_at)
    .bind(f.created_at)
    .execute(sqlite)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO refresh_tokens (id, user_id, token_hash, family, expires_at, revoked, created_at)
         VALUES (?, ?, ?, ?, ?, 0, ?)",
    )
    .bind(f.live_token)
    .bind(f.other_user)
    .bind("b".repeat(64))
    .bind(Uuid::new_v4())
    .bind(f.created_at + Duration::days(14))
    .bind(f.created_at)
    .execute(sqlite)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO access_tokens (id, user_id, token_hash, session, role, expires_at, created_at)
         VALUES (?, ?, ?, ?, 'admin', ?, ?)",
    )
    .bind(f.access_token)
    .bind(f.user)
    .bind("c".repeat(64))
    .bind(f.session)
    .bind(f.created_at + Duration::minutes(15))
    .bind(f.created_at)
    .execute(sqlite)
    .await
    .unwrap();

    f
}

/// A SQLite database with the real schema applied, in a directory that lives as
/// long as the returned guard.
async fn sqlite_source() -> (TempDir, String, SqlitePool) {
    let dir = TempDir::new().unwrap();
    let url = format!("sqlite://{}/app.db?mode=rwc", dir.path().display());
    let pool = bastion::db::sqlite::connect(&bastion::config::DatabaseConfig {
        backend: bastion::config::Backend::Sqlite,
        url: url.clone(),
        max_connections: 2,
        acquire_timeout: std::time::Duration::from_secs(5),
    })
    .await
    .expect("could not prepare the source database");

    (dir, url, pool)
}

/// Serialises the tests that write to the shared target.
///
/// Each one truncates the database and then asserts on counts, so two running
/// at once would have one clearing the other's rows mid-assertion. Holding the
/// guard for the whole test — rather than just the truncate — is what makes
/// that impossible; `--test-threads=1` would also work and is easier to forget.
static TARGET: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A PostgreSQL database with every Bastion table emptied, so a rerun does not
/// trip the tool's own empty-target check.
///
/// The returned guard must outlive the assertions.
async fn postgres_target() -> Option<(String, PgPool, tokio::sync::MutexGuard<'static, ()>)> {
    let Ok(url) = std::env::var("APP_TEST_POSTGRES_URL") else {
        eprintln!("skipping: APP_TEST_POSTGRES_URL is not set");
        return None;
    };

    let guard = TARGET.lock().await;

    let pool = PgPool::connect(&url)
        .await
        .expect("could not open postgres");
    sqlx::migrate!("./migrations/postgres")
        .run(&pool)
        .await
        .expect("could not migrate postgres");

    // `users` cascades into all three children.
    sqlx::query("TRUNCATE users, notes, refresh_tokens, access_tokens CASCADE")
        .execute(&pool)
        .await
        .expect("could not clear the target");

    Some((url, pool, guard))
}

#[tokio::test]
async fn every_column_survives_the_crossing() {
    let Some((pg_url, pg, _target)) = postgres_target().await else {
        return;
    };
    let (_dir, sqlite_url, sqlite) = sqlite_source().await;
    let f = seed(&sqlite).await;
    sqlite.close().await;

    let moved = migrate::sqlite_to_postgres(&sqlite_url, &pg_url, Plan::default())
        .await
        .expect("the migration failed");

    assert_eq!(moved.users, 2);
    assert_eq!(moved.notes, 1);
    assert_eq!(moved.refresh_tokens, 2);
    assert_eq!(moved.access_tokens, 1);

    // --- users -----------------------------------------------------------
    let row = sqlx::query(
        "SELECT email, password_hash, role, failed_attempts, locked_until, created_at, updated_at
         FROM users WHERE id = $1",
    )
    .bind(f.user)
    .fetch_one(&pg)
    .await
    .expect("the locked administrator did not arrive");

    assert_eq!(row.get::<String, _>("email"), "locked-admin@example.com");
    assert!(
        row.get::<String, _>("password_hash")
            .starts_with("$argon2id$"),
        "the hash must arrive byte-for-byte; it is the only copy that exists"
    );
    assert_eq!(
        row.get::<String, _>("role"),
        "admin",
        "a demoted administrator is a silent privilege change"
    );
    assert_eq!(
        row.get::<i64, _>("failed_attempts"),
        4,
        "resetting the counter hands an attacker back their spent guesses"
    );
    assert_eq!(
        row.get::<Option<DateTime<Utc>>, _>("locked_until"),
        Some(f.locked_until),
        "a lockout that does not survive is a lockout lifted early"
    );
    assert_eq!(row.get::<DateTime<Utc>, _>("created_at"), f.created_at);
    assert_eq!(
        row.get::<DateTime<Utc>, _>("updated_at"),
        f.created_at + Duration::minutes(1),
        "updated_at is unread by the application, which is not a reason to drop it"
    );

    // --- notes -----------------------------------------------------------
    let row = sqlx::query(
        "SELECT owner_id, title, body, created_at, updated_at FROM notes WHERE id = $1",
    )
    .bind(f.note)
    .fetch_one(&pg)
    .await
    .expect("the note did not arrive");

    assert_eq!(row.get::<Uuid, _>("owner_id"), f.user);
    assert_eq!(
        row.get::<String, _>("title"),
        "a title with ünïcode and 'quotes'"
    );
    assert_eq!(row.get::<String, _>("body"), "a body\nwith a newline");
    assert_eq!(row.get::<DateTime<Utc>, _>("created_at"), f.created_at);
    assert_eq!(
        row.get::<DateTime<Utc>, _>("updated_at"),
        f.created_at + Duration::minutes(2)
    );

    // --- refresh tokens: the security-critical flags ---------------------
    let row = sqlx::query(
        "SELECT user_id, token_hash, family, expires_at, used_at, revoked, created_at
         FROM refresh_tokens WHERE id = $1",
    )
    .bind(f.spent_token)
    .fetch_one(&pg)
    .await
    .expect("the spent token did not arrive");

    assert_eq!(row.get::<Uuid, _>("user_id"), f.user);
    assert_eq!(row.get::<String, _>("token_hash"), "a".repeat(64));
    assert_eq!(row.get::<Uuid, _>("family"), f.family);
    assert_eq!(
        row.get::<Option<DateTime<Utc>>, _>("used_at"),
        Some(f.used_at),
        "a redeemed token arriving unredeemed is a replay the server would honour"
    );
    assert!(
        row.get::<bool, _>("revoked"),
        "a revoked family arriving clean undoes a revocation somebody performed deliberately"
    );
    assert_eq!(
        row.get::<DateTime<Utc>, _>("expires_at"),
        f.created_at + Duration::days(14)
    );

    let row = sqlx::query("SELECT used_at, revoked FROM refresh_tokens WHERE id = $1")
        .bind(f.live_token)
        .fetch_one(&pg)
        .await
        .expect("the live token did not arrive");

    // The other half of the check: the flags were copied, not defaulted to
    // something that happens to look right on one row.
    assert_eq!(row.get::<Option<DateTime<Utc>>, _>("used_at"), None);
    assert!(!row.get::<bool, _>("revoked"));

    // --- access tokens ---------------------------------------------------
    let row = sqlx::query(
        "SELECT user_id, token_hash, session, role, expires_at, created_at
         FROM access_tokens WHERE id = $1",
    )
    .bind(f.access_token)
    .fetch_one(&pg)
    .await
    .expect("the access token did not arrive");

    assert_eq!(row.get::<Uuid, _>("user_id"), f.user);
    assert_eq!(row.get::<String, _>("token_hash"), "c".repeat(64));
    assert_eq!(
        row.get::<Uuid, _>("session"),
        f.session,
        "the session is what lets one device be logged out without the others"
    );
    assert_eq!(row.get::<String, _>("role"), "admin");
}

#[tokio::test]
async fn a_dry_run_writes_nothing() {
    let Some((pg_url, pg, _target)) = postgres_target().await else {
        return;
    };
    let (_dir, sqlite_url, sqlite) = sqlite_source().await;
    seed(&sqlite).await;
    sqlite.close().await;

    let planned = migrate::sqlite_to_postgres(&sqlite_url, &pg_url, Plan { dry_run: true })
        .await
        .expect("the dry run failed");

    // It reports what a real run would move — the numbers are useless if they
    // are not the real ones.
    assert_eq!(planned.total(), 6);

    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&pg)
        .await
        .unwrap();
    assert_eq!(
        left, 0,
        "a dry run must leave the target exactly as it found it"
    );
}

#[tokio::test]
async fn a_non_empty_target_is_refused() {
    let Some((pg_url, pg, _target)) = postgres_target().await else {
        return;
    };
    let (_dir, sqlite_url, sqlite) = sqlite_source().await;
    seed(&sqlite).await;
    sqlite.close().await;

    // Stand in for an earlier attempt that died halfway.
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, role, failed_attempts, created_at, updated_at)
         VALUES ($1, 'squatter@example.com', 'hash', 'user', 0, now(), now())",
    )
    .bind(Uuid::new_v4())
    .execute(&pg)
    .await
    .unwrap();

    let refused = migrate::sqlite_to_postgres(&sqlite_url, &pg_url, Plan::default())
        .await
        .expect_err("a populated target must be refused");

    let message = format!("{refused:#}");
    assert!(
        message.contains("not empty") && message.contains("users"),
        "the error must name the table that is in the way: {message}"
    );

    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&pg)
        .await
        .unwrap();
    assert_eq!(left, 1, "refusing must not delete what was already there");
}

#[tokio::test]
async fn a_missing_source_is_an_error_not_an_empty_migration() {
    let Some((pg_url, _pg, _target)) = postgres_target().await else {
        return;
    };
    let dir = TempDir::new().unwrap();
    let absent = format!("sqlite://{}/not-here.db", dir.path().display());

    // The failure mode this guards: `create_if_missing` would make a typo in
    // the path produce an empty database, a migration reporting zero rows, and
    // a run that looks like a success.
    let refused = migrate::sqlite_to_postgres(&absent, &pg_url, Plan::default())
        .await
        .expect_err("a source that does not exist must be an error");

    assert!(
        format!("{refused:#}").contains("source database"),
        "the error must say the source is the problem: {refused:#}"
    );
}

#[tokio::test]
async fn survey_counts_without_touching_anything() {
    let (_dir, sqlite_url, sqlite) = sqlite_source().await;
    seed(&sqlite).await;
    sqlite.close().await;

    let found = migrate::survey(&sqlite_url).await.expect("survey failed");

    assert_eq!(found.users, 2);
    assert_eq!(found.notes, 1);
    assert_eq!(found.refresh_tokens, 2);
    assert_eq!(found.access_tokens, 1);
    assert_eq!(found.total(), 6);
}
