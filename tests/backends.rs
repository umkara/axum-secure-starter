//! The backend conformance suite.
//!
//! Every repository trait carries a **# Contract** section. With one
//! implementation those paragraphs described what the code happened to do. With
//! four they are a specification, and a specification nothing checks is a
//! comment. This file is the check: one assertion per promise, run against
//! every backend the environment offers.
//!
//! Run it against the stores you have:
//!
//! ```sh
//! # SQLite alone — the default, no services needed.
//! cargo test --test backends
//!
//! # All four.
//! export APP_TEST_POSTGRES_URL=postgres://bastion:bastion@localhost/bastion_test
//! export APP_TEST_MYSQL_URL=mysql://bastion:bastion@localhost/bastion_test
//! export APP_TEST_MONGODB_URL=mongodb://localhost:27017/bastion_test
//! cargo test --features all-backends --test backends
//! ```
//!
//! A backend whose url is unset is skipped and says so. A backend whose url is
//! set but whose feature is off is **not** silently skipped — that combination
//! means the run is not testing what the operator asked for, so it fails.
//!
//! The suite shares a database between runs rather than creating one per test.
//! Every fixture therefore keys on a fresh `Uuid`, and no assertion counts rows
//! it did not create.

use std::time::Duration;

use bastion::{
    config::{Backend, DatabaseConfig},
    domain::Role,
    repository::{
        Repositories, RepositoryError,
        access_token_repository::NewAccessToken,
        note_repository::NewNote,
        token_repository::{NewRefreshToken, RefreshTokenRecord},
        user_repository::NewUser,
    },
};
use chrono::{Duration as ChronoDuration, Utc};
use tempfile::TempDir;
use uuid::Uuid;

/// One connected backend, plus whatever has to stay alive for it to keep
/// working. The `TempDir` is not unused: dropping it deletes the SQLite file.
struct Store {
    name: &'static str,
    repositories: Repositories,
    _scratch: Option<TempDir>,
}

/// Connects to every backend this run can reach.
///
/// Ordering is fixed so a failure report reads the same way twice.
async fn stores() -> Vec<Store> {
    let mut stores = Vec::new();

    if cfg!(feature = "sqlite") {
        let scratch = TempDir::new().expect("failed to create a scratch directory");
        let url = format!(
            "sqlite://{}/conformance.db?mode=rwc",
            scratch.path().display()
        );
        stores.push(Store {
            name: "sqlite",
            repositories: connect(&url).await,
            _scratch: Some(scratch),
        });
    }

    for (name, variable, compiled) in [
        (
            "postgres",
            "APP_TEST_POSTGRES_URL",
            cfg!(feature = "postgres"),
        ),
        ("mysql", "APP_TEST_MYSQL_URL", cfg!(feature = "mysql")),
        ("mongodb", "APP_TEST_MONGODB_URL", cfg!(feature = "mongodb")),
    ] {
        let Ok(url) = std::env::var(variable) else {
            eprintln!("skipping {name}: {variable} is not set");
            continue;
        };

        assert!(
            compiled,
            "{variable} is set but this binary was built without the `{name}` feature; \
             rebuild with --features all-backends or unset the variable"
        );

        stores.push(Store {
            name,
            repositories: connect(&url).await,
            _scratch: None,
        });
    }

    assert!(!stores.is_empty(), "no backend was available to test");
    stores
}

async fn connect(url: &str) -> Repositories {
    let config = DatabaseConfig {
        backend: Backend::from_url(url).expect("unusable test database url"),
        url: url.to_owned(),
        max_connections: 8,
        acquire_timeout: Duration::from_secs(5),
    };

    Repositories::connect(&config)
        .await
        .unwrap_or_else(|error| panic!("could not open {url}: {error:#}"))
}

/// A saved account, since the SQL backends' foreign keys mean notes and tokens
/// need one to point at.
async fn account(store: &Store) -> Uuid {
    let id = Uuid::new_v4();
    store
        .repositories
        .users
        .insert(NewUser {
            id,
            email: format!("{id}@conformance.test"),
            password_hash: "not-a-real-hash".into(),
            role: Role::User,
        })
        .await
        .unwrap_or_else(|error| panic!("[{}] could not seed an account: {error:#}", store.name));
    id
}

fn refresh_token(user_id: Uuid, family: Uuid, minutes: i64) -> NewRefreshToken {
    NewRefreshToken {
        id: Uuid::new_v4(),
        user_id,
        token_hash: Uuid::new_v4().simple().to_string(),
        family,
        expires_at: Utc::now() + ChronoDuration::minutes(minutes),
    }
}

fn access_token(user_id: Uuid, session: Uuid, minutes: i64) -> NewAccessToken {
    NewAccessToken {
        id: Uuid::new_v4(),
        user_id,
        token_hash: Uuid::new_v4().simple().to_string(),
        session,
        role: "user".into(),
        expires_at: Utc::now() + ChronoDuration::minutes(minutes),
    }
}

// ---------------------------------------------------------------------------
// UserRepository
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_duplicate_email_is_a_conflict_not_a_second_account() {
    for store in stores().await {
        let email = format!("{}@conformance.test", Uuid::new_v4());
        let new = |email: &str| NewUser {
            id: Uuid::new_v4(),
            email: email.to_owned(),
            password_hash: "not-a-real-hash".into(),
            role: Role::User,
        };

        store.repositories.users.insert(new(&email)).await.unwrap();

        // The contract the services rely on: they check for an existing account
        // first, but the check and the write are two steps, so only the store
        // can decide the race. A backend that answered `Backend` here would
        // turn a routine duplicate registration into a 500; one that answered
        // `Ok` would create two accounts for one address.
        let rejected = store
            .repositories
            .users
            .insert(new(&email))
            .await
            .expect_err(&format!(
                "[{}] a duplicate email must be refused",
                store.name
            ));

        assert!(
            matches!(rejected, RepositoryError::Conflict),
            "[{}] expected Conflict, got {rejected:?}",
            store.name
        );
    }
}

#[tokio::test]
async fn an_email_is_compared_exactly() {
    for store in stores().await {
        let email = format!("{}@conformance.test", Uuid::new_v4());
        store
            .repositories
            .users
            .insert(NewUser {
                id: Uuid::new_v4(),
                email: email.clone(),
                password_hash: "not-a-real-hash".into(),
                role: Role::User,
            })
            .await
            .unwrap();

        assert!(
            store
                .repositories
                .users
                .find_by_email(&email)
                .await
                .unwrap()
                .is_some(),
            "[{}] the stored address must be findable",
            store.name
        );

        // Callers normalise before calling, so the store must not normalise
        // again. A case-insensitive backend would make two callers disagree
        // about which addresses collide.
        assert!(
            store
                .repositories
                .users
                .find_by_email(&email.to_ascii_uppercase())
                .await
                .unwrap()
                .is_none(),
            "[{}] lookup must be case-sensitive",
            store.name
        );
    }
}

#[tokio::test]
async fn login_failures_are_recorded_and_cleared() {
    for store in stores().await {
        let id = account(&store).await;
        let until = Utc::now() + ChronoDuration::minutes(15);

        store
            .repositories
            .users
            .record_failed_login(id, 3, Some(until))
            .await
            .unwrap();

        let locked = store
            .repositories
            .users
            .find_by_id(id)
            .await
            .unwrap()
            .expect("the account exists");
        assert_eq!(locked.failed_attempts, 3, "[{}]", store.name);
        assert!(locked.locked_until.is_some(), "[{}]", store.name);

        store
            .repositories
            .users
            .clear_login_failures(id)
            .await
            .unwrap();

        let cleared = store
            .repositories
            .users
            .find_by_id(id)
            .await
            .unwrap()
            .expect("the account exists");
        assert_eq!(cleared.failed_attempts, 0, "[{}]", store.name);
        assert!(cleared.locked_until.is_none(), "[{}]", store.name);
    }
}

#[tokio::test]
async fn updating_a_missing_account_is_not_an_error() {
    for store in stores().await {
        // "Updates to a missing id are not an error" — callers that need
        // existence check it explicitly, so a backend that reported one would
        // turn a benign no-op into a 500.
        let absent = Uuid::new_v4();

        store
            .repositories
            .users
            .clear_login_failures(absent)
            .await
            .unwrap_or_else(|error| panic!("[{}] {error:#}", store.name));
        store
            .repositories
            .users
            .update_password_hash(absent, "nothing")
            .await
            .unwrap_or_else(|error| panic!("[{}] {error:#}", store.name));
        store
            .repositories
            .users
            .set_role(absent, Role::Admin)
            .await
            .unwrap_or_else(|error| panic!("[{}] {error:#}", store.name));
    }
}

#[tokio::test]
async fn a_role_survives_a_round_trip() {
    for store in stores().await {
        let id = account(&store).await;
        store
            .repositories
            .users
            .set_role(id, Role::Admin)
            .await
            .unwrap();

        let promoted = store
            .repositories
            .users
            .find_by_id(id)
            .await
            .unwrap()
            .expect("the account exists");
        assert_eq!(promoted.role, Role::Admin, "[{}]", store.name);
    }
}

// ---------------------------------------------------------------------------
// NoteRepository
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_note_operation_is_scoped_by_owner() {
    for store in stores().await {
        let owner = account(&store).await;
        let stranger = account(&store).await;
        let notes = &store.repositories.notes;

        let note = notes
            .insert(NewNote {
                id: Uuid::new_v4(),
                owner_id: owner,
                title: "mine".into(),
                body: "private".into(),
            })
            .await
            .unwrap();

        // Knowing an id is not authorisation. A backend that treated `owner_id`
        // as a hint would turn a leaked identifier into a read, a write and a
        // delete of someone else's data.
        assert!(
            notes.find_owned(note.id, stranger).await.unwrap().is_none(),
            "[{}] a stranger must not read the note",
            store.name
        );
        assert!(
            notes
                .update_owned(note.id, stranger, "theirs", "rewritten")
                .await
                .unwrap()
                .is_none(),
            "[{}] a stranger must not rewrite the note",
            store.name
        );
        assert!(
            !notes.delete_owned(note.id, stranger).await.unwrap(),
            "[{}] a stranger must not delete the note",
            store.name
        );

        let survived = notes
            .find_owned(note.id, owner)
            .await
            .unwrap()
            .expect("the owner still has the note");
        assert_eq!(survived.title, "mine", "[{}]", store.name);
        assert_eq!(survived.body, "private", "[{}]", store.name);
    }
}

#[tokio::test]
async fn an_update_that_changes_nothing_still_finds_the_note() {
    for store in stores().await {
        let owner = account(&store).await;
        let notes = &store.repositories.notes;

        let note = notes
            .insert(NewNote {
                id: Uuid::new_v4(),
                owner_id: owner,
                title: "same".into(),
                body: "same".into(),
            })
            .await
            .unwrap();

        // MySQL's `rows_affected` counts *changed* rows, so an implementation
        // that judged existence by it would answer `None` here and the API
        // would return 404 for a note that is sitting right there.
        let updated = notes
            .update_owned(note.id, owner, "same", "same")
            .await
            .unwrap();

        assert!(
            updated.is_some(),
            "[{}] re-saving identical content must still return the note",
            store.name
        );
    }
}

#[tokio::test]
async fn listing_is_newest_first_and_paged() {
    for store in stores().await {
        let owner = account(&store).await;
        let notes = &store.repositories.notes;

        for index in 0..5 {
            notes
                .insert(NewNote {
                    id: Uuid::new_v4(),
                    owner_id: owner,
                    title: format!("note {index}"),
                    body: "body".into(),
                })
                .await
                .unwrap();
            // Backends store timestamps at different precisions — MongoDB to
            // the millisecond — so the order is only well defined if the writes
            // are distinguishable.
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        assert_eq!(
            notes.count_owned(owner).await.unwrap(),
            5,
            "[{}]",
            store.name
        );

        let first = notes.list_owned(owner, 2, 0).await.unwrap();
        assert_eq!(first.len(), 2, "[{}]", store.name);
        assert_eq!(first[0].title, "note 4", "[{}] newest first", store.name);
        assert_eq!(first[1].title, "note 3", "[{}]", store.name);

        let second = notes.list_owned(owner, 2, 2).await.unwrap();
        assert_eq!(second[0].title, "note 2", "[{}] offset applies", store.name);

        let past_the_end = notes.list_owned(owner, 10, 50).await.unwrap();
        assert!(past_the_end.is_empty(), "[{}]", store.name);
    }
}

#[tokio::test]
async fn a_deleted_note_is_gone_and_deleting_it_twice_reports_false() {
    for store in stores().await {
        let owner = account(&store).await;
        let notes = &store.repositories.notes;

        let note = notes
            .insert(NewNote {
                id: Uuid::new_v4(),
                owner_id: owner,
                title: "transient".into(),
                body: "body".into(),
            })
            .await
            .unwrap();

        assert!(
            notes.delete_owned(note.id, owner).await.unwrap(),
            "[{}]",
            store.name
        );
        assert!(
            !notes.delete_owned(note.id, owner).await.unwrap(),
            "[{}] a second delete affects nothing",
            store.name
        );
        assert!(
            notes.find_owned(note.id, owner).await.unwrap().is_none(),
            "[{}]",
            store.name
        );
    }
}

// ---------------------------------------------------------------------------
// TokenRepository
// ---------------------------------------------------------------------------

#[tokio::test]
async fn redemption_is_single_shot_under_concurrency() {
    for store in stores().await {
        let user_id = account(&store).await;
        let token = refresh_token(user_id, Uuid::new_v4(), 60);
        let id = token.id;
        store.repositories.tokens.insert(token).await.unwrap();

        // The contract that makes stolen-token detection work. Two clients
        // present the same token at once; exactly one may be told it redeemed
        // it. A backend that says `true` twice hands two clients a session from
        // one theft.
        let tokens = store.repositories.tokens.clone();
        let racing = (0..8).map(|_| {
            let tokens = tokens.clone();
            tokio::spawn(async move { tokens.mark_used(id).await.unwrap() })
        });

        let mut winners = 0;
        for attempt in racing {
            if attempt.await.unwrap() {
                winners += 1;
            }
        }

        assert_eq!(
            winners, 1,
            "[{}] exactly one caller may redeem a refresh token",
            store.name
        );
    }
}

#[tokio::test]
async fn a_redeemed_or_revoked_token_is_not_usable() {
    for store in stores().await {
        let user_id = account(&store).await;
        let tokens = &store.repositories.tokens;

        let fresh = refresh_token(user_id, Uuid::new_v4(), 60);
        let fresh_hash = fresh.token_hash.clone();
        tokens.insert(fresh).await.unwrap();

        let expired = refresh_token(user_id, Uuid::new_v4(), -60);
        let expired_hash = expired.token_hash.clone();
        tokens.insert(expired).await.unwrap();

        let stored = |record: Option<RefreshTokenRecord>| record.expect("the token was stored");

        assert!(
            stored(tokens.find_by_hash(&fresh_hash).await.unwrap()).is_usable_at(Utc::now()),
            "[{}] a fresh token is usable",
            store.name
        );
        assert!(
            !stored(tokens.find_by_hash(&expired_hash).await.unwrap()).is_usable_at(Utc::now()),
            "[{}] an expired token is not",
            store.name
        );

        // The digest is matched exactly; there is nothing to normalise about a
        // hash, and a backend that folded case would accept a near-miss.
        assert!(
            tokens
                .find_by_hash(&fresh_hash.to_ascii_uppercase())
                .await
                .unwrap()
                .is_none(),
            "[{}] the digest is matched exactly",
            store.name
        );
    }
}

#[tokio::test]
async fn revocation_takes_a_family_and_is_idempotent() {
    for store in stores().await {
        let user_id = account(&store).await;
        let tokens = &store.repositories.tokens;

        let family = Uuid::new_v4();
        let condemned = refresh_token(user_id, family, 60);
        let condemned_hash = condemned.token_hash.clone();
        tokens.insert(condemned).await.unwrap();

        // A second login by the same account: its own family, and revoking the
        // first must leave it alone.
        let spared = refresh_token(user_id, Uuid::new_v4(), 60);
        let spared_hash = spared.token_hash.clone();
        tokens.insert(spared).await.unwrap();

        tokens.revoke_family(family).await.unwrap();
        // Idempotent, and revoking a family that does not exist affects nothing.
        tokens.revoke_family(family).await.unwrap();
        tokens.revoke_family(Uuid::new_v4()).await.unwrap();

        assert!(
            tokens
                .find_by_hash(&condemned_hash)
                .await
                .unwrap()
                .expect("stored")
                .revoked,
            "[{}] the family was revoked",
            store.name
        );
        assert!(
            !tokens
                .find_by_hash(&spared_hash)
                .await
                .unwrap()
                .expect("stored")
                .revoked,
            "[{}] another family is untouched",
            store.name
        );

        // A revoked token cannot be redeemed even though it was never used.
        assert!(
            !tokens
                .mark_used(
                    tokens
                        .find_by_hash(&condemned_hash)
                        .await
                        .unwrap()
                        .expect("stored")
                        .id
                )
                .await
                .unwrap(),
            "[{}] a revoked token is not redeemable",
            store.name
        );
    }
}

#[tokio::test]
async fn revoking_an_account_revokes_all_of_its_families() {
    for store in stores().await {
        let user_id = account(&store).await;
        let bystander = account(&store).await;
        let tokens = &store.repositories.tokens;

        let mut hashes = Vec::new();
        for _ in 0..3 {
            let token = refresh_token(user_id, Uuid::new_v4(), 60);
            hashes.push(token.token_hash.clone());
            tokens.insert(token).await.unwrap();
        }

        let other = refresh_token(bystander, Uuid::new_v4(), 60);
        let other_hash = other.token_hash.clone();
        tokens.insert(other).await.unwrap();

        tokens.revoke_all_for_user(user_id).await.unwrap();

        for hash in hashes {
            assert!(
                tokens
                    .find_by_hash(&hash)
                    .await
                    .unwrap()
                    .expect("stored")
                    .revoked,
                "[{}] every family of the account is revoked",
                store.name
            );
        }
        assert!(
            !tokens
                .find_by_hash(&other_hash)
                .await
                .unwrap()
                .expect("stored")
                .revoked,
            "[{}] another account is untouched",
            store.name
        );
    }
}

// ---------------------------------------------------------------------------
// AccessTokenRepository
// ---------------------------------------------------------------------------

#[tokio::test]
async fn logging_out_one_device_leaves_the_others_signed_in() {
    for store in stores().await {
        let user_id = account(&store).await;
        let access = &store.repositories.access_tokens;

        let phone = Uuid::new_v4();
        let laptop = Uuid::new_v4();

        let on_phone = access_token(user_id, phone, 15);
        let phone_hash = on_phone.token_hash.clone();
        access.insert(on_phone).await.unwrap();

        let on_laptop = access_token(user_id, laptop, 15);
        let laptop_hash = on_laptop.token_hash.clone();
        access.insert(on_laptop).await.unwrap();

        access.delete_by_session(phone).await.unwrap();
        // Deleting nothing is success.
        access.delete_by_session(phone).await.unwrap();

        assert!(
            access.find_by_hash(&phone_hash).await.unwrap().is_none(),
            "[{}] the phone's token is gone",
            store.name
        );
        assert!(
            access.find_by_hash(&laptop_hash).await.unwrap().is_some(),
            "[{}] the laptop stays signed in",
            store.name
        );

        access.delete_all_for_user(user_id).await.unwrap();
        assert!(
            access.find_by_hash(&laptop_hash).await.unwrap().is_none(),
            "[{}] an account-wide revocation reaches every device",
            store.name
        );
    }
}

// ---------------------------------------------------------------------------
// ExpiredTokenSweeper and HealthRepository
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_sweeper_removes_expired_rows_and_counts_them() {
    for store in stores().await {
        let user_id = account(&store).await;

        let stale = refresh_token(user_id, Uuid::new_v4(), -60);
        let stale_hash = stale.token_hash.clone();
        store.repositories.tokens.insert(stale).await.unwrap();

        let live = refresh_token(user_id, Uuid::new_v4(), 60);
        let live_hash = live.token_hash.clone();
        store.repositories.tokens.insert(live).await.unwrap();

        let expired_access = access_token(user_id, Uuid::new_v4(), -60);
        let expired_access_hash = expired_access.token_hash.clone();
        store
            .repositories
            .access_tokens
            .insert(expired_access)
            .await
            .unwrap();

        // The count is shared with every other test's leftovers on a shared
        // server, so it is only asserted to have reached at least this run's
        // rows. What must be exact is which rows survive.
        let mut swept = 0;
        for sweeper in &store.repositories.sweepers {
            swept += sweeper.delete_expired(Utc::now()).await.unwrap();
        }
        assert!(
            swept >= 2,
            "[{}] both expired rows were counted",
            store.name
        );

        assert!(
            store
                .repositories
                .tokens
                .find_by_hash(&stale_hash)
                .await
                .unwrap()
                .is_none(),
            "[{}] the expired refresh token is gone",
            store.name
        );
        assert!(
            store
                .repositories
                .access_tokens
                .find_by_hash(&expired_access_hash)
                .await
                .unwrap()
                .is_none(),
            "[{}] the expired access token is gone",
            store.name
        );
        assert!(
            store
                .repositories
                .tokens
                .find_by_hash(&live_hash)
                .await
                .unwrap()
                .is_some(),
            "[{}] a live token is not swept",
            store.name
        );
    }
}

#[tokio::test]
async fn readiness_round_trips_a_statement() {
    for store in stores().await {
        store
            .repositories
            .health
            .ping()
            .await
            .unwrap_or_else(|error| panic!("[{}] readiness probe failed: {error:#}", store.name));
    }
}
