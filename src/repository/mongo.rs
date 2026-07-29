//! The MongoDB backend.
//!
//! The other three backends differ from each other in dialect. This one differs
//! in kind, and the places where that shows are worth reading before trusting
//! it in production.
//!
//! **Ids are BSON UUIDs in `_id`.** Not strings: a binary `_id` indexes and
//! compares byte-for-byte, and there is no case-folding to disagree with the
//! SQL backends about.
//!
//! **Timestamps lose sub-millisecond precision.** `bson::DateTime` is
//! milliseconds since the epoch, where the SQL schemas keep microseconds or
//! better. Nothing in the application compares two timestamps for equality —
//! they are read as deadlines (`expires_at > now`) and as an ordering — so the
//! loss is not observable, with one exception: two notes written in the same
//! millisecond tie on `created_at`. `list_owned` therefore sorts by `_id` as a
//! tiebreaker, which the SQL backends leave to the engine.
//!
//! **Uniqueness is an index, created at connect time.** `Conflict` depends on
//! it existing — `insert` would otherwise happily store a second account with
//! the same address — so [`crate::db::mongo::connect`] runs [`ensure_indexes`]
//! before returning a handle, and a failure to create one fails start-up. That
//! call is this backend's migration step.
//!
//! **There is no `ON DELETE CASCADE`.** The SQL schemas delete a user's tokens
//! and notes with the user; MongoDB cannot. Nothing in the application deletes
//! a user today, so there is no path that orphans anything — but a future
//! `delete_user` must delete the dependent documents itself, and adding one
//! without doing so is a data leak, not a tidiness problem.

use anyhow::anyhow;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::TryStreamExt as _;
use mongodb::{
    Collection, Database,
    bson::{self, Bson, doc},
    options::{IndexOptions, ReturnDocument},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    domain::{Note, Role, User},
    repository::{
        AccessTokenRepository, ExpiredTokenSweeper, HealthRepository, NoteRepository,
        TokenRepository, UserRepository,
        access_token_repository::{AccessTokenRecord, NewAccessToken},
        error::{RepositoryError, RepositoryResult},
        note_repository::{NewNote, NoteRow},
        token_repository::{NewRefreshToken, RefreshTokenRecord},
        user_repository::{NewUser, UserRow},
    },
};

const USERS: &str = "users";
const NOTES: &str = "notes";
const REFRESH_TOKENS: &str = "refresh_tokens";
const ACCESS_TOKENS: &str = "access_tokens";

/// The document-store equivalent of the SQL migrations.
///
/// Every index here is either an enforced contract or a query the application
/// makes on every request; none is an optimisation that could be dropped. It is
/// idempotent — `createIndexes` on an index that already exists with the same
/// definition succeeds and does nothing.
pub(crate) async fn ensure_indexes(database: &Database) -> mongodb::error::Result<()> {
    let unique = |keys: bson::Document| {
        mongodb::IndexModel::builder()
            .keys(keys)
            .options(IndexOptions::builder().unique(true).build())
            .build()
    };
    let plain = |keys: bson::Document| mongodb::IndexModel::builder().keys(keys).build();

    // `insert` promising `Conflict` on a duplicate address rests entirely on
    // this one.
    database
        .collection::<bson::Document>(USERS)
        .create_index(unique(doc! { "email": 1 }))
        .await?;

    database
        .collection::<bson::Document>(REFRESH_TOKENS)
        .create_indexes(vec![
            unique(doc! { "token_hash": 1 }),
            plain(doc! { "user_id": 1 }),
            plain(doc! { "family": 1 }),
            plain(doc! { "expires_at": 1 }),
        ])
        .await?;

    database
        .collection::<bson::Document>(NOTES)
        .create_index(plain(doc! { "owner_id": 1, "created_at": -1 }))
        .await?;

    database
        .collection::<bson::Document>(ACCESS_TOKENS)
        .create_indexes(vec![
            unique(doc! { "token_hash": 1 }),
            plain(doc! { "user_id": 1 }),
            plain(doc! { "session": 1 }),
            plain(doc! { "expires_at": 1 }),
        ])
        .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

fn to_uuid(id: Uuid) -> bson::Uuid {
    bson::Uuid::from_bytes(*id.as_bytes())
}

fn from_uuid(id: bson::Uuid) -> Uuid {
    Uuid::from_bytes(id.bytes())
}

fn to_time(at: DateTime<Utc>) -> bson::DateTime {
    bson::DateTime::from_millis(at.timestamp_millis())
}

/// Fails rather than clamps. A timestamp BSON can hold but chrono cannot means
/// the document was written by something other than this application, and
/// guessing a date for it would be worse than refusing the row.
fn from_time(at: bson::DateTime) -> RepositoryResult<DateTime<Utc>> {
    DateTime::from_timestamp_millis(at.timestamp_millis()).ok_or_else(|| {
        RepositoryError::Backend(anyhow!(
            "stored timestamp {} is outside the representable range",
            at.timestamp_millis()
        ))
    })
}

/// `Conflict` when a unique index rejected the write, and nothing else.
///
/// MongoDB reports every duplicate-key failure as code 11000, whichever index
/// caught it — the same role the driver-specific codes play in
/// `repository::sql`.
fn translate(err: mongodb::error::Error) -> RepositoryError {
    use mongodb::error::{ErrorKind, WriteFailure};

    const DUPLICATE_KEY: i32 = 11000;

    let duplicate = match err.kind.as_ref() {
        ErrorKind::Write(WriteFailure::WriteError(write)) => write.code == DUPLICATE_KEY,
        ErrorKind::InsertMany(insert) => insert
            .write_errors
            .as_ref()
            .is_some_and(|errors| errors.iter().any(|error| error.code == DUPLICATE_KEY)),
        _ => false,
    };

    if duplicate {
        RepositoryError::Conflict
    } else {
        RepositoryError::Backend(anyhow::Error::new(err).context("database failure"))
    }
}

// ---------------------------------------------------------------------------
// Documents
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct UserDoc {
    #[serde(rename = "_id")]
    id: bson::Uuid,
    email: String,
    password_hash: String,
    role: String,
    failed_attempts: i64,
    locked_until: Option<bson::DateTime>,
    created_at: bson::DateTime,
    updated_at: bson::DateTime,
}

impl UserDoc {
    /// Goes through [`UserRow`] rather than straight to [`User`] so that the
    /// one place deciding what an unknown `role` means stays in
    /// `user_repository`, shared with every other backend.
    fn into_user(self) -> RepositoryResult<User> {
        UserRow {
            id: from_uuid(self.id),
            email: self.email,
            password_hash: self.password_hash,
            role: self.role,
            failed_attempts: self.failed_attempts,
            locked_until: self.locked_until.map(from_time).transpose()?,
            created_at: from_time(self.created_at)?,
        }
        .try_into()
    }
}

#[derive(Serialize, Deserialize)]
struct NoteDoc {
    #[serde(rename = "_id")]
    id: bson::Uuid,
    owner_id: bson::Uuid,
    title: String,
    body: String,
    created_at: bson::DateTime,
    updated_at: bson::DateTime,
}

impl NoteDoc {
    fn into_note(self) -> RepositoryResult<Note> {
        Ok(NoteRow {
            id: from_uuid(self.id),
            owner_id: from_uuid(self.owner_id),
            title: self.title,
            body: self.body,
            created_at: from_time(self.created_at)?,
            updated_at: from_time(self.updated_at)?,
        }
        .into())
    }
}

#[derive(Serialize, Deserialize)]
struct RefreshTokenDoc {
    #[serde(rename = "_id")]
    id: bson::Uuid,
    user_id: bson::Uuid,
    token_hash: String,
    family: bson::Uuid,
    expires_at: bson::DateTime,
    used_at: Option<bson::DateTime>,
    revoked: bool,
    created_at: bson::DateTime,
}

impl RefreshTokenDoc {
    fn into_record(self) -> RepositoryResult<RefreshTokenRecord> {
        Ok(RefreshTokenRecord {
            id: from_uuid(self.id),
            user_id: from_uuid(self.user_id),
            token_hash: self.token_hash,
            family: from_uuid(self.family),
            expires_at: from_time(self.expires_at)?,
            used_at: self.used_at.map(from_time).transpose()?,
            revoked: self.revoked,
            created_at: from_time(self.created_at)?,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct AccessTokenDoc {
    #[serde(rename = "_id")]
    id: bson::Uuid,
    user_id: bson::Uuid,
    token_hash: String,
    session: bson::Uuid,
    role: String,
    expires_at: bson::DateTime,
    created_at: bson::DateTime,
}

impl AccessTokenDoc {
    fn into_record(self) -> RepositoryResult<AccessTokenRecord> {
        Ok(AccessTokenRecord {
            id: from_uuid(self.id),
            user_id: from_uuid(self.user_id),
            token_hash: self.token_hash,
            session: from_uuid(self.session),
            role: self.role,
            expires_at: from_time(self.expires_at)?,
            created_at: from_time(self.created_at)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Repositories
// ---------------------------------------------------------------------------

pub struct MongoUserRepository {
    users: Collection<UserDoc>,
}

impl MongoUserRepository {
    pub fn new(database: &Database) -> Self {
        Self {
            users: database.collection(USERS),
        }
    }

    async fn set(&self, id: Uuid, mut fields: bson::Document) -> RepositoryResult<()> {
        fields.insert("updated_at", to_time(Utc::now()));
        self.users
            .update_one(doc! { "_id": to_uuid(id) }, doc! { "$set": fields })
            .await
            .map_err(translate)?;
        Ok(())
    }
}

#[async_trait]
impl UserRepository for MongoUserRepository {
    async fn insert(&self, user: NewUser) -> RepositoryResult<User> {
        let now = to_time(Utc::now());
        let document = UserDoc {
            id: to_uuid(user.id),
            email: user.email,
            password_hash: user.password_hash,
            role: user.role.as_str().to_owned(),
            failed_attempts: 0,
            locked_until: None,
            created_at: now,
            updated_at: now,
        };

        // The unique index on `email` created in `ensure_indexes` is what
        // enforces the contract on the trait; `translate` turns its violation
        // into `Conflict`.
        self.users.insert_one(&document).await.map_err(translate)?;

        // Converted from what was written rather than re-read: the value is
        // already the stored one, millisecond truncation included.
        document.into_user()
    }

    async fn find_by_id(&self, id: Uuid) -> RepositoryResult<Option<User>> {
        let found = self
            .users
            .find_one(doc! { "_id": to_uuid(id) })
            .await
            .map_err(translate)?;
        found.map(UserDoc::into_user).transpose()
    }

    async fn find_by_email(&self, email: &str) -> RepositoryResult<Option<User>> {
        let found = self
            .users
            .find_one(doc! { "email": email })
            .await
            .map_err(translate)?;
        found.map(UserDoc::into_user).transpose()
    }

    async fn record_failed_login(
        &self,
        id: Uuid,
        attempts: i64,
        locked_until: Option<DateTime<Utc>>,
    ) -> RepositoryResult<()> {
        self.set(
            id,
            doc! {
                "failed_attempts": attempts,
                "locked_until": locked_until.map(to_time).map_or(Bson::Null, Bson::from),
            },
        )
        .await
    }

    async fn clear_login_failures(&self, id: Uuid) -> RepositoryResult<()> {
        self.set(
            id,
            doc! { "failed_attempts": 0_i64, "locked_until": Bson::Null },
        )
        .await
    }

    async fn update_password_hash(&self, id: Uuid, password_hash: &str) -> RepositoryResult<()> {
        self.set(id, doc! { "password_hash": password_hash }).await
    }

    async fn set_role(&self, id: Uuid, role: Role) -> RepositoryResult<()> {
        self.set(id, doc! { "role": role.as_str() }).await
    }
}

pub struct MongoNoteRepository {
    notes: Collection<NoteDoc>,
}

impl MongoNoteRepository {
    pub fn new(database: &Database) -> Self {
        Self {
            notes: database.collection(NOTES),
        }
    }
}

#[async_trait]
impl NoteRepository for MongoNoteRepository {
    async fn insert(&self, note: NewNote) -> RepositoryResult<Note> {
        let now = to_time(Utc::now());
        let document = NoteDoc {
            id: to_uuid(note.id),
            owner_id: to_uuid(note.owner_id),
            title: note.title,
            body: note.body,
            created_at: now,
            updated_at: now,
        };

        self.notes.insert_one(&document).await.map_err(translate)?;

        document.into_note()
    }

    async fn find_owned(&self, id: Uuid, owner_id: Uuid) -> RepositoryResult<Option<Note>> {
        // Both halves of the filter, always: the owner is the authorisation
        // check, not a hint.
        let found = self
            .notes
            .find_one(doc! { "_id": to_uuid(id), "owner_id": to_uuid(owner_id) })
            .await
            .map_err(translate)?;
        found.map(NoteDoc::into_note).transpose()
    }

    async fn list_owned(
        &self,
        owner_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> RepositoryResult<Vec<Note>> {
        // `_id` breaks ties within a millisecond; see the module note on
        // timestamp precision.
        let documents: Vec<NoteDoc> = self
            .notes
            .find(doc! { "owner_id": to_uuid(owner_id) })
            .sort(doc! { "created_at": -1, "_id": 1 })
            .skip(offset.max(0) as u64)
            .limit(limit)
            .await
            .map_err(translate)?
            .try_collect()
            .await
            .map_err(translate)?;

        documents.into_iter().map(NoteDoc::into_note).collect()
    }

    async fn count_owned(&self, owner_id: Uuid) -> RepositoryResult<i64> {
        let count = self
            .notes
            .count_documents(doc! { "owner_id": to_uuid(owner_id) })
            .await
            .map_err(translate)?;
        i64::try_from(count).map_err(|_| {
            RepositoryError::Backend(anyhow!("note count {count} does not fit in an i64"))
        })
    }

    async fn update_owned(
        &self,
        id: Uuid,
        owner_id: Uuid,
        title: &str,
        body: &str,
    ) -> RepositoryResult<Option<Note>> {
        // One round trip, and atomic: the document either matched the owner
        // filter and comes back updated, or it did not exist and comes back
        // `None`. No read-then-write window.
        let updated = self
            .notes
            .find_one_and_update(
                doc! { "_id": to_uuid(id), "owner_id": to_uuid(owner_id) },
                doc! { "$set": {
                    "title": title,
                    "body": body,
                    "updated_at": to_time(Utc::now()),
                }},
            )
            .return_document(ReturnDocument::After)
            .await
            .map_err(translate)?;

        updated.map(NoteDoc::into_note).transpose()
    }

    async fn delete_owned(&self, id: Uuid, owner_id: Uuid) -> RepositoryResult<bool> {
        let result = self
            .notes
            .delete_one(doc! { "_id": to_uuid(id), "owner_id": to_uuid(owner_id) })
            .await
            .map_err(translate)?;
        Ok(result.deleted_count == 1)
    }
}

pub struct MongoTokenRepository {
    tokens: Collection<RefreshTokenDoc>,
}

impl MongoTokenRepository {
    pub fn new(database: &Database) -> Self {
        Self {
            tokens: database.collection(REFRESH_TOKENS),
        }
    }
}

#[async_trait]
impl TokenRepository for MongoTokenRepository {
    async fn insert(&self, token: NewRefreshToken) -> RepositoryResult<()> {
        self.tokens
            .insert_one(RefreshTokenDoc {
                id: to_uuid(token.id),
                user_id: to_uuid(token.user_id),
                token_hash: token.token_hash,
                family: to_uuid(token.family),
                expires_at: to_time(token.expires_at),
                used_at: None,
                revoked: false,
                created_at: to_time(Utc::now()),
            })
            .await
            .map_err(translate)?;
        Ok(())
    }

    async fn find_by_hash(&self, token_hash: &str) -> RepositoryResult<Option<RefreshTokenRecord>> {
        let found = self
            .tokens
            .find_one(doc! { "token_hash": token_hash })
            .await
            .map_err(translate)?;
        found.map(RefreshTokenDoc::into_record).transpose()
    }

    async fn mark_used(&self, id: Uuid) -> RepositoryResult<bool> {
        // A single-document update is atomic in MongoDB, and the `used_at`
        // guard is inside the filter, so of two concurrent refreshes exactly
        // one matches. That is the single-shot redemption the contract
        // requires; a read-then-write pair here would hand two clients a
        // session from one stolen token.
        let redeemed = self
            .tokens
            .find_one_and_update(
                doc! { "_id": to_uuid(id), "used_at": Bson::Null, "revoked": false },
                doc! { "$set": { "used_at": to_time(Utc::now()) } },
            )
            .await
            .map_err(translate)?;

        Ok(redeemed.is_some())
    }

    async fn revoke_family(&self, family: Uuid) -> RepositoryResult<()> {
        self.tokens
            .update_many(
                doc! { "family": to_uuid(family) },
                doc! { "$set": { "revoked": true } },
            )
            .await
            .map_err(translate)?;
        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: Uuid) -> RepositoryResult<()> {
        self.tokens
            .update_many(
                doc! { "user_id": to_uuid(user_id) },
                doc! { "$set": { "revoked": true } },
            )
            .await
            .map_err(translate)?;
        Ok(())
    }
}

#[async_trait]
impl ExpiredTokenSweeper for MongoTokenRepository {
    async fn delete_expired(&self, now: DateTime<Utc>) -> RepositoryResult<u64> {
        let result = self
            .tokens
            .delete_many(doc! { "expires_at": { "$lt": to_time(now) } })
            .await
            .map_err(translate)?;
        Ok(result.deleted_count)
    }
}

pub struct MongoAccessTokenRepository {
    tokens: Collection<AccessTokenDoc>,
}

impl MongoAccessTokenRepository {
    pub fn new(database: &Database) -> Self {
        Self {
            tokens: database.collection(ACCESS_TOKENS),
        }
    }
}

#[async_trait]
impl AccessTokenRepository for MongoAccessTokenRepository {
    async fn insert(&self, token: NewAccessToken) -> RepositoryResult<()> {
        self.tokens
            .insert_one(AccessTokenDoc {
                id: to_uuid(token.id),
                user_id: to_uuid(token.user_id),
                token_hash: token.token_hash,
                session: to_uuid(token.session),
                role: token.role,
                expires_at: to_time(token.expires_at),
                created_at: to_time(Utc::now()),
            })
            .await
            .map_err(translate)?;
        Ok(())
    }

    async fn find_by_hash(&self, token_hash: &str) -> RepositoryResult<Option<AccessTokenRecord>> {
        let found = self
            .tokens
            .find_one(doc! { "token_hash": token_hash })
            .await
            .map_err(translate)?;
        found.map(AccessTokenDoc::into_record).transpose()
    }

    async fn delete_by_session(&self, session: Uuid) -> RepositoryResult<()> {
        self.tokens
            .delete_many(doc! { "session": to_uuid(session) })
            .await
            .map_err(translate)?;
        Ok(())
    }

    async fn delete_all_for_user(&self, user_id: Uuid) -> RepositoryResult<()> {
        self.tokens
            .delete_many(doc! { "user_id": to_uuid(user_id) })
            .await
            .map_err(translate)?;
        Ok(())
    }
}

#[async_trait]
impl ExpiredTokenSweeper for MongoAccessTokenRepository {
    async fn delete_expired(&self, now: DateTime<Utc>) -> RepositoryResult<u64> {
        let result = self
            .tokens
            .delete_many(doc! { "expires_at": { "$lt": to_time(now) } })
            .await
            .map_err(translate)?;
        Ok(result.deleted_count)
    }
}

pub struct MongoHealthRepository {
    database: Database,
}

impl MongoHealthRepository {
    pub fn new(database: Database) -> Self {
        Self { database }
    }
}

#[async_trait]
impl HealthRepository for MongoHealthRepository {
    async fn ping(&self) -> RepositoryResult<()> {
        // The SQL backends round-trip `SELECT 1`; this is the same idea —
        // cheap, and it still proves a server was selected and answered.
        self.database
            .run_command(doc! { "ping": 1 })
            .await
            .map_err(translate)?;
        Ok(())
    }
}
