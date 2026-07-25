//! Password hashing with Argon2id.
//!
//! Parameters follow the OWASP Password Storage Cheat Sheet (19 MiB memory,
//! 2 iterations, 1 lane).
//!
//! Two separate resource problems have to be handled here, and only the first
//! is obvious:
//!
//! * Hashing is deliberately slow, so it runs on a blocking thread rather than
//!   on the async runtime — otherwise a burst of logins would stall unrelated
//!   request processing.
//! * Moving it to the blocking pool bounds nothing on its own. The pool is
//!   hundreds of threads deep, each Argon2 call reserves 19 MiB, and an
//!   unauthenticated request is what triggers it. A few hundred bytes of
//!   request buys seconds of CPU and megabytes of memory: an attacker with a
//!   handful of source addresses can exhaust the machine while every per-IP
//!   rate limit is still satisfied. [`Hasher`] therefore admits a bounded
//!   number of concurrent hashes; the rest wait, and the request timeout sheds
//!   them rather than letting the queue grow without limit.

use std::sync::{Arc, LazyLock};

use anyhow::{Context, anyhow};
use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::SaltString,
};
use async_trait::async_trait;
use tokio::sync::Semaphore;

use crate::error::{AppError, AppResult};

const MEMORY_KIB: u32 = 19 * 1024;
const ITERATIONS: u32 = 2;
const PARALLELISM: u32 = 1;
/// 128 bits, the value recommended by RFC 9106.
const SALT_BYTES: usize = 16;

/// Peak memory one in-flight hash reserves. Used to report the ceiling at
/// start-up, so the bound is a number an operator can reason about.
pub const MEMORY_PER_HASH_BYTES: usize = (MEMORY_KIB as usize) * 1024;

/// Draws a fresh salt from the OS CSPRNG.
fn new_salt() -> SaltString {
    let mut bytes = [0u8; SALT_BYTES];
    rand::fill(&mut bytes);
    SaltString::encode_b64(&bytes).expect("a 16-byte salt is within the PHC length limits")
}

/// A hash of a password nobody knows. Verifying against it burns the same CPU
/// as a real check, which keeps login timing identical whether or not the
/// account exists — closing a user-enumeration side channel.
static DUMMY_HASH: LazyLock<String> = LazyLock::new(|| {
    argon2()
        .hash_password(b"argon2id-timing-equalisation-placeholder", &new_salt())
        .expect("hashing a constant with valid params cannot fail")
        .to_string()
});

fn argon2() -> Argon2<'static> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, None)
        .expect("Argon2 parameters are within valid ranges");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// What the rest of the application needs from password hashing.
///
/// Services depend on this, not on Argon2. Hashing is deliberately slow, which
/// makes a real hasher the wrong collaborator for tests that are about
/// something else — lockout counting, token rotation — so those substitute an
/// instant implementation and stay in the millisecond range.
#[async_trait]
pub trait CredentialHasher: Send + Sync + 'static {
    async fn hash(&self, plaintext: String) -> AppResult<String>;
    async fn verify(&self, plaintext: String, stored_hash: String) -> AppResult<bool>;
    /// Performs the same work as [`CredentialHasher::verify`] against a
    /// throwaway hash. Called on the "no such user" path so both paths cost the
    /// same and account existence cannot be timed.
    async fn verify_dummy(&self, plaintext: String) -> AppResult<()>;
}

/// Argon2id with admission control.
///
/// Cloning shares the same budget: the limit is per process, which is the unit
/// that actually runs out of CPU and memory.
#[derive(Clone)]
pub(crate) struct Argon2Hasher {
    permits: Arc<Semaphore>,
}

impl Argon2Hasher {
    /// `limit` is the number of hashes allowed to run at once. Sizing it to the
    /// core count keeps the machine busy without oversubscribing: extra
    /// concurrent hashes do not add throughput, they just multiply resident
    /// memory and slow every hash already running.
    pub fn new(limit: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(limit.max(1))),
        }
    }

    /// Waits for a slot. Callers are inside a request, so the request timeout
    /// bounds this wait and turns a saturated hasher into shed load rather than
    /// an unbounded queue.
    async fn acquire(&self) -> AppResult<tokio::sync::SemaphorePermit<'_>> {
        self.permits
            .acquire()
            .await
            .map_err(|_| AppError::Internal(anyhow!("the password hasher was shut down")))
    }
}

#[async_trait]
impl CredentialHasher for Argon2Hasher {
    /// Returns a PHC string that embeds salt and parameters, so stored hashes
    /// remain verifiable after a future parameter change.
    async fn hash(&self, plaintext: String) -> AppResult<String> {
        let _permit = self.acquire().await?;

        tokio::task::spawn_blocking(move || {
            argon2()
                .hash_password(plaintext.as_bytes(), &new_salt())
                .map(|h| h.to_string())
                .map_err(|e| anyhow!("failed to hash password: {e}"))
        })
        .await
        .context("password hashing task panicked")
        .map_err(AppError::Internal)?
        .map_err(AppError::Internal)
    }

    /// A malformed stored hash is reported as "does not match" rather than as
    /// an error: it must never be distinguishable from a wrong password.
    async fn verify(&self, plaintext: String, stored_hash: String) -> AppResult<bool> {
        let _permit = self.acquire().await?;

        tokio::task::spawn_blocking(move || {
            let Ok(parsed) = PasswordHash::new(&stored_hash) else {
                tracing::error!("stored password hash is malformed");
                return false;
            };
            argon2()
                .verify_password(plaintext.as_bytes(), &parsed)
                .is_ok()
        })
        .await
        .context("password verification task panicked")
        .map_err(AppError::Internal)
    }

    async fn verify_dummy(&self, plaintext: String) -> AppResult<()> {
        let _ = self.verify(plaintext, DUMMY_HASH.clone()).await?;
        Ok(())
    }
}

/// The default bound: one hash per available core.
pub fn default_limit() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}
