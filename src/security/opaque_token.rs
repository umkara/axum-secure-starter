//! Opaque refresh tokens.
//!
//! The token itself is 32 bytes of CSPRNG output, shown to the client once and
//! never stored. The database keeps only a SHA-256 digest, so a dump of the
//! token table cannot be replayed. Lookups are by digest, which is a constant
//! -length value and safe to index.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const TOKEN_BYTES: usize = 32;

/// A freshly minted refresh token: the secret for the client, the digest for us.
pub struct FreshToken {
    pub secret: String,
    pub digest: String,
}

pub fn generate() -> FreshToken {
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::fill(&mut bytes);
    let secret = URL_SAFE_NO_PAD.encode(bytes);
    let digest = digest_of(&secret);
    FreshToken { secret, digest }
}

pub fn digest_of(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compares two digests without leaking their difference through timing.
pub fn digests_match(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}
