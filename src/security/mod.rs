//! Security primitives: hashing, tokens, request authentication, and the
//! response headers applied to the whole surface.

pub mod extract;
pub mod headers;
pub mod jwt;
pub mod opaque_token;
pub mod password;

// Only the traits are re-exported. `JwtCodec` and `Argon2Hasher` are
// `pub(crate)` and deliberately absent: depending on a concrete implementation
// should require reaching for it on purpose, and the only place entitled to do
// that is `state.rs`, where the wiring lives.
pub use extract::{AdminUser, CurrentUser};
pub use jwt::TokenIssuer;
pub use password::CredentialHasher;
