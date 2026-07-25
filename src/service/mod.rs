//! Business logic.
//!
//! One service per cohesive responsibility, rather than one per aggregate:
//!
//! * [`AccountService`] — who someone is: registration, credentials, lockout.
//! * [`SessionService`] — what a session may do: issuing, rotation, revocation.
//! * [`AuthService`] — the composition of those two into use cases.
//! * [`NoteService`] — the resource this API happens to serve.
//! * [`TokenJanitor`] — the scheduled sweep, which is not a use case at all.
//!
//! Services own policy and orchestration; handlers stay thin and repositories
//! stay dumb.

pub mod account_service;
pub mod auth_service;
#[cfg(test)]
pub mod fakes;
pub mod note_service;
pub mod session_service;
pub mod token_janitor;

pub use account_service::{AccountService, AdminBootstrap};
pub use auth_service::AuthService;
pub use note_service::{NoteService, Page};
pub use session_service::{AuthTokens, SessionService};
pub use token_janitor::TokenJanitor;
