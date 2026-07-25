//! Domain entities. Plain data plus the invariants that belong to the data
//! itself; anything requiring collaborators lives in `service`.

pub mod note;
pub mod user;

pub use note::Note;
pub use user::{Role, User};
