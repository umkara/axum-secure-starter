//! The plugins Bastion ships with.
//!
//! Each one is additive: it either adds a layer at a [`super::Stage`] or a
//! pre-routing [`super::RequestFilter`], and none of them can weaken a core
//! control. See the module documentation of [`super`] for why that holds
//! structurally rather than by convention.

mod cors;
mod guards;
mod rate_limit;
mod request_log;

pub use cors::Cors;
pub use guards::{ContentTypeGuard, HostGuard, MethodGuard, PathGuard};
pub use rate_limit::RateLimit;
pub use request_log::RequestLog;
