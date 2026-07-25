//! Structured logging.
//!
//! Production emits JSON so a log pipeline can index it; development emits a
//! human-readable format. Neither ever receives credentials — the sensitive
//! header layer strips them before `TraceLayer` sees the request.

use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use crate::config::Environment;

pub fn init(environment: Environment) {
    let filter = EnvFilter::try_from_env("APP_LOG").unwrap_or_else(|_| {
        // `tower_http=debug` gives one line per request without being noisy.
        EnvFilter::new("info,axum_secure_starter=info,tower_http=info,sqlx=warn")
    });

    let registry = tracing_subscriber::registry().with(filter);

    if environment.is_production() {
        registry
            .with(
                fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_current_span(true),
            )
            .init();
    } else {
        registry.with(fmt::layer().with_target(true)).init();
    }
}
