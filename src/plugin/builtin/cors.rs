//! Cross-origin resource sharing.
//!
//! This is the reference plugin: it was part of the hard-wired stack, and it
//! moved out without changing what the server does. It qualifies as a plugin
//! for one specific reason — removing it is *strictly more restrictive*. With
//! no layer at all no `Access-Control-Allow-Origin` is emitted, so a browser
//! refuses the cross-origin request. A plugin whose absence loosened anything
//! would have had to stay in the core.

use std::time::Duration;

use axum::http::{HeaderValue, Method, header};
use tower_http::cors::CorsLayer;

use crate::{
    api::REQUEST_ID_HEADER,
    plugin::{Plugin, PluginCx, PluginError, RouteLayer, Stage},
};

/// Wraps every route in the configured CORS policy.
#[derive(Debug, Clone, Copy, Default)]
pub struct Cors;

impl Plugin for Cors {
    fn name(&self) -> &'static str {
        "cors"
    }

    fn stage(&self) -> Stage {
        Stage::Outer
    }

    fn layer(&self, cx: &PluginCx<'_>) -> Result<Option<RouteLayer>, PluginError> {
        if !cx.enabled(true)? {
            return Ok(None);
        }

        let origins = &cx.config().security.cors_allowed_origins;

        // No origins configured: same-origin only. That is the default, and it
        // is the safe one — an API with no browser clients needs no CORS, so
        // the plugin installs nothing rather than an empty policy.
        if origins.is_empty() {
            return Ok(None);
        }

        // Re-checked here and not only in `crate::config`: an embedder that
        // builds `AppConfig` in code never passes through `from_env`, and this
        // is the setting where a wildcard costs the most.
        if origins.iter().any(|origin| origin == "*") {
            return Err(cx.invalid(
                "origins",
                "wildcard origins are not allowed; list exact origins",
            ));
        }

        let mut parsed = Vec::with_capacity(origins.len());
        for origin in origins {
            // A typo used to fall through `filter_map(..ok())` and silently
            // become same-origin-only. Safe, but silent: a refusal to boot is
            // the house style, and a frontend that cannot talk to its API is
            // better discovered at deploy time than in a browser console.
            parsed.push(origin.parse::<HeaderValue>().map_err(|error| {
                cx.invalid(
                    "origins",
                    format!("`{origin}` is not a valid origin: {error}"),
                )
            })?);
        }

        let max_age: u64 = cx.parse_or("MAX_AGE_SECS", 600)?;
        if max_age > 86_400 {
            return Err(cx.invalid(
                "MAX_AGE_SECS",
                "must not exceed 86400; a longer preflight cache outlives most policy changes",
            ));
        }

        let layer = CorsLayer::new()
            .allow_origin(parsed)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                REQUEST_ID_HEADER,
            ])
            .expose_headers([REQUEST_ID_HEADER])
            // Credentials travel in the Authorization header, not cookies, so
            // credentialed CORS is not needed. Not configurable either: this is
            // the single setting that turns an origin list into a surface for
            // riding somebody else's session.
            .allow_credentials(false)
            .max_age(Duration::from_secs(max_age));

        Ok(Some(crate::plugin::Plugins::erase(layer)))
    }
}
