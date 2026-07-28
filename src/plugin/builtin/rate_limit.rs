//! Per-client rate limiting.
//!
//! Two instances of one plugin: [`RateLimit::credentials`] guards register,
//! login, refresh and logout with a tight bucket, and [`RateLimit::api`] gives
//! the rest of the API a looser one. Two instances rather than one plugin that
//! inspects paths — the router already knows which routes are which, and a
//! limiter that re-derives that from the URI is a second copy of the routing
//! table waiting to disagree with the first.
//!
//! Health probes are reachable from neither: they live outside both stages, so
//! a traffic spike cannot starve the orchestrator's liveness check into a
//! restart loop.
//!
//! # It cannot be switched off in production
//!
//! This is the one built-in whose absence genuinely weakens the server, which
//! is why `APP_PLUGIN_RATE_LIMIT_ENABLED=false` is refused when `APP_ENV` is
//! `production`. Development gets to turn it off; production does not. The
//! precedent is TLS, which `crate::config` already refuses to start without.

use tower_governor::{
    GovernorLayer, governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor,
};

use crate::{
    config::Environment,
    plugin::{Plugin, PluginCx, PluginError, Plugins, RouteLayer, Stage},
};

/// Which bucket an instance installs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tier {
    Credentials,
    Api,
}

/// Per-client rate limiting for one tier of routes.
#[derive(Debug, Clone, Copy)]
pub struct RateLimit(Tier);

impl RateLimit {
    /// The tight bucket, on the credential endpoints.
    pub fn credentials() -> Self {
        Self(Tier::Credentials)
    }

    /// The general bucket, on the rest of the API.
    pub fn api() -> Self {
        Self(Tier::Api)
    }
}

impl Plugin for RateLimit {
    fn name(&self) -> &'static str {
        // One name, so one `APP_PLUGIN_RATE_LIMIT_ENABLED` switches both tiers.
        // Splitting them would let somebody disable the credential bucket and
        // leave the general one on, which reads like a safe change and is not.
        "rate-limit"
    }

    fn stage(&self) -> Stage {
        match self.0 {
            Tier::Credentials => Stage::Credentials,
            Tier::Api => Stage::Api,
        }
    }

    fn layer(&self, cx: &PluginCx<'_>) -> Result<Option<RouteLayer>, PluginError> {
        let config = cx.config();

        if !cx.enabled(true)? {
            if config.environment == Environment::Production {
                return Err(cx.invalid(
                    "ENABLED",
                    "rate limiting cannot be disabled in production; \
                     unset APP_ENV or run with APP_ENV=development to do this locally",
                ));
            }
            return Ok(None);
        }

        let (per_second, burst) = match self.0 {
            Tier::Credentials => (
                config.rate_limit.auth_per_second,
                config.rate_limit.auth_burst,
            ),
            Tier::Api => (
                config.rate_limit.global_per_second,
                config.rate_limit.global_burst,
            ),
        };

        // Client identity comes from the socket address unless the deployment
        // has declared that it sits behind a trusted proxy. Honouring
        // `X-Forwarded-For` otherwise lets any client forge its identity and
        // bypass the limit outright.
        let layer = if config.security.trust_proxy_headers {
            let governor = GovernorConfigBuilder::default()
                .per_second(per_second)
                .burst_size(burst)
                .key_extractor(SmartIpKeyExtractor)
                .finish()
                .ok_or_else(|| cx.invalid("burst", "the rate limit configuration is not valid"))?;
            Plugins::erase(GovernorLayer::new(governor))
        } else {
            let governor = GovernorConfigBuilder::default()
                .per_second(per_second)
                .burst_size(burst)
                .finish()
                .ok_or_else(|| cx.invalid("burst", "the rate limit configuration is not valid"))?;
            Plugins::erase(GovernorLayer::new(governor))
        };

        Ok(Some(layer))
    }
}
