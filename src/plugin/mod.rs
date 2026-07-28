//! Middleware plugins.
//!
//! The stack in [`crate::api::build_router`] is assembled once so that the
//! protections applying to every request cannot be forgotten on an individual
//! route. That is worth keeping, and it is also why there was no way to add
//! middleware without editing that function. Plugins are the seam.
//!
//! # Plugins are additive
//!
//! A plugin may add a layer at one of the [`Stage`]s, or a pre-routing
//! [`RequestFilter`], and nothing else. It cannot remove, replace or reorder a
//! core control, because every stage sits *inside* the core hardening:
//!
//! ```text
//! CatchPanic ─ request id ─ sensitive headers ─ the eight hardening headers
//!   └── [Stage::Outer]
//!         └── HandleError ─ load shed ─ concurrency ─ timeout ─ body limits
//!               └── router ─ [Stage::Api] on /api/v1, [Stage::Page] on pages
//! ```
//!
//! Two mechanisms make that structural rather than conventional. The header
//! layers use `SetResponseHeaderLayer::overriding` and run outside every slot,
//! so a plugin that strips a header has it written back on the way out. And
//! [`RouteLayer`] pins `Error = Infallible`, so a plugin cannot produce the
//! error that `HandleErrorLayer` exists to catch and can never land between it
//! and the load shedder.
//!
//! # Order comes from source
//!
//! A plugin declares its stage; order within a stage is the order plugins were
//! registered in [`Registry::builtin`]. Configuration can switch a plugin off
//! and tune it. It cannot reorder the stack, because a reordering that boots is
//! a reordering nobody reviewed.

pub mod builtin;

use std::{
    collections::BTreeMap,
    convert::Infallible,
    future::Future,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{
    Router,
    extract::Request,
    http::{HeaderMap, Method, Uri, Version},
    response::{IntoResponse, Response},
    routing::Route,
};
use tower::{Layer, Service, util::BoxCloneSyncServiceLayer};

use crate::{config::AppConfig, error::AppError};

/// Where a plugin's layer is inserted.
///
/// Non-exhaustive so that adding a slot later is not a breaking change. What a
/// stage *cannot* express is deliberate: there is no slot outside the hardening
/// headers, and none between `HandleErrorLayer` and the load shedder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Stage {
    /// Around every route — API, health probes and pages alike.
    ///
    /// A plugin here observes the 408, 413 and 503 the availability controls
    /// produce. It must not try to read the request body: the body limits sit
    /// below this point and have not run yet.
    Outer,
    /// The authenticated `/api/v1` routes — notes, admin, password change —
    /// inside the API's `default-src 'none'` policy and `no-store`.
    ///
    /// Health probes are **not** here. They sit in their own branch precisely
    /// so that nothing installed at a stage can starve an orchestrator's
    /// liveness check.
    Api,
    /// The credential endpoints only: register, login, refresh, logout.
    ///
    /// Separate from [`Stage::Api`] because these four are where the expensive,
    /// unauthenticated work happens, and they have always carried a tighter
    /// budget than the rest of the API. A plugin that should treat them
    /// differently — a limiter, an audit log — registers here.
    Credentials,
    /// The static-file branch only, inside the page policy and the asset cache.
    Page,
}

impl Stage {
    const ALL: [Stage; 4] = [Stage::Outer, Stage::Api, Stage::Credentials, Stage::Page];
}

/// A tower layer with its type erased, so plugins of different shapes can share
/// one list.
///
/// `Error = Infallible` is not a simplification — `Router::layer` requires it.
/// A plugin contributing a fallible layer has to handle its own errors, which
/// is what keeps the core's `HandleErrorLayer` welded to the load shedder.
pub type RouteLayer = BoxCloneSyncServiceLayer<Route, Request, Response, Infallible>;

/// The part of a request a pre-routing check may see: the head, never the body,
/// and never mutably.
#[derive(Clone, Copy, Debug)]
pub struct RequestHead<'a> {
    pub method: &'a Method,
    pub uri: &'a Uri,
    pub headers: &'a HeaderMap,
    pub version: Version,
}

/// A check that runs before the router has matched a path.
///
/// Deliberately not a [`Layer`]. A layer at this position could rewrite the URI
/// and so undo the canonicalisation below it — rewriting `//notes` to `/notes`
/// destroys the evidence [`crate::api::path::CanonicalPathLayer`] needs, which
/// is the one way a plugin could make the server *less* strict. A check that
/// can only return `Err` cannot.
pub trait RequestFilter: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    /// `Ok(())` lets the request through; `Err` answers it immediately.
    fn check(&self, head: RequestHead<'_>) -> Result<(), AppError>;
}

/// A middleware plugin.
///
/// Implementations are registered in code and tuned by configuration. See the
/// module documentation for what a plugin can and cannot do.
pub trait Plugin: Send + Sync + 'static {
    /// Stable identifier in kebab-case. Also the environment prefix:
    /// `"request-log"` reads `APP_PLUGIN_REQUEST_LOG_*`.
    fn name(&self) -> &'static str;

    /// Where [`Plugin::layer`] is installed. Irrelevant for a filter-only
    /// plugin.
    fn stage(&self) -> Stage {
        Stage::Outer
    }

    /// Reads and validates settings, and returns the layer to install.
    ///
    /// `Ok(None)` means configured off: the plugin contributes nothing and
    /// costs nothing at run time. `Err` aborts start-up, which is the rule
    /// [`crate::config`] already follows — a misconfigured server should fail
    /// to boot rather than fail open later.
    fn layer(&self, cx: &PluginCx<'_>) -> Result<Option<RouteLayer>, PluginError> {
        let _ = cx;
        Ok(None)
    }

    /// Reads and validates settings, and returns a pre-routing check.
    fn filter(&self, cx: &PluginCx<'_>) -> Result<Option<Arc<dyn RequestFilter>>, PluginError> {
        let _ = cx;
        Ok(None)
    }
}

/// A plugin refused its configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("plugin `{plugin}`: {setting} is invalid: {reason}")]
pub struct PluginError {
    pub plugin: &'static str,
    pub setting: String,
    pub reason: String,
}

/// The plugin half of the environment, snapshotted once.
///
/// A map rather than `std::env` at the point of use: under edition 2024
/// `set_var` is `unsafe`, and a test that sets a variable while other tests run
/// in parallel is racy. This way a test — or an embedder that does not want
/// process environment to be the source at all — can supply settings directly.
#[derive(Debug, Clone, Default)]
pub struct Settings(BTreeMap<String, String>);

impl Settings {
    /// Every `APP_PLUGIN_*` variable in the process environment.
    pub fn from_env() -> Self {
        Self(
            std::env::vars()
                .filter(|(key, _)| key.starts_with("APP_PLUGIN_"))
                .collect(),
        )
    }

    /// No settings at all. Every plugin sees its defaults.
    pub fn empty() -> Self {
        Self(BTreeMap::new())
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.0.insert(key.into(), value.into());
    }

    fn raw(&self, prefix: &str, key: &str) -> Option<&str> {
        self.0.get(&format!("{prefix}{key}")).map(String::as_str)
    }

    /// Parses a setting, falling back to `default` when unset. A value that is
    /// present but does not parse is an error, never a silent fallback.
    fn parse_or<T>(
        &self,
        plugin: &'static str,
        prefix: &str,
        key: &str,
        default: T,
    ) -> Result<T, PluginError>
    where
        T: FromStr,
        T::Err: std::fmt::Display,
    {
        match self.raw(prefix, key) {
            Some(raw) => raw.parse().map_err(|error| PluginError {
                plugin,
                setting: format!("{prefix}{key}"),
                reason: format!("{error}"),
            }),
            None => Ok(default),
        }
    }

    /// A comma-separated setting, trimmed, with empty entries dropped.
    fn list(&self, prefix: &str, key: &str) -> Vec<&str> {
        self.raw(prefix, key)
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|entry| !entry.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// What a plugin may read while it is being resolved.
///
/// It carries the whole validated [`AppConfig`] because a plugin often needs a
/// value the core already checked. It deliberately does **not** carry
/// `AppState`: middleware that can reach the services is a route handler
/// wearing a disguise, and the layering rule in `lib.rs` says dependencies
/// point inward only.
pub struct PluginCx<'a> {
    name: &'static str,
    prefix: String,
    config: &'a AppConfig,
    settings: &'a Settings,
}

impl<'a> PluginCx<'a> {
    fn new(name: &'static str, config: &'a AppConfig, settings: &'a Settings) -> Self {
        Self {
            name,
            prefix: env_prefix(name),
            config,
            settings,
        }
    }

    pub fn config(&self) -> &'a AppConfig {
        self.config
    }

    /// `cx.raw("SAMPLE")` reads `APP_PLUGIN_<NAME>_SAMPLE`.
    pub fn raw(&self, key: &str) -> Option<&'a str> {
        self.settings.raw(&self.prefix, key)
    }

    /// Parses a setting, falling back to `default` when it is unset. A value
    /// that does not parse is an error, never a silent fallback.
    pub fn parse_or<T>(&self, key: &str, default: T) -> Result<T, PluginError>
    where
        T: FromStr,
        T::Err: std::fmt::Display,
    {
        self.settings
            .parse_or(self.name, &self.prefix, key, default)
    }

    /// `APP_PLUGIN_<NAME>_ENABLED`, defaulting to `on_by_default`.
    pub fn enabled(&self, on_by_default: bool) -> Result<bool, PluginError> {
        self.parse_or("ENABLED", on_by_default)
    }

    /// A comma-separated setting, trimmed, with empty entries dropped.
    pub fn list(&self, key: &str) -> Vec<&'a str> {
        self.settings.list(&self.prefix, key)
    }

    /// Builds the error a plugin returns when a setting is unusable.
    pub fn invalid(&self, key: &str, reason: impl Into<String>) -> PluginError {
        PluginError {
            plugin: self.name,
            setting: format!("{}{key}", self.prefix),
            reason: reason.into(),
        }
    }
}

/// `"request-log"` becomes `"APP_PLUGIN_REQUEST_LOG_"`.
fn env_prefix(name: &str) -> String {
    format!(
        "APP_PLUGIN_{}_",
        name.to_ascii_uppercase().replace('-', "_")
    )
}

/// The plugins the server will run, in the order they were registered.
pub struct Registry {
    plugins: Vec<Box<dyn Plugin>>,
    settings: Settings,
}

impl Registry {
    /// No plugins. The core hardening is unaffected: an empty registry is still
    /// a fully protected server, and a test asserts exactly that.
    pub fn empty() -> Self {
        Self {
            plugins: Vec::new(),
            settings: Settings::from_env(),
        }
    }

    /// No plugins and no environment, for tests that want a plugin's defaults
    /// regardless of what is set on the machine running them.
    pub fn bare() -> Self {
        Self {
            plugins: Vec::new(),
            settings: Settings::empty(),
        }
    }

    /// The plugins Bastion ships with, in stack order.
    ///
    /// **This list is the order.** Within a stage, a plugin registered earlier
    /// wraps one registered later; configuration can switch a plugin off but
    /// never move it.
    pub fn builtin() -> Self {
        Self::empty()
            // Pre-routing guards first: a request that never reaches the
            // router costs the least.
            .with(builtin::PathGuard)
            .with(builtin::HostGuard)
            .with(builtin::MethodGuard)
            .with(builtin::ContentTypeGuard)
            .with(builtin::RateLimit::credentials())
            .with(builtin::RateLimit::api())
            .with(builtin::Cors)
            .with(builtin::RequestLog)
    }

    #[must_use]
    pub fn with(mut self, plugin: impl Plugin) -> Self {
        self.plugins.push(Box::new(plugin));
        self
    }

    /// Overrides one setting. An explicit `set` beats the environment snapshot
    /// taken when the registry was created.
    #[must_use]
    pub fn set(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.settings.set(key, value);
        self
    }

    /// Resolves every plugin against the configuration, once, before anything
    /// is served. A plugin that refuses its settings stops the server here.
    pub fn resolve(self, config: &AppConfig) -> Result<Plugins, PluginError> {
        let mut stages: BTreeMap<usize, Vec<RouteLayer>> = BTreeMap::new();
        let mut filters: Vec<Arc<dyn RequestFilter>> = Vec::new();
        let mut enabled: Vec<&'static str> = Vec::new();

        for plugin in &self.plugins {
            let cx = PluginCx::new(plugin.name(), config, &self.settings);
            let mut contributed = false;

            if let Some(layer) = plugin.layer(&cx)? {
                stages
                    .entry(stage_index(plugin.stage()))
                    .or_default()
                    .push(layer);
                contributed = true;
            }

            if let Some(filter) = plugin.filter(&cx)? {
                filters.push(filter);
                contributed = true;
            }

            if contributed {
                enabled.push(plugin.name());
            }
        }

        Ok(Plugins {
            stages: Stage::ALL
                .map(|stage| stages.remove(&stage_index(stage)).unwrap_or_default())
                .map(Arc::from),
            filters: filters.into(),
            enabled: enabled.into(),
        })
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::empty()
    }
}

fn stage_index(stage: Stage) -> usize {
    match stage {
        Stage::Outer => 0,
        Stage::Api => 1,
        Stage::Credentials => 2,
        Stage::Page => 3,
    }
}

/// Plugins resolved against configuration and ready to install. Cheap to clone.
#[derive(Clone)]
pub struct Plugins {
    stages: [Arc<[RouteLayer]>; 4],
    filters: Arc<[Arc<dyn RequestFilter>]>,
    enabled: Arc<[&'static str]>,
}

impl Plugins {
    /// Nothing registered.
    pub fn none() -> Self {
        Self {
            stages: [
                Arc::from(vec![]),
                Arc::from(vec![]),
                Arc::from(vec![]),
                Arc::from(vec![]),
            ],
            filters: Vec::new().into(),
            enabled: Vec::new().into(),
        }
    }

    /// The names of the plugins that contributed something, for the start-up
    /// log line.
    pub fn enabled(&self) -> &[&'static str] {
        &self.enabled
    }

    pub fn filters(&self) -> Arc<[Arc<dyn RequestFilter>]> {
        self.filters.clone()
    }

    fn stage(&self, stage: Stage) -> &[RouteLayer] {
        &self.stages[stage_index(stage)]
    }

    pub(crate) fn is_empty(&self, stage: Stage) -> bool {
        self.stage(stage).is_empty()
    }

    /// Applies one stage to a router.
    ///
    /// Registration order is outermost-first, so the list is walked backwards:
    /// each `layer` call wraps what is already there. An empty stage returns the
    /// router untouched, so an unused slot costs nothing at run time.
    pub(crate) fn apply<S>(&self, stage: Stage, mut router: Router<S>) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        for layer in self.stage(stage).iter().rev() {
            router = router.layer(layer.clone());
        }
        router
    }

    /// Erases a concrete layer so it can be stored beside plugins of other
    /// shapes.
    ///
    /// The `Sync` bound is axum's, not ours — `Router::layer` demands it of
    /// every layer, erased or not.
    pub fn erase<L>(layer: L) -> RouteLayer
    where
        L: Layer<Route> + Send + Sync + 'static,
        L::Service: Service<Request, Response = Response, Error = Infallible> + Clone + Send + Sync,
        <L::Service as Service<Request>>::Future: Send + 'static,
    {
        BoxCloneSyncServiceLayer::new(layer)
    }
}

impl std::fmt::Debug for Plugins {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plugins")
            .field("enabled", &self.enabled)
            .field("filters", &self.filters.len())
            .finish()
    }
}

/// Runs the registered pre-routing checks, then hands off.
///
/// The position is the core's; plugins supply only the checks. Sits above
/// [`crate::api::path::CanonicalPathLayer`] so a filter sees the URI the client
/// actually sent, while canonicalisation still runs underneath regardless of
/// what any filter decides.
#[derive(Clone)]
pub struct RequestFilterLayer(Arc<[Arc<dyn RequestFilter>]>);

impl RequestFilterLayer {
    pub fn new(filters: Arc<[Arc<dyn RequestFilter>]>) -> Self {
        Self(filters)
    }
}

impl<S> Layer<S> for RequestFilterLayer {
    type Service = RequestFilters<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestFilters {
            inner,
            filters: self.0.clone(),
        }
    }
}

#[derive(Clone)]
pub struct RequestFilters<S> {
    inner: S,
    filters: Arc<[Arc<dyn RequestFilter>]>,
}

impl<S, B> Service<axum::http::Request<B>> for RequestFilters<S>
where
    S: Service<axum::http::Request<B>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: axum::http::Request<B>) -> Self::Future {
        let head = RequestHead {
            method: request.method(),
            uri: request.uri(),
            headers: request.headers(),
            version: request.version(),
        };

        for filter in self.filters.iter() {
            if let Err(rejection) = filter.check(head) {
                let response = rejection.into_response();
                return Box::pin(async move { Ok(response) });
            }
        }

        // `poll_ready` was called on `self.inner`, so readiness belongs to it
        // rather than to the clone; swap so the ready one is what gets called.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move { inner.call(request).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_env_prefix_is_derived_from_the_name() {
        assert_eq!(env_prefix("cors"), "APP_PLUGIN_CORS_");
        assert_eq!(env_prefix("request-log"), "APP_PLUGIN_REQUEST_LOG_");
        assert_eq!(env_prefix("path-guard"), "APP_PLUGIN_PATH_GUARD_");
    }

    const PREFIX: &str = "APP_PLUGIN_DEMO_";

    #[test]
    fn a_setting_that_does_not_parse_is_an_error_not_a_default() {
        let mut settings = Settings::empty();
        settings.set("APP_PLUGIN_DEMO_SAMPLE", "nope");

        let rejected = settings
            .parse_or::<u32>("demo", PREFIX, "SAMPLE", 1)
            .unwrap_err();
        assert_eq!(rejected.setting, "APP_PLUGIN_DEMO_SAMPLE");

        assert_eq!(
            settings
                .parse_or::<u32>("demo", PREFIX, "MISSING", 7)
                .unwrap(),
            7,
            "an unset value falls back"
        );
    }

    #[test]
    fn lists_are_trimmed_and_empties_dropped() {
        let mut settings = Settings::empty();
        settings.set("APP_PLUGIN_DEMO_HOSTS", " a.example , ,b.example ");

        assert_eq!(
            settings.list(PREFIX, "HOSTS"),
            vec!["a.example", "b.example"]
        );
        assert!(settings.list(PREFIX, "MISSING").is_empty());
    }

    #[test]
    fn an_explicit_setting_beats_the_environment_snapshot() {
        let registry = Registry::bare().set("APP_PLUGIN_DEMO_ENABLED", "false");
        assert_eq!(
            registry.settings.raw(PREFIX, "ENABLED"),
            Some("false"),
            "set() must reach the resolved settings"
        );
    }
}
