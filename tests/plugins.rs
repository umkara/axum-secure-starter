//! The plugin system, from the outside.
//!
//! `src/plugin` claims that a plugin is *additive*: it may add a layer or a
//! pre-routing check and nothing else, and no configuration can make the server
//! weaker than an empty registry leaves it. That claim is only worth as much as
//! the evidence for it, so most of this file registers plugins that actively try
//! to break it — stripping hardening headers, panicking, sitting on the
//! credential path — and asserts that the core wins every time.
//!
//! What is **not** tested here is what the type system already refuses to
//! compile:
//!
//! * a plugin cannot rewrite a request, because [`RequestFilter::check`] takes
//!   [`RequestHead`] by shared reference and can only return `Err`;
//! * a plugin cannot land between `HandleErrorLayer` and the load shedder,
//!   because [`RouteLayer`] pins `Error = Infallible`;
//! * a plugin cannot reach `AppState`, because [`PluginCx`] does not carry it.
//!
//! A test that "proves" those would only be testing that the file still
//! compiles.

mod common;

use std::{
    future::Future,
    io::{Read, Write},
    net::TcpStream,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue, Method},
    response::Response,
};
use bastion::{
    config::{AppConfig, Environment},
    plugin::{
        Plugin, PluginCx, PluginError, Plugins, Registry, RequestFilter, RequestHead, RouteLayer,
        Stage,
    },
};
use common::{TestOptions, register_and_login, spawn_with};
use serde_json::Value;
use tower::{Layer, Service};

const PASSWORD: &str = "correct horse battery staple";

/// Every header the core promises on every response.
const HARDENING: [&str; 7] = [
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-resource-policy",
    "cross-origin-opener-policy",
    "strict-transport-security",
];

// ---------------------------------------------------------------------------
// Plugins written to misbehave
// ---------------------------------------------------------------------------

/// What a [`Hostile`] plugin does to the requests passing through it.
#[derive(Clone)]
enum Action {
    /// Deletes response headers on the way out — the core's job is to put them
    /// back.
    Strip(&'static [&'static str]),
    /// Appends a label to `x-order`, so a test can read the stack order off a
    /// response.
    Mark(&'static str),
    /// Panics instead of serving.
    Panic,
    /// Records what the plugin could see of the request.
    Peek(Arc<Mutex<Vec<Peeked>>>),
}

/// What a plugin observed about one request.
#[derive(Debug, Clone)]
struct Peeked {
    path: String,
    /// `None` when the header was absent. `Some(false)` would mean the core's
    /// `SetSensitiveRequestHeadersLayer` did not reach this far.
    authorization_is_sensitive: Option<bool>,
}

/// A plugin that installs one [`Action`] at one [`Stage`].
struct Hostile {
    name: &'static str,
    stage: Stage,
    action: Action,
}

impl Hostile {
    fn new(name: &'static str, stage: Stage, action: Action) -> Self {
        Self {
            name,
            stage,
            action,
        }
    }
}

impl Plugin for Hostile {
    fn name(&self) -> &'static str {
        self.name
    }

    fn stage(&self) -> Stage {
        self.stage
    }

    fn layer(&self, _cx: &PluginCx<'_>) -> Result<Option<RouteLayer>, PluginError> {
        Ok(Some(Plugins::erase(HostileLayer {
            action: self.action.clone(),
        })))
    }
}

#[derive(Clone)]
struct HostileLayer {
    action: Action,
}

impl<S> Layer<S> for HostileLayer {
    type Service = Hostiled<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Hostiled {
            inner,
            action: self.action.clone(),
        }
    }
}

#[derive(Clone)]
struct Hostiled<S> {
    inner: S,
    action: Action,
}

impl<S> Service<Request> for Hostiled<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        if let Action::Panic = self.action {
            panic!("a plugin panicked on purpose");
        }

        if let Action::Peek(sink) = &self.action {
            sink.lock().unwrap().push(Peeked {
                path: request.uri().path().to_owned(),
                authorization_is_sensitive: request
                    .headers()
                    .get(axum::http::header::AUTHORIZATION)
                    .map(HeaderValue::is_sensitive),
            });
        }

        let action = self.action.clone();
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let mut response = inner.call(request).await?;

            match action {
                Action::Strip(names) => {
                    for name in names {
                        response.headers_mut().remove(*name);
                    }
                }
                Action::Mark(label) => {
                    response.headers_mut().append(
                        HeaderName::from_static("x-order"),
                        HeaderValue::from_static(label),
                    );
                }
                Action::Panic | Action::Peek(_) => {}
            }

            Ok(response)
        })
    }
}

/// A plugin that refuses its configuration.
struct Refuses;

impl Plugin for Refuses {
    fn name(&self) -> &'static str {
        "refuses"
    }

    fn layer(&self, cx: &PluginCx<'_>) -> Result<Option<RouteLayer>, PluginError> {
        Err(cx.invalid("SETTING", "this plugin is never satisfied"))
    }
}

/// A pre-routing check that lets everything through. Registered to prove that a
/// filter cannot *widen* what the core accepts, only narrow it.
struct WavesEverythingThrough;

impl Plugin for WavesEverythingThrough {
    fn name(&self) -> &'static str {
        "waves-everything-through"
    }

    fn filter(&self, _cx: &PluginCx<'_>) -> Result<Option<Arc<dyn RequestFilter>>, PluginError> {
        Ok(Some(Arc::new(Permissive)))
    }
}

struct Permissive;

impl RequestFilter for Permissive {
    fn name(&self) -> &'static str {
        "waves-everything-through"
    }

    fn check(&self, _head: RequestHead<'_>) -> Result<(), bastion::error::AppError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn assert_hardened(headers: &reqwest::header::HeaderMap, context: &str) {
    for name in HARDENING {
        assert!(
            headers.contains_key(name),
            "{context}: `{name}` is missing — a plugin removed a core header"
        );
    }
    assert_eq!(headers["x-content-type-options"], "nosniff", "{context}");
    assert_eq!(headers["x-frame-options"], "DENY", "{context}");
    assert_eq!(headers["referrer-policy"], "no-referrer", "{context}");
    assert!(
        headers.contains_key("x-request-id"),
        "{context}: the request id is a core control too"
    );
}

/// Sends a request over a socket, because `reqwest` normalises a URL before it
/// sends it: `%2e%2e` is resolved to `..` by the URL parser, so a guard that
/// exists to catch exactly that spelling would never see it.
///
/// Blocking work goes to a blocking thread — `#[tokio::test]` runs a
/// single-threaded runtime, and blocking here would starve the server task.
async fn raw_request(addr: std::net::SocketAddr, request: &'static [u8]) -> String {
    tokio::task::spawn_blocking(move || {
        let mut socket = TcpStream::connect(addr).expect("failed to connect");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket.write_all(request).expect("failed to write");
        socket.flush().ok();

        let mut response = Vec::new();
        let _ = socket.read_to_end(&mut response);
        String::from_utf8_lossy(&response).into_owned()
    })
    .await
    .expect("the raw socket probe panicked")
}

/// The status line of a raw response, as `"400 Bad Request"`.
fn status_line(response: &str) -> &str {
    let line = response.lines().next().unwrap_or_default();
    line.strip_prefix("HTTP/1.1 ").unwrap_or(line)
}

/// A production-shaped copy of the harness configuration, for the settings that
/// only bite outside development.
fn as_production(config: &AppConfig) -> AppConfig {
    AppConfig {
        environment: Environment::Production,
        ..config.clone()
    }
}

// ---------------------------------------------------------------------------
// The floor: an empty registry
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_empty_registry_still_serves_a_fully_hardened_response() {
    let app = spawn_with(TestOptions {
        plugins: Registry::bare(),
        ..Default::default()
    })
    .await;

    let response = app
        .client
        .get(app.url("/health/live"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_hardened(response.headers(), "no plugins at all");
}

#[tokio::test]
async fn an_empty_registry_still_refuses_a_non_canonical_path() {
    let app = spawn_with(TestOptions {
        plugins: Registry::bare(),
        ..Default::default()
    })
    .await;

    // Canonicalisation is core, not a plugin: removing every plugin must not
    // give `//api/v1/notes` a second spelling. It answers 404 rather than 400 —
    // a path with an empty segment is not a path this server has.
    let response = app
        .client
        .get(app.url("//api/v1/notes"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        404,
        "an empty registry must not relax path canonicalisation"
    );
}

// ---------------------------------------------------------------------------
// A plugin cannot remove a core control
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_plugin_that_strips_the_hardening_headers_has_them_written_back() {
    /// The core's headers plus one the core does not set. Stripping the second
    /// is what proves the plugin is really running: without it, a stripper that
    /// silently did nothing would pass this test.
    const STRIPPED: [&str; 8] = [
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
        "cross-origin-resource-policy",
        "cross-origin-opener-policy",
        "strict-transport-security",
        "x-order",
    ];

    let app = spawn_with(TestOptions {
        plugins: Registry::bare()
            .with(Hostile::new(
                "hostile-stripper",
                Stage::Outer,
                Action::Strip(&STRIPPED),
            ))
            // Registered second, so it runs inside the stripper: it adds
            // `x-order` and the stripper then takes it away again.
            .with(Hostile::new("marker", Stage::Outer, Action::Mark("marked"))),
        ..Default::default()
    })
    .await;

    let response = app
        .client
        .get(app.url("/health/live"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert!(
        response.headers().get("x-order").is_none(),
        "the stripper must actually strip, or this test proves nothing"
    );
    // The layers above the stage set their headers with `overriding`, so the
    // strip happens and is then undone on the way out.
    assert_hardened(response.headers(), "a plugin stripped them at Stage::Outer");
}

#[tokio::test]
async fn a_plugin_inside_the_api_stage_cannot_strip_them_either() {
    let app = spawn_with(TestOptions {
        plugins: Registry::bare().with(Hostile::new(
            "hostile-stripper",
            Stage::Api,
            // The API's own two headers as well, which are applied closer to
            // the routes than the shared hardening is.
            Action::Strip(&[
                "x-content-type-options",
                "x-frame-options",
                "referrer-policy",
                "permissions-policy",
                "cross-origin-resource-policy",
                "cross-origin-opener-policy",
                "strict-transport-security",
                "content-security-policy",
                "cache-control",
            ]),
        )),
        ..Default::default()
    })
    .await;

    let (access, _) = register_and_login(&app, "api-stage@example.com", PASSWORD).await;
    let response = app
        .client
        .get(app.url("/api/v1/notes"))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_hardened(response.headers(), "a plugin stripped them at Stage::Api");
    assert!(
        response.headers().contains_key("content-security-policy"),
        "the API policy is applied outside the stage as well"
    );
    assert_eq!(
        response.headers()["cache-control"],
        "no-store, no-cache, must-revalidate",
        "a per-user response must not become cacheable because a plugin said so"
    );
}

#[tokio::test]
async fn a_panicking_plugin_becomes_a_500_and_the_server_survives() {
    let app = spawn_with(TestOptions {
        plugins: Registry::bare().with(Hostile::new("hostile-panic", Stage::Api, Action::Panic)),
        ..Default::default()
    })
    .await;

    let response = app
        .client
        .get(app.url("/api/v1/notes"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        500,
        "CatchPanicLayer sits above every stage"
    );

    // The substitute response `CatchPanicLayer` returns is a response like any
    // other: the hardening sits above the catch, so a bug in a plugin cannot
    // produce the one 500 that arrives without headers.
    assert_hardened(response.headers(), "a plugin panicked");

    // The connection was not dropped and the process is still serving: a
    // plugin's bug is one request's problem.
    let live = app
        .client
        .get(app.url("/health/live"))
        .send()
        .await
        .unwrap();
    assert_eq!(live.status(), 200, "the server survived the panic");
}

// ---------------------------------------------------------------------------
// What a plugin is allowed to see
// ---------------------------------------------------------------------------

#[tokio::test]
async fn credentials_reach_a_plugin_already_marked_sensitive() {
    let seen: Arc<Mutex<Vec<Peeked>>> = Arc::new(Mutex::new(Vec::new()));
    let app = spawn_with(TestOptions {
        plugins: Registry::bare().with(Hostile::new(
            "peeker",
            Stage::Outer,
            Action::Peek(seen.clone()),
        )),
        ..Default::default()
    })
    .await;

    let (access, _) = register_and_login(&app, "sensitive@example.com", PASSWORD).await;
    let response = app
        .client
        .get(app.url("/api/v1/notes"))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let peeked = seen.lock().unwrap();
    let with_token = peeked
        .iter()
        .find(|entry| entry.authorization_is_sensitive.is_some())
        .expect("the plugin should have seen the authenticated request");

    // `SetSensitiveRequestHeadersLayer` runs above every stage, so anything a
    // plugin prints with `Debug` — a log line, a span field — redacts the
    // credential instead of publishing it.
    assert_eq!(
        with_token.authorization_is_sensitive,
        Some(true),
        "the credential must arrive marked sensitive"
    );
    assert_eq!(with_token.path, "/api/v1/notes");
}

#[tokio::test]
async fn a_filter_cannot_widen_what_the_core_accepts() {
    let app = spawn_with(TestOptions {
        plugins: Registry::bare().with(WavesEverythingThrough),
        ..Default::default()
    })
    .await;

    // The filter returns `Ok` for everything, and canonicalisation still runs
    // underneath it. A filter is a veto, not an approval.
    let response = app
        .client
        .get(app.url("//api/v1/notes"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        404,
        "a permissive filter must not smuggle a non-canonical path through"
    );
}

// ---------------------------------------------------------------------------
// Stages and order
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registration_order_is_stack_order() {
    let app = spawn_with(TestOptions {
        plugins: Registry::bare()
            .with(Hostile::new("first", Stage::Outer, Action::Mark("first")))
            .with(Hostile::new("second", Stage::Outer, Action::Mark("second"))),
        ..Default::default()
    })
    .await;

    let response = app
        .client
        .get(app.url("/health/live"))
        .send()
        .await
        .unwrap();

    let order: Vec<&str> = response
        .headers()
        .get_all("x-order")
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();

    // Registered outermost-first, so the *inner* plugin touches the response
    // first on the way out.
    assert_eq!(
        order,
        vec!["second", "first"],
        "the plugin registered first must wrap the one registered second"
    );
}

#[tokio::test]
async fn the_credential_stage_is_separate_from_the_api_stage() {
    let app = spawn_with(TestOptions {
        plugins: Registry::bare().with(Hostile::new(
            "credentials-only",
            Stage::Credentials,
            Action::Mark("credentials"),
        )),
        ..Default::default()
    })
    .await;

    let (access, _) = register_and_login(&app, "stages@example.com", PASSWORD).await;

    let login = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({ "email": "stages@example.com", "password": PASSWORD }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        login.headers().get("x-order").map(|v| v.to_str().unwrap()),
        Some("credentials"),
        "a plugin at Stage::Credentials must reach the login route"
    );

    let notes = app
        .client
        .get(app.url("/api/v1/notes"))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap();
    assert!(
        notes.headers().get("x-order").is_none(),
        "and must not reach the rest of the API"
    );

    let live = app
        .client
        .get(app.url("/health/live"))
        .send()
        .await
        .unwrap();
    assert!(
        live.headers().get("x-order").is_none(),
        "health probes sit outside every stage on purpose"
    );
}

#[tokio::test]
async fn the_page_stage_reaches_static_files_and_nothing_else() {
    let static_dir = tempfile::tempdir().expect("failed to create a static directory");
    std::fs::write(static_dir.path().join("index.html"), "<!doctype html>hello")
        .expect("failed to write the test index");

    let app = spawn_with(TestOptions {
        static_dir: Some(static_dir.path().to_path_buf()),
        plugins: Registry::bare().with(Hostile::new(
            "pages-only",
            Stage::Page,
            Action::Mark("pages"),
        )),
        ..Default::default()
    })
    .await;

    let page = app.client.get(app.url("/")).send().await.unwrap();
    assert_eq!(page.status(), 200);
    assert_eq!(
        page.headers().get("x-order").map(|v| v.to_str().unwrap()),
        Some("pages"),
        "a plugin at Stage::Page must reach the static branch"
    );

    let api = app
        .client
        .get(app.url("/api/v1/notes"))
        .send()
        .await
        .unwrap();
    assert!(
        api.headers().get("x-order").is_none(),
        "and must not reach the API"
    );
}

// ---------------------------------------------------------------------------
// Resolution: settings are read once, before anything is served
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_plugin_that_refuses_its_settings_stops_start_up() {
    let app = spawn_with(TestOptions {
        plugins: Registry::bare(),
        ..Default::default()
    })
    .await;
    let config = app.state.config_handle();

    let refusal = Registry::bare()
        .with(Refuses)
        .resolve(&config)
        .expect_err("the plugin refuses every configuration");

    assert_eq!(refusal.plugin, "refuses");
    assert_eq!(refusal.setting, "APP_PLUGIN_REFUSES_SETTING");
    assert!(
        refusal.to_string().contains("never satisfied"),
        "the reason must survive into the message operators see: {refusal}"
    );
}

#[tokio::test]
async fn only_the_plugins_that_contribute_are_reported_as_enabled() {
    let app = spawn_with(TestOptions {
        plugins: Registry::bare(),
        ..Default::default()
    })
    .await;
    let config = app.state.config_handle();

    let plugins = Registry::bare()
        .with(bastion::plugin::builtin::PathGuard)
        .with(bastion::plugin::builtin::HostGuard)
        .resolve(&config)
        .expect("the defaults are valid");

    // The host guard has no host list, so it installs nothing and is not
    // reported. A start-up line that claimed otherwise would be worse than no
    // line at all.
    assert_eq!(plugins.enabled(), ["path-guard"]);
}

#[tokio::test]
async fn a_setting_that_does_not_parse_stops_start_up() {
    let app = spawn_with(TestOptions {
        plugins: Registry::bare(),
        ..Default::default()
    })
    .await;
    let config = app.state.config_handle();

    let refusal = Registry::bare()
        .with(bastion::plugin::builtin::PathGuard)
        .set("APP_PLUGIN_PATH_GUARD_MAX_PATH_LEN", "quite long")
        .resolve(&config)
        .expect_err("a value that does not parse is never a silent default");

    assert_eq!(refusal.setting, "APP_PLUGIN_PATH_GUARD_MAX_PATH_LEN");
}

#[tokio::test]
async fn rate_limiting_cannot_be_switched_off_in_production() {
    let app = spawn_with(TestOptions {
        plugins: Registry::bare(),
        ..Default::default()
    })
    .await;
    let development = app.state.config_handle();
    let production = as_production(&development);

    let refusal = Registry::bare()
        .with(bastion::plugin::builtin::RateLimit::credentials())
        .set("APP_PLUGIN_RATE_LIMIT_ENABLED", "false")
        .resolve(&production)
        .expect_err("production must refuse to start without a limiter");
    assert_eq!(refusal.plugin, "rate-limit");
    assert!(
        refusal
            .to_string()
            .contains("cannot be disabled in production"),
        "the message must say what to do instead: {refusal}"
    );

    // The same setting is honoured in development, which is the whole reason it
    // exists.
    let permitted = Registry::bare()
        .with(bastion::plugin::builtin::RateLimit::credentials())
        .set("APP_PLUGIN_RATE_LIMIT_ENABLED", "false")
        .resolve(&development)
        .expect("development may run without a limiter");
    assert!(permitted.enabled().is_empty());
}

#[tokio::test]
async fn a_credential_header_can_never_be_added_to_the_request_log() {
    let app = spawn_with(TestOptions {
        plugins: Registry::bare(),
        ..Default::default()
    })
    .await;
    let config = app.state.config_handle();

    for name in ["authorization", "Cookie", "X-API-Key"] {
        let refusal = Registry::bare()
            .with(bastion::plugin::builtin::RequestLog)
            .set("APP_PLUGIN_REQUEST_LOG_HEADERS", name)
            .resolve(&config)
            .unwrap_err();
        assert_eq!(refusal.plugin, "request-log", "`{name}` must be refused");
    }

    // An ordinary header is fine, so the refusal is about credentials rather
    // than about the setting being unusable.
    Registry::bare()
        .with(bastion::plugin::builtin::RequestLog)
        .set("APP_PLUGIN_REQUEST_LOG_HEADERS", "user-agent")
        .resolve(&config)
        .expect("a non-credential header is allowed");
}

// ---------------------------------------------------------------------------
// The shipped plugins, over HTTP
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_shipped_guards_reject_before_the_router_matches() {
    let app = spawn_with(TestOptions::default()).await;

    // Parameter pollution.
    let duplicated = app
        .client
        .get(app.url("/api/v1/notes?limit=1&limit=2"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        duplicated.status(),
        400,
        "a repeated query key is refused before authentication is even checked"
    );

    // TRACE reflects the request, which is how cross-site tracing reads a
    // header the browser would not otherwise hand over.
    let traced = app
        .client
        .request(Method::TRACE, app.url("/api/v1/notes"))
        .send()
        .await
        .unwrap();
    assert_eq!(traced.status(), 400, "TRACE never reaches a handler");

    // A cross-origin form post cannot set a JSON content type.
    let form = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("email=a@example.com&password=hunter2")
        .send()
        .await
        .unwrap();
    assert_eq!(form.status(), 400, "a form post cannot reach the API");
}

#[tokio::test]
async fn an_encoded_separator_is_refused_off_the_socket() {
    let app = spawn_with(TestOptions::default()).await;

    // `%2e%2e` reaches the same place as `..` for anything that decodes before
    // it resolves, and disagreement about when to decode is the whole trick.
    // Sent raw because a URL library resolves it client-side.
    let refused = raw_request(
        app.addr(),
        b"GET /api/v1/%2e%2e/notes HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        status_line(&refused),
        "400 Bad Request",
        "an encoded separator is refused:\n{refused}"
    );

    let backslash = raw_request(
        app.addr(),
        b"GET /api/v1/notes\\admin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        status_line(&backslash),
        "400 Bad Request",
        "a Windows separator in a URL is only ever an attempt to be split on:\n{backslash}"
    );
}

#[tokio::test]
async fn a_rejection_made_above_the_router_is_hardened_like_any_other_response() {
    let app = spawn_with(TestOptions::default()).await;

    // A pre-routing filter short-circuits above the router, so its rejection
    // never passes through the stack inside it. The hardening is repeated above
    // the filters for exactly this reason: rejecting early must not mean
    // answering with less.
    let refused = raw_request(
        app.addr(),
        b"GET /api/v1/%2e%2e/notes HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert_eq!(status_line(&refused), "400 Bad Request");
    let lowered = refused.to_lowercase();
    for name in HARDENING {
        assert!(
            lowered.contains(name),
            "a filter's rejection is missing `{name}`:\n{refused}"
        );
    }
    assert!(
        lowered.contains("x-request-id"),
        "and it is correlatable:\n{refused}"
    );
    // The body is still the API envelope, so a client parses one shape.
    assert!(
        refused.contains("\"bad_request\""),
        "a rejection is still the error envelope:\n{refused}"
    );

    // The core's own canonicalisation refusal sits in the same place, and gains
    // the headers from the same repetition.
    let non_canonical = app
        .client
        .get(app.url("//api/v1/notes"))
        .send()
        .await
        .unwrap();
    assert_eq!(non_canonical.status(), 404);
    assert_hardened(non_canonical.headers(), "a non-canonical path");
}

#[tokio::test]
async fn a_guard_rejection_is_the_api_error_envelope() {
    let app = spawn_with(TestOptions::default()).await;

    let response = app
        .client
        .get(app.url("/api/v1/notes?limit=1&limit=2"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.expect("a rejection must be JSON");
    assert_eq!(body["error"]["code"], "bad_request");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("appears more than once"),
        "the client is told which parameter to fix: {body}"
    );
}

#[tokio::test]
async fn the_guards_can_be_turned_off_without_touching_the_core() {
    let app = spawn_with(TestOptions {
        plugins: Registry::builtin()
            .set("APP_PLUGIN_PATH_GUARD_ENABLED", "false")
            .set("APP_PLUGIN_METHOD_GUARD_ENABLED", "false"),
        ..Default::default()
    })
    .await;

    // Without the guard the request reaches routing and is answered on its
    // merits — the point being that a guard adds a refusal and nothing else.
    let duplicated = app
        .client
        .get(app.url("/api/v1/notes?limit=1&limit=2"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        duplicated.status(),
        401,
        "routing decided this one, not the guard"
    );

    let traced = app
        .client
        .request(Method::TRACE, app.url("/api/v1/notes"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        traced.status(),
        405,
        "axum answers a method it has no route for"
    );

    // Canonicalisation is core, so switching off every guard does not reopen
    // the second spelling.
    let non_canonical = app
        .client
        .get(app.url("//api/v1/notes"))
        .send()
        .await
        .unwrap();
    assert_eq!(non_canonical.status(), 404);
    assert_hardened(non_canonical.headers(), "every guard disabled");
}

#[tokio::test]
async fn the_host_guard_answers_only_for_the_hosts_it_is_given() {
    let app = spawn_with(TestOptions {
        plugins: Registry::builtin().set("APP_PLUGIN_HOST_GUARD_HOSTS", "bastionrs.dev"),
        ..Default::default()
    })
    .await;

    // The harness connects to 127.0.0.1, which is not on the list.
    let refused = app
        .client
        .get(app.url("/health/live"))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 400, "an unrecognised Host is refused");

    let accepted = app
        .client
        .get(app.url("/health/live"))
        .header("host", "bastionrs.dev")
        .send()
        .await
        .unwrap();
    assert_eq!(accepted.status(), 200, "the configured host is served");
}

#[tokio::test]
async fn cors_is_a_plugin_and_removing_it_only_narrows_the_server() {
    let origin = "https://app.example";

    let with_cors = spawn_with(TestOptions {
        cors_allowed_origins: vec![origin.into()],
        ..Default::default()
    })
    .await;

    let allowed = with_cors
        .client
        .get(with_cors.url("/health/live"))
        .header("origin", origin)
        .send()
        .await
        .unwrap();
    assert_eq!(
        allowed.headers()["access-control-allow-origin"],
        origin,
        "the plugin installs the policy the configuration asks for"
    );

    let without_cors = spawn_with(TestOptions {
        cors_allowed_origins: vec![origin.into()],
        plugins: Registry::builtin().set("APP_PLUGIN_CORS_ENABLED", "false"),
        ..Default::default()
    })
    .await;

    let refused = without_cors
        .client
        .get(without_cors.url("/health/live"))
        .header("origin", origin)
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 200, "the request still reaches the route");
    assert!(
        refused
            .headers()
            .get("access-control-allow-origin")
            .is_none(),
        "with no policy the browser refuses the cross-origin read — \
         removing this plugin is strictly more restrictive"
    );
    assert_hardened(refused.headers(), "cors disabled");
}

#[tokio::test]
async fn a_wildcard_origin_is_refused_even_when_it_reaches_the_plugin() {
    let app = spawn_with(TestOptions {
        plugins: Registry::bare(),
        ..Default::default()
    })
    .await;

    // An embedder that builds `AppConfig` in code never passes through
    // `config::from_env`, so the plugin re-checks rather than trusting it.
    let mut config = (*app.state.config_handle()).clone();
    config.security.cors_allowed_origins = vec!["*".into()];

    let refusal = Registry::bare()
        .with(bastion::plugin::builtin::Cors)
        .resolve(&config)
        .expect_err("a wildcard origin must not boot");
    assert_eq!(refusal.plugin, "cors");
}
