//! Routing and the middleware stack.
//!
//! The stack is assembled once, here, so the protections that must apply to
//! every request cannot be forgotten on an individual route.

pub mod admin_handler;
pub mod auth_handler;
pub mod dto;
pub mod extract;
pub mod health_handler;
pub mod note_handler;
pub mod path;

use axum::{
    Router,
    error_handling::HandleErrorLayer,
    extract::DefaultBodyLimit,
    http::{HeaderName, StatusCode, header},
    routing::{delete, get, post},
};
use tower::{BoxError, ServiceBuilder};
use tower_http::{
    catch_panic::CatchPanicLayer,
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    sensitive_headers::SetSensitiveRequestHeadersLayer,
    services::{ServeDir, ServeFile},
    timeout::TimeoutLayer,
};

use crate::{
    error::AppError,
    plugin::{Plugins, Stage},
    security::headers::SecurityHeaders,
    state::AppState,
};

pub(crate) const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// Builds the fully wrapped application router.
///
/// `plugins` may only add layers at the [`Stage`]s marked below. The core
/// controls in this function are applied outside every one of those slots, so
/// no plugin can remove them — see [`crate::plugin`].
pub fn build_router(state: AppState, plugins: &Plugins) -> Router {
    let config = state.config_handle();

    // Health probes sit outside the rate limiter: a limiter that starves the
    // orchestrator's probes turns a traffic spike into a restart loop.
    let health_routes = Router::new()
        .route("/health/live", get(health_handler::live))
        .route("/health/ready", get(health_handler::ready));

    // Credential endpoints are their own stage: they carry the expensive,
    // unauthenticated work, and the shipped limiter gives them a tighter
    // bucket there than the rest of the API gets.
    let auth_routes = plugins.apply(
        Stage::Credentials,
        Router::new()
            .route("/auth/register", post(auth_handler::register))
            .route("/auth/login", post(auth_handler::login))
            .route("/auth/refresh", post(auth_handler::refresh))
            .route("/auth/logout", post(auth_handler::logout)),
    );

    let api_routes = plugins.apply(
        Stage::Api,
        Router::new()
            .route("/auth/password", post(auth_handler::change_password))
            .route(
                "/admin/users/{id}/sessions",
                delete(admin_handler::revoke_sessions),
            )
            .route("/notes", get(note_handler::list).post(note_handler::create))
            .route(
                "/notes/{id}",
                get(note_handler::get)
                    .put(note_handler::update)
                    .delete(note_handler::delete),
            ),
    );

    // The API's own fallback stays JSON: an unknown `/api/v1/...` path is a
    // client error, not a request for the frontend's index page.
    let versioned = Router::new()
        .merge(auth_routes)
        .merge(api_routes)
        .fallback(not_found);

    // The strict response headers belong to the API alone. A page that loads
    // stylesheets and scripts cannot live under `default-src 'none'`, and the
    // usual way that gets "fixed" is by loosening the policy for everything —
    // which is how adding a frontend quietly weakens an API.
    let api = Router::new()
        .merge(health_routes)
        .nest("/api/v1", versioned)
        .layer(
            ServiceBuilder::new()
                .layer(SecurityHeaders::content_security_policy())
                .layer(SecurityHeaders::no_store()),
        );

    // Prebuilt frontend assets, when configured. Unknown paths fall back to
    // `index.html` so a client-side router can handle them, and these responses
    // carry the page CSP and a cache lifetime rather than the API's.
    let router = match &config.server.static_dir {
        Some(dir) => {
            let files = ServiceBuilder::new()
                .layer(SecurityHeaders::page_content_security_policy())
                .layer(SecurityHeaders::asset_cache())
                .service(ServeDir::new(dir).fallback(ServeFile::new(dir.join("index.html"))));

            if plugins.is_empty(Stage::Page) {
                api.fallback_service(files)
            } else {
                // Reached through a `Router` because that is the only way to
                // apply an erased layer from outside axum; skipped entirely
                // when the stage is empty so static requests do not pay for a
                // routing pass they do not need.
                let pages = plugins.apply(Stage::Page, Router::new().fallback_service(files));
                api.fallback_service(pages)
            }
        }
        None => api.fallback(not_found),
    };

    // Listed outermost first. Order matters: panics are caught above
    // everything so a panic still produces a well-formed response, and body
    // limits sit above the handlers so oversized payloads are rejected before
    // they are buffered.
    //
    // The stack is in two halves with `Stage::Outer` between them. Everything
    // in `hardening` therefore runs outside every plugin — a plugin that strips
    // a header has it written back on the way out, because these layers set
    // theirs with `overriding`.
    let hardening = ServiceBuilder::new()
        // Correlates log lines across a request, and echoes the id back.
        .layer(SetRequestIdLayer::new(REQUEST_ID_HEADER, MakeRequestUuid))
        .layer(PropagateRequestIdLayer::new(REQUEST_ID_HEADER))
        // Above the panic handler, so the substitute 500 it returns is hardened
        // and correlatable like any other response. The layers above this point
        // only copy a header or write a constant; a panic in one of them is not
        // a state this server can reach, and putting the catch above them would
        // trade that impossibility for a real gap.
        .layer(SecurityHeaders::hardening())
        // A panicking handler — or a panicking plugin — becomes a 500 instead
        // of a dropped connection.
        .layer(CatchPanicLayer::new())
        // Above every plugin on purpose: this is what keeps credentials out of
        // anything downstream that prints headers, including a logging plugin.
        .layer(SetSensitiveRequestHeadersLayer::new([
            header::AUTHORIZATION,
            header::COOKIE,
            header::PROXY_AUTHORIZATION,
        ]));

    // The availability controls. `HandleErrorLayer` stays welded directly above
    // the load shedder: put anything between them and a shed request becomes an
    // opaque 500 instead of a 503.
    let controls = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(handle_middleware_error))
        // Sheds load rather than queueing without bound when saturated.
        .load_shed()
        .concurrency_limit(config.server.max_concurrency)
        // A slow or stuck handler cannot hold a connection open forever.
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            config.server.request_timeout,
        ))
        // Two limits: the declared `Content-Length` check, and the streamed
        // byte count, so a lying header does not get past either.
        .layer(DefaultBodyLimit::max(config.server.body_limit_bytes))
        .layer(RequestBodyLimitLayer::new(config.server.body_limit_bytes));

    let router = if plugins.is_empty(Stage::Outer) {
        // Nothing occupies the slot, so the two halves compose into one layer
        // and the router is boxed exactly as often as it was before plugins
        // existed.
        router.layer(ServiceBuilder::new().layer(hardening).layer(controls))
    } else {
        plugins
            .apply(Stage::Outer, router.layer(controls))
            .layer(hardening)
    };

    router.with_state(state)
}

async fn handle_middleware_error(error: BoxError) -> AppError {
    if error.is::<tower::load_shed::error::Overloaded>() {
        tracing::warn!("request shed: concurrency limit reached");
        return AppError::Unavailable;
    }
    AppError::Internal(anyhow::anyhow!("middleware failure: {error}"))
}

/// Unknown routes get the same JSON error shape as everything else.
async fn not_found() -> AppError {
    AppError::NotFound
}
