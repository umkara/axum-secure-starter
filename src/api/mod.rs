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

use std::time::Duration;

use axum::{
    Router,
    error_handling::HandleErrorLayer,
    extract::DefaultBodyLimit,
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
    routing::{delete, get, post},
};
use tower::{BoxError, ServiceBuilder};
use tower_governor::{
    GovernorLayer, governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor,
};
use tower_http::{
    catch_panic::CatchPanicLayer,
    cors::CorsLayer,
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    sensitive_headers::SetSensitiveRequestHeadersLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

use crate::{
    config::AppConfig, error::AppError, security::headers::SecurityHeaders, state::AppState,
};

const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// Builds the fully wrapped application router.
pub fn build_router(state: AppState) -> Router {
    let config = state.config_handle();

    // Health probes sit outside the rate limiter: a limiter that starves the
    // orchestrator's probes turns a traffic spike into a restart loop.
    let health_routes = Router::new()
        .route("/health/live", get(health_handler::live))
        .route("/health/ready", get(health_handler::ready));

    // Credential endpoints get their own, much tighter bucket.
    let auth_routes = with_rate_limit(
        Router::new()
            .route("/auth/register", post(auth_handler::register))
            .route("/auth/login", post(auth_handler::login))
            .route("/auth/refresh", post(auth_handler::refresh))
            .route("/auth/logout", post(auth_handler::logout)),
        &config,
        config.rate_limit.auth_per_second,
        config.rate_limit.auth_burst,
    );

    let api_routes = with_rate_limit(
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
        &config,
        config.rate_limit.global_per_second,
        config.rate_limit.global_burst,
    );

    let versioned = Router::new().merge(auth_routes).merge(api_routes);

    let router = Router::new()
        .merge(health_routes)
        .nest("/api/v1", versioned)
        .fallback(not_found);

    // Listed outermost first. Order matters: panics are caught above
    // everything so a panic still produces a well-formed response, and body
    // limits sit above the handlers so oversized payloads are rejected before
    // they are buffered.
    let stack = ServiceBuilder::new()
        // A panicking handler becomes a 500 instead of a dropped connection.
        .layer(CatchPanicLayer::new())
        // Correlates log lines across a request, and echoes the id back.
        .layer(SetRequestIdLayer::new(REQUEST_ID_HEADER, MakeRequestUuid))
        .layer(PropagateRequestIdLayer::new(REQUEST_ID_HEADER))
        // Keeps credentials out of the tracing output below.
        .layer(SetSensitiveRequestHeadersLayer::new([
            header::AUTHORIZATION,
            header::COOKIE,
            header::PROXY_AUTHORIZATION,
        ]))
        .layer(TraceLayer::new_for_http())
        .layer(SecurityHeaders::hsts())
        .layer(SecurityHeaders::content_security_policy())
        .layer(SecurityHeaders::no_sniff())
        .layer(SecurityHeaders::frame_options())
        .layer(SecurityHeaders::referrer_policy())
        .layer(SecurityHeaders::permissions_policy())
        .layer(SecurityHeaders::cross_origin_resource_policy())
        .layer(SecurityHeaders::cross_origin_opener_policy())
        .layer(SecurityHeaders::no_store())
        .layer(cors_layer(&config))
        // Converts the failures produced by the two layers below into the
        // API's error shape instead of an opaque 500.
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

    router.layer(stack).with_state(state)
}

/// Applies per-client rate limiting to a group of routes.
///
/// Client identity comes from the socket address unless the deployment has
/// declared that it sits behind a trusted proxy — honouring `X-Forwarded-For`
/// otherwise lets any client forge its identity and bypass the limit outright.
fn with_rate_limit(
    router: Router<AppState>,
    config: &AppConfig,
    per_second: u64,
    burst: u32,
) -> Router<AppState> {
    if config.security.trust_proxy_headers {
        let governor = GovernorConfigBuilder::default()
            .per_second(per_second)
            .burst_size(burst)
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("rate limit configuration is valid");
        router.layer(GovernorLayer::new(governor))
    } else {
        let governor = GovernorConfigBuilder::default()
            .per_second(per_second)
            .burst_size(burst)
            .finish()
            .expect("rate limit configuration is valid");
        router.layer(GovernorLayer::new(governor))
    }
}

fn cors_layer(config: &AppConfig) -> CorsLayer {
    let origins: Vec<HeaderValue> = config
        .security
        .cors_allowed_origins
        .iter()
        .filter_map(|origin| origin.parse().ok())
        .collect();

    if origins.is_empty() {
        // No origins configured: same-origin only. That is the default, and it
        // is the safe one — an API with no browser clients needs no CORS.
        return CorsLayer::new();
    }

    CorsLayer::new()
        .allow_origin(origins)
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
        // credentialed CORS is not needed and is not enabled.
        .allow_credentials(false)
        .max_age(Duration::from_secs(600))
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
