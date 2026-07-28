//! Structured per-request logging.
//!
//! A hand-written service rather than a configured `TraceLayer`: the fields
//! logged here are a security decision, and threading an allowlist through
//! `MakeSpan`/`OnResponse` generics buys nothing over forty lines that say
//! exactly what they emit.
//!
//! What it never logs, by construction rather than by care: the request body,
//! the query *values*, and any header outside the allowlist. The core's
//! `SetSensitiveRequestHeadersLayer` marks credentials sensitive, but that only
//! changes how they print in `Debug` — a plugin calling `to_str()` would still
//! read them. The allowlist below is what actually stops that, so it refuses to
//! boot rather than filtering at run time.

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use axum::{
    extract::{ConnectInfo, MatchedPath, Request},
    http::HeaderName,
    response::Response,
};
use tower::{Layer, Service};

use crate::plugin::{Plugin, PluginCx, PluginError, RouteLayer, Stage};

/// Header names a log line must never carry, whatever the configuration says.
const NEVER_LOGGED: [&str; 6] = [
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
];

/// Logs one line per request: method, matched route, status, latency.
#[derive(Debug, Clone, Copy, Default)]
pub struct RequestLog;

impl Plugin for RequestLog {
    fn name(&self) -> &'static str {
        "request-log"
    }

    fn stage(&self) -> Stage {
        Stage::Outer
    }

    fn layer(&self, cx: &PluginCx<'_>) -> Result<Option<RouteLayer>, PluginError> {
        if !cx.enabled(true)? {
            return Ok(None);
        }

        let sample: u64 = cx.parse_or("SAMPLE", 1)?;
        if sample == 0 || sample > 1000 {
            return Err(cx.invalid("SAMPLE", "must be between 1 and 1000"));
        }

        let mut headers = Vec::new();
        for name in cx.list("HEADERS") {
            let lowered = name.to_ascii_lowercase();
            if NEVER_LOGGED.contains(&lowered.as_str()) {
                return Err(cx.invalid(
                    "HEADERS",
                    format!("`{name}` carries credentials and must never be logged"),
                ));
            }
            headers.push(
                HeaderName::try_from(lowered)
                    .map_err(|error| cx.invalid("HEADERS", format!("`{name}`: {error}")))?,
            );
        }

        // An IP is personal data, so it is opt-in rather than opt-out.
        let client_ip: bool = cx.parse_or("CLIENT_IP", false)?;

        Ok(Some(crate::plugin::Plugins::erase(RequestLogLayer {
            config: Arc::new(LogConfig {
                sample,
                headers,
                client_ip,
                seen: AtomicU64::new(0),
            }),
        })))
    }
}

#[derive(Debug)]
struct LogConfig {
    sample: u64,
    headers: Vec<HeaderName>,
    client_ip: bool,
    seen: AtomicU64,
}

impl LogConfig {
    /// Successful responses are sampled; failures never are.
    ///
    /// Deterministic rather than random: a counter is predictable to reason
    /// about and costs one atomic add. A client that can count requests could
    /// in principle align with the unsampled slots, which affects log volume
    /// and nothing else — errors bypass this entirely.
    fn should_log(&self, status: u16) -> bool {
        if status >= 400 {
            return true;
        }
        if self.sample == 1 {
            return true;
        }
        self.seen.fetch_add(1, Ordering::Relaxed) % self.sample == 0
    }
}

#[derive(Clone)]
struct RequestLogLayer {
    config: Arc<LogConfig>,
}

impl<S> Layer<S> for RequestLogLayer {
    type Service = RequestLogged<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestLogged {
            inner,
            config: self.config.clone(),
        }
    }
}

#[derive(Clone)]
struct RequestLogged<S> {
    inner: S,
    config: Arc<LogConfig>,
}

impl<S> Service<Request> for RequestLogged<S>
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
        let config = self.config.clone();
        let method = request.method().clone();

        // The matched route rather than the raw path: an id or an address in a
        // URL is exactly the thing that should not land in a log pipeline.
        let route = request
            .extensions()
            .get::<MatchedPath>()
            .map(|matched| matched.as_str().to_owned())
            .unwrap_or_else(|| "<unmatched>".to_owned());

        let request_id = request
            .headers()
            .get(crate::api::REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("-")
            .to_owned();

        let selected: Vec<(String, String)> = config
            .headers
            .iter()
            .filter_map(|name| {
                request
                    .headers()
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect();

        let client_ip = config.client_ip.then(|| {
            request
                .extensions()
                .get::<ConnectInfo<std::net::SocketAddr>>()
                .map(|ConnectInfo(addr)| addr.ip().to_string())
                .unwrap_or_else(|| "-".to_owned())
        });

        // `poll_ready` was called on `self.inner`, so readiness belongs to it
        // rather than to the clone; swap so the ready one is what gets called.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let started = tokio::time::Instant::now();
            let response = inner.call(request).await?;
            let status = response.status().as_u16();

            if config.should_log(status) {
                tracing::info!(
                    method = %method,
                    route = %route,
                    status,
                    latency_ms = started.elapsed().as_millis() as u64,
                    request_id = %request_id,
                    client_ip = client_ip.as_deref().unwrap_or(""),
                    headers = ?selected,
                    "request"
                );
            }

            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_headers_are_rejected_case_insensitively() {
        for name in ["Authorization", "COOKIE", "x-api-key"] {
            assert!(
                NEVER_LOGGED.contains(&name.to_ascii_lowercase().as_str()),
                "{name} must be refused"
            );
        }
        assert!(!NEVER_LOGGED.contains(&"user-agent"));
    }

    #[test]
    fn errors_are_never_sampled_out() {
        let config = LogConfig {
            sample: 1000,
            headers: Vec::new(),
            client_ip: false,
            seen: AtomicU64::new(1),
        };

        assert!(config.should_log(500), "a 500 must always be logged");
        assert!(config.should_log(429), "a rejection must always be logged");
        assert!(
            !config.should_log(200),
            "a success outside the sample is dropped"
        );
    }

    #[test]
    fn a_sample_of_one_logs_everything() {
        let config = LogConfig {
            sample: 1,
            headers: Vec::new(),
            client_ip: false,
            seen: AtomicU64::new(0),
        };

        assert!((0..5).all(|_| config.should_log(200)));
    }
}
