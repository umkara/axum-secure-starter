//! Path canonicalisation, applied before routing.
//!
//! This is a hand-written tower service rather than an `axum::middleware::from_fn`
//! for two reasons, both of which cost a debugging round to learn:
//!
//! * Middleware added with `Router::layer` runs *after* route matching, so a
//!   rewrite there is too late to affect which route is chosen.
//! * `from_fn` only implements `Service` for axum's own body type, so it cannot
//!   wrap the router at the point where the body is still `hyper::body::Incoming`.
//!
//! Wrapping the router directly avoids both.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{
    extract::Request,
    http::Uri,
    response::{IntoResponse, Response},
};
use tower::{Layer, Service};

use crate::error::AppError;

/// Gives every request exactly one legitimate spelling before it is routed.
///
/// * A path containing an empty segment is refused. `//notes` and `/notes` would
///   otherwise reach the same handler, while a proxy, WAF, or gateway rule
///   written against the single-slash form matches only one of the two. That gap
///   is the whole basis of path-confusion ACL bypasses.
/// * A trailing slash is trimmed, so `/notes` and `/notes/` cannot drift into
///   two routes with two sets of behaviour.
///
/// `tower_http`'s trailing-slash normaliser handles only the second point, and
/// in doing so trims leading slashes as well — destroying the evidence the first
/// check needs before that check can run.
#[derive(Clone, Copy, Debug, Default)]
pub struct CanonicalPathLayer;

impl<S> Layer<S> for CanonicalPathLayer {
    type Service = CanonicalPath<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CanonicalPath { inner }
    }
}

#[derive(Clone, Debug)]
pub struct CanonicalPath<S> {
    inner: S,
}

impl<S, B> Service<Request<B>> for CanonicalPath<S>
where
    S: Service<Request<B>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        let path = request.uri().path();

        if path.contains("//") {
            return Box::pin(async { Ok(AppError::NotFound.into_response()) });
        }

        if let Some(rewritten) = trim_trailing_slash(request.uri()) {
            *request.uri_mut() = rewritten;
        }

        // `poll_ready` was called on `self.inner`, so readiness belongs to it
        // rather than to the clone; swap so the ready one is what gets called.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move { inner.call(request).await })
    }
}

/// Returns the URI with one trailing slash removed, or `None` when there is
/// nothing to change. The root path is left alone; it is already canonical.
fn trim_trailing_slash(uri: &Uri) -> Option<Uri> {
    let path = uri.path();
    if path.len() <= 1 || !path.ends_with('/') {
        return None;
    }

    let trimmed = path.trim_end_matches('/');
    let rewritten = match uri.query() {
        Some(query) => format!("{trimmed}?{query}"),
        None => trimmed.to_string(),
    };

    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(rewritten.parse().ok()?);
    Uri::from_parts(parts).ok()
}

#[cfg(test)]
mod tests {
    use super::trim_trailing_slash;

    fn rewrite(raw: &str) -> Option<String> {
        trim_trailing_slash(&raw.parse().unwrap()).map(|uri| uri.to_string())
    }

    #[test]
    fn trims_one_trailing_slash_and_keeps_the_query() {
        assert_eq!(rewrite("/notes/").as_deref(), Some("/notes"));
        assert_eq!(
            rewrite("/notes/?limit=5").as_deref(),
            Some("/notes?limit=5")
        );
    }

    #[test]
    fn leaves_canonical_paths_alone() {
        assert_eq!(rewrite("/notes"), None);
        assert_eq!(rewrite("/"), None);
    }
}
