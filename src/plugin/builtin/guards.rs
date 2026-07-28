//! Pre-routing guards.
//!
//! Four checks that reject a request before the router has matched it. Each is
//! a [`RequestFilter`], so none of them can rewrite a URI — a guard that
//! "helpfully" normalised `//notes` to `/notes` would destroy the evidence
//! [`crate::api::path::CanonicalPathLayer`] needs, and that is the one way a
//! plugin could make this server less strict.
//!
//! Everything here is a byte scan over the head. No allocation, no regular
//! expressions, and deliberately no signature matching: an in-process WAF
//! looking for `' OR 1=1` gives a sense of coverage it cannot honour, and the
//! injection defences live where they belong — parameterised queries and a
//! deny-everything CSP.

use std::{collections::HashSet, sync::Arc};

use axum::http::Method;

use crate::{
    error::AppError,
    plugin::{Plugin, PluginCx, PluginError, RequestFilter, RequestHead},
};

// ---------------------------------------------------------------------------
// path-guard
// ---------------------------------------------------------------------------

/// Refuses URLs whose spelling is a technique rather than an address.
///
/// [`crate::api::path::CanonicalPathLayer`] already gives every request one
/// legitimate spelling — no empty segments, no trailing slash. This covers what
/// it does not: encodings that only a proxy would decode differently,
/// characters no route needs, and lengths no client legitimately sends.
#[derive(Debug, Clone, Copy, Default)]
pub struct PathGuard;

impl Plugin for PathGuard {
    fn name(&self) -> &'static str {
        "path-guard"
    }

    fn filter(&self, cx: &PluginCx<'_>) -> Result<Option<Arc<dyn RequestFilter>>, PluginError> {
        if !cx.enabled(true)? {
            return Ok(None);
        }

        let limits = PathLimits {
            max_path: cx.parse_or("MAX_PATH_LEN", 2048)?,
            max_query: cx.parse_or("MAX_QUERY_LEN", 4096)?,
            max_pairs: cx.parse_or("MAX_QUERY_PAIRS", 32)?,
            allow_duplicate_query: cx.parse_or("ALLOW_DUPLICATE_QUERY", false)?,
        };

        if limits.max_path == 0 || limits.max_query == 0 || limits.max_pairs == 0 {
            return Err(cx.invalid("MAX_PATH_LEN", "limits must be greater than zero"));
        }

        Ok(Some(Arc::new(limits)))
    }
}

#[derive(Debug, Clone, Copy)]
struct PathLimits {
    max_path: usize,
    max_query: usize,
    max_pairs: usize,
    allow_duplicate_query: bool,
}

impl RequestFilter for PathLimits {
    fn name(&self) -> &'static str {
        "path-guard"
    }

    fn check(&self, head: RequestHead<'_>) -> Result<(), AppError> {
        let path = head.uri.path();

        if path.len() > self.max_path {
            return Err(AppError::BadRequest("the request path is too long".into()));
        }
        if has_control_characters(path) {
            return Err(AppError::BadRequest(
                "the request path contains control characters".into(),
            ));
        }
        // A Windows separator in a URL is only ever an attempt to be read as a
        // separator by something downstream that splits on it.
        if path.contains('\\') {
            return Err(AppError::BadRequest(
                "the request path contains a backslash".into(),
            ));
        }
        // Percent-encoded separators and dots: `%2e%2e%2f` reaches the same
        // place as `../` for anything that decodes before it resolves, and
        // disagreement about when to decode is the whole trick.
        if contains_encoded_separator(path) {
            return Err(AppError::BadRequest(
                "the request path contains an encoded separator".into(),
            ));
        }
        if path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
        {
            return Err(AppError::BadRequest(
                "the request path contains a dot segment".into(),
            ));
        }

        let Some(query) = head.uri.query() else {
            return Ok(());
        };

        if query.len() > self.max_query {
            return Err(AppError::BadRequest("the query string is too long".into()));
        }
        if has_control_characters(query) {
            return Err(AppError::BadRequest(
                "the query string contains control characters".into(),
            ));
        }

        let mut seen = HashSet::new();
        for (index, pair) in query.split('&').filter(|pair| !pair.is_empty()).enumerate() {
            if index >= self.max_pairs {
                return Err(AppError::BadRequest(
                    "the query string has too many parameters".into(),
                ));
            }

            let key = pair.split('=').next().unwrap_or_default();
            // Parameter pollution: `?limit=1&limit=2`. Every parser picks a
            // winner and they do not all pick the same one, so a gateway rule
            // written against the first can be bypassed by appending a second.
            if !seen.insert(key) && !self.allow_duplicate_query {
                return Err(AppError::BadRequest(format!(
                    "the query parameter `{key}` appears more than once"
                )));
            }
        }

        Ok(())
    }
}

fn has_control_characters(value: &str) -> bool {
    value.bytes().any(|byte| byte < 0x20 || byte == 0x7F)
}

/// Matches `%2e`, `%2f` and `%5c` in either case, without allocating.
fn contains_encoded_separator(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.windows(3).any(|window| {
        window[0] == b'%'
            && matches!(
                (
                    window[1].to_ascii_lowercase(),
                    window[2].to_ascii_lowercase()
                ),
                (b'2', b'e') | (b'2', b'f') | (b'5', b'c')
            )
    })
}

// ---------------------------------------------------------------------------
// host-guard
// ---------------------------------------------------------------------------

/// Refuses requests whose `Host` is not one this deployment answers to.
///
/// Off unless `APP_PLUGIN_HOST_GUARD_HOSTS` lists something, because the right
/// answer is deployment-specific and a wrong guess here is an outage. Turn it
/// on and a forged `Host` — the lever behind cache poisoning and password-reset
/// link rewriting — stops at the door.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostGuard;

impl Plugin for HostGuard {
    fn name(&self) -> &'static str {
        "host-guard"
    }

    fn filter(&self, cx: &PluginCx<'_>) -> Result<Option<Arc<dyn RequestFilter>>, PluginError> {
        if !cx.enabled(true)? {
            return Ok(None);
        }

        let hosts: Vec<String> = cx
            .list("HOSTS")
            .into_iter()
            .map(|host| host.to_ascii_lowercase())
            .collect();

        if hosts.is_empty() {
            return Ok(None);
        }

        if hosts.iter().any(|host| host == "*") {
            return Err(cx.invalid(
                "HOSTS",
                "a wildcard host defeats the check; list exact hosts",
            ));
        }

        Ok(Some(Arc::new(AllowedHosts(hosts))))
    }
}

#[derive(Debug)]
struct AllowedHosts(Vec<String>);

impl RequestFilter for AllowedHosts {
    fn name(&self) -> &'static str {
        "host-guard"
    }

    fn check(&self, head: RequestHead<'_>) -> Result<(), AppError> {
        // An absolute-form request line carries its own authority, which a
        // proxy may route on while the origin reads `Host`. If both are
        // present they have to agree.
        let authority = head.uri.authority().map(|authority| authority.host());
        let header = head
            .headers
            .get(axum::http::header::HOST)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.split(':').next().unwrap_or(value));

        for candidate in [authority, header].into_iter().flatten() {
            let candidate = candidate.to_ascii_lowercase();
            if !self.0.contains(&candidate) {
                return Err(AppError::BadRequest("unrecognised host".into()));
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// method-guard
// ---------------------------------------------------------------------------

/// Refuses methods this server has no route for.
///
/// `TRACE` is the one that matters — it reflects the request, which is how
/// cross-site tracing reads a header the browser would not otherwise hand over.
/// Axum would answer 405 for these anyway; rejecting before routing means a
/// method never reaches a handler at all.
///
/// It deliberately does **not** reject `X-HTTP-Method-Override` headers. This
/// server routes on the real method and never consults them, which
/// `tests/attacks.rs` pins by asserting such a request is answered normally.
/// Rejecting inert headers would trade a passing test for no security.
#[derive(Debug, Clone, Copy, Default)]
pub struct MethodGuard;

impl Plugin for MethodGuard {
    fn name(&self) -> &'static str {
        "method-guard"
    }

    fn filter(&self, cx: &PluginCx<'_>) -> Result<Option<Arc<dyn RequestFilter>>, PluginError> {
        if !cx.enabled(true)? {
            return Ok(None);
        }

        let configured = cx.list("METHODS");
        let methods = if configured.is_empty() {
            vec![
                Method::GET,
                Method::HEAD,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ]
        } else {
            let mut parsed = Vec::with_capacity(configured.len());
            for method in configured {
                parsed.push(
                    Method::from_bytes(method.to_ascii_uppercase().as_bytes())
                        .map_err(|error| cx.invalid("METHODS", format!("`{method}`: {error}")))?,
                );
            }
            parsed
        };

        Ok(Some(Arc::new(AllowedMethods(methods))))
    }
}

#[derive(Debug)]
struct AllowedMethods(Vec<Method>);

impl RequestFilter for AllowedMethods {
    fn name(&self) -> &'static str {
        "method-guard"
    }

    fn check(&self, head: RequestHead<'_>) -> Result<(), AppError> {
        if self.0.iter().any(|allowed| allowed == head.method) {
            Ok(())
        } else {
            Err(AppError::BadRequest("unsupported method".into()))
        }
    }
}

// ---------------------------------------------------------------------------
// content-type-guard
// ---------------------------------------------------------------------------

/// Requires a JSON content type on API requests that carry a body.
///
/// This is the CSRF guard for a token-authenticated API. A browser can be made
/// to submit a cross-origin form without any cooperation from the user, but a
/// form can only send `application/x-www-form-urlencoded`, `multipart/form-data`
/// or `text/plain` — never `application/json`. Requiring JSON means a
/// cross-origin form post cannot reach a handler even if it somehow arrived
/// with credentials attached.
#[derive(Debug, Clone, Copy, Default)]
pub struct ContentTypeGuard;

impl Plugin for ContentTypeGuard {
    fn name(&self) -> &'static str {
        "content-type-guard"
    }

    fn filter(&self, cx: &PluginCx<'_>) -> Result<Option<Arc<dyn RequestFilter>>, PluginError> {
        if !cx.enabled(true)? {
            return Ok(None);
        }
        if !cx.parse_or("REQUIRE_JSON", true)? {
            return Ok(None);
        }
        Ok(Some(Arc::new(JsonBodies)))
    }
}

#[derive(Debug)]
struct JsonBodies;

impl RequestFilter for JsonBodies {
    fn name(&self) -> &'static str {
        "content-type-guard"
    }

    fn check(&self, head: RequestHead<'_>) -> Result<(), AppError> {
        let carries_body = matches!(*head.method, Method::POST | Method::PUT | Method::PATCH);
        if !carries_body || !head.uri.path().starts_with("/api/") {
            return Ok(());
        }

        let content_type = head
            .headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();

        // Compared on the media type alone: `application/json; charset=utf-8`
        // is the same thing and arrives from plenty of clients.
        let media_type = content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();

        if media_type == "application/json" {
            Ok(())
        } else {
            Err(AppError::BadRequest(
                "this endpoint accepts application/json".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, Uri, Version};

    fn head<'a>(method: &'a Method, uri: &'a Uri, headers: &'a HeaderMap) -> RequestHead<'a> {
        RequestHead {
            method,
            uri,
            headers,
            version: Version::HTTP_11,
        }
    }

    fn limits() -> PathLimits {
        PathLimits {
            max_path: 2048,
            max_query: 4096,
            max_pairs: 32,
            allow_duplicate_query: false,
        }
    }

    fn check_path(raw: &str) -> Result<(), AppError> {
        let uri: Uri = raw.parse().unwrap();
        let headers = HeaderMap::new();
        limits().check(head(&Method::GET, &uri, &headers))
    }

    #[test]
    fn poisoned_paths_are_refused() {
        for raw in [
            "/api/v1/%2e%2e/notes",
            "/api/v1/%2E%2E/notes",
            "/api/v1/notes%2fsecret",
            "/api/v1/..%5cnotes",
            "/api/v1/../notes",
            "/api/v1/./notes",
            "/api/v1/notes\\admin",
        ] {
            assert!(check_path(raw).is_err(), "{raw} should be refused");
        }
    }

    #[test]
    fn ordinary_paths_and_queries_pass() {
        for raw in [
            "/api/v1/notes",
            "/api/v1/notes?limit=5&offset=10",
            "/health/live",
            "/",
            "/assets/app.4f2c.js",
        ] {
            assert!(check_path(raw).is_ok(), "{raw} should be allowed");
        }
    }

    #[test]
    fn a_repeated_query_key_is_refused_unless_allowed() {
        assert!(check_path("/api/v1/notes?limit=1&limit=2").is_err());

        let permissive = PathLimits {
            allow_duplicate_query: true,
            ..limits()
        };
        let uri: Uri = "/api/v1/notes?limit=1&limit=2".parse().unwrap();
        let headers = HeaderMap::new();
        assert!(
            permissive.check(head(&Method::GET, &uri, &headers)).is_ok(),
            "the setting must actually relax it"
        );
    }

    #[test]
    fn lengths_are_bounded() {
        let long = format!("/api/v1/{}", "a".repeat(3000));
        assert!(check_path(&long).is_err());

        let many: String = (0..40)
            .map(|index| format!("k{index}=1"))
            .collect::<Vec<_>>()
            .join("&");
        assert!(check_path(&format!("/api/v1/notes?{many}")).is_err());
    }

    #[test]
    fn only_json_bodies_reach_the_api() {
        let uri: Uri = "/api/v1/notes".parse().unwrap();

        let mut json = HeaderMap::new();
        json.insert(
            "content-type",
            "application/json; charset=utf-8".parse().unwrap(),
        );
        assert!(JsonBodies.check(head(&Method::POST, &uri, &json)).is_ok());

        let mut form = HeaderMap::new();
        form.insert(
            "content-type",
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        assert!(
            JsonBodies.check(head(&Method::POST, &uri, &form)).is_err(),
            "a cross-origin form post must not reach a handler"
        );

        // A GET carries no body, so the rule does not apply to it.
        let empty = HeaderMap::new();
        assert!(JsonBodies.check(head(&Method::GET, &uri, &empty)).is_ok());

        // Neither does it apply outside the API.
        let page: Uri = "/index.html".parse().unwrap();
        assert!(JsonBodies.check(head(&Method::POST, &page, &form)).is_ok());
    }

    #[test]
    fn only_the_listed_methods_are_allowed() {
        let allowed = AllowedMethods(vec![Method::GET, Method::POST]);
        let uri: Uri = "/api/v1/notes".parse().unwrap();
        let headers = HeaderMap::new();

        assert!(allowed.check(head(&Method::GET, &uri, &headers)).is_ok());
        assert!(allowed.check(head(&Method::TRACE, &uri, &headers)).is_err());
    }

    #[test]
    fn a_host_outside_the_allowlist_is_refused() {
        let allowed = AllowedHosts(vec!["bastionrs.dev".into()]);
        let uri: Uri = "/api/v1/notes".parse().unwrap();

        let mut ours = HeaderMap::new();
        ours.insert("host", "bastionrs.dev:443".parse().unwrap());
        assert!(allowed.check(head(&Method::GET, &uri, &ours)).is_ok());

        let mut theirs = HeaderMap::new();
        theirs.insert("host", "evil.example".parse().unwrap());
        assert!(allowed.check(head(&Method::GET, &uri, &theirs)).is_err());
    }
}
