//! Response hardening headers.
//!
//! These are cheap, apply to every response, and remove whole classes of
//! browser-side attacks. They are set unconditionally rather than per-route so
//! a new endpoint cannot be shipped without them.

use axum::http::{HeaderName, HeaderValue, header};
use tower_http::set_header::SetResponseHeaderLayer;

/// A JSON API serves no HTML, scripts, or frames, so the policy can deny
/// essentially everything.
const CONTENT_SECURITY_POLICY: &str =
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; sandbox";

const PERMISSIONS_POLICY: &str = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";

/// Policy for served pages, which — unlike the API — legitimately load styles,
/// scripts, and images. Still same-origin only, with no inline execution: a
/// frontend that needs `unsafe-inline` should move that code into a file
/// rather than have every page relax the policy.
const PAGE_CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// One year, including subdomains, and preload-eligible. Only meaningful over
/// HTTPS; browsers ignore it on plaintext connections.
const STRICT_TRANSPORT_SECURITY: &str = "max-age=31536000; includeSubDomains; preload";

macro_rules! static_header {
    ($name:expr, $value:expr) => {
        SetResponseHeaderLayer::overriding($name, HeaderValue::from_static($value))
    };
}

/// Layers applied to every response, outermost first.
pub struct SecurityHeaders;

impl SecurityHeaders {
    pub fn content_security_policy() -> SetResponseHeaderLayer<HeaderValue> {
        static_header!(header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY)
    }

    pub fn no_sniff() -> SetResponseHeaderLayer<HeaderValue> {
        static_header!(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
    }

    pub fn frame_options() -> SetResponseHeaderLayer<HeaderValue> {
        static_header!(header::X_FRAME_OPTIONS, "DENY")
    }

    pub fn referrer_policy() -> SetResponseHeaderLayer<HeaderValue> {
        static_header!(header::REFERRER_POLICY, "no-referrer")
    }

    pub fn permissions_policy() -> SetResponseHeaderLayer<HeaderValue> {
        static_header!(
            HeaderName::from_static("permissions-policy"),
            PERMISSIONS_POLICY
        )
    }

    pub fn cross_origin_resource_policy() -> SetResponseHeaderLayer<HeaderValue> {
        static_header!(
            HeaderName::from_static("cross-origin-resource-policy"),
            "same-origin"
        )
    }

    pub fn cross_origin_opener_policy() -> SetResponseHeaderLayer<HeaderValue> {
        static_header!(
            HeaderName::from_static("cross-origin-opener-policy"),
            "same-origin"
        )
    }

    /// Responses are per-user; caching them anywhere shared is a data leak.
    pub fn no_store() -> SetResponseHeaderLayer<HeaderValue> {
        static_header!(header::CACHE_CONTROL, "no-store, no-cache, must-revalidate")
    }

    pub fn hsts() -> SetResponseHeaderLayer<HeaderValue> {
        static_header!(header::STRICT_TRANSPORT_SECURITY, STRICT_TRANSPORT_SECURITY)
    }

    /// The CSP for served pages. Kept separate from the API policy so that
    /// adding a frontend cannot quietly loosen the policy protecting the API.
    pub fn page_content_security_policy() -> SetResponseHeaderLayer<HeaderValue> {
        static_header!(
            header::CONTENT_SECURITY_POLICY,
            PAGE_CONTENT_SECURITY_POLICY
        )
    }

    /// Static assets are public and unchanging between deploys; `no-store`
    /// would make every page load re-fetch them. Build pipelines that emit
    /// content-hashed filenames can raise this considerably.
    pub fn asset_cache() -> SetResponseHeaderLayer<HeaderValue> {
        static_header!(header::CACHE_CONTROL, "public, max-age=3600")
    }
}
