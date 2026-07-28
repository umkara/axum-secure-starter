//! Response hardening headers.
//!
//! These are cheap, apply to every response, and remove whole classes of
//! browser-side attacks. They are set unconditionally rather than per-route so
//! a new endpoint cannot be shipped without them.

use axum::http::{HeaderName, HeaderValue, Response, header};
use tower::util::MapResponseLayer;
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

/// Chooses a `Cache-Control` value by inspecting the response it will be
/// attached to. Named so the layer's type stays readable.
pub type CachePolicy<B> = fn(&Response<B>) -> Option<HeaderValue>;

/// The headers that belong on every response, whatever produced it.
///
/// Data rather than a stack of layers, because a layer can only reach responses
/// the router produced. Rejections made *above* the router — a pre-routing
/// filter's, path canonicalisation's — and the substitute response
/// `CatchPanicLayer` returns are all responses a layer inside the router never
/// sees, and they need these headers just as much.
///
/// Branch-specific headers are deliberately absent: the content security policy
/// differs between the API and served pages, and `Cache-Control` between the
/// API and static assets. Applying either from here would clobber the other.
const ALWAYS: [(HeaderName, HeaderValue); 7] = [
    (
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static(STRICT_TRANSPORT_SECURITY),
    ),
    (
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    ),
    (header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")),
    (
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    ),
    (
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(PERMISSIONS_POLICY),
    ),
    (
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    ),
    (
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    ),
];

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

    /// Writes [`ALWAYS`] onto a response, overriding whatever is there.
    ///
    /// Public because it is the only way to harden a response produced outside
    /// a router — and because a caller that assembles its own stack should not
    /// have to re-derive this list to match.
    /// Generic over the body because it is applied in two places whose body
    /// types differ: `CatchPanicLayer` boxes the body it passes on, and the
    /// copy above the router still sees the plain one.
    pub fn harden<B>(mut response: Response<B>) -> Response<B> {
        let headers = response.headers_mut();
        for (name, value) in ALWAYS {
            headers.insert(name, value);
        }
        response
    }

    /// [`SecurityHeaders::harden`] as a layer.
    ///
    /// One layer writing seven headers rather than seven layers writing one
    /// each: the same work, one less service in the stack, and — the reason it
    /// changed — a form that can also be applied above the router.
    pub fn hardening<B>() -> MapResponseLayer<fn(Response<B>) -> Response<B>> {
        MapResponseLayer::new(Self::harden as fn(Response<B>) -> Response<B>)
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

    /// Caching for served files, chosen per response.
    ///
    /// HTML gets `no-cache`, meaning "revalidate before reusing" rather than
    /// "never cache" — the conditional request is cheap and usually answered
    /// with a 304. Everything else may be held for an hour.
    ///
    /// The distinction matters: a blanket lifetime on `index.html` leaves
    /// browsers showing a stale page for that long after every deploy, while
    /// the document is the one file that must always be fresh, because it is
    /// what points at the current asset filenames.
    pub fn asset_cache<B>() -> SetResponseHeaderLayer<CachePolicy<B>> {
        fn policy<B>(response: &Response<B>) -> Option<HeaderValue> {
            let is_document = response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("text/html"));

            Some(if is_document {
                HeaderValue::from_static("no-cache")
            } else {
                HeaderValue::from_static("public, max-age=3600")
            })
        }

        // Annotated rather than cast with `as fn(_) -> _`: the inferred cast
        // pins a single lifetime, and this has to stay valid for any borrow of
        // the response.
        let policy: CachePolicy<B> = policy::<B>;
        SetResponseHeaderLayer::overriding(header::CACHE_CONTROL, policy)
    }
}
