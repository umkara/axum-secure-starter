//! Serving.
//!
//! Both the binary and the integration tests go through here, so a connection
//! limit or timeout that the tests verify is necessarily the same one
//! production runs. Wiring this separately in each place is how a control ends
//! up tested but not deployed.

use std::{net::SocketAddr, time::Duration};

use anyhow::Context;
use axum::ServiceExt;
use axum_server::{
    Handle, Server,
    accept::Accept,
    service::{MakeService, SendService},
    tls_rustls::{RustlsAcceptor, RustlsConfig},
};
use hyper::{Request, body::Incoming};
use hyper_util::rt::TokioTimer;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::Layer;

use crate::{
    api::path::CanonicalPathLayer,
    config::AppConfig,
    net::ConnectionLimitAcceptor,
    plugin::{Registry, RequestFilterLayer},
    state::AppState,
};

/// Serves until the handle is told to shut down.
///
/// TLS is used when the configuration provides a certificate. The listener is
/// passed in already bound so the caller can report the real port — useful when
/// binding to port 0.
pub async fn serve(
    listener: std::net::TcpListener,
    state: AppState,
    plugins: Registry,
    handle: Handle<SocketAddr>,
) -> anyhow::Result<()> {
    let config = state.config_handle();

    // Resolved before the acceptor exists, so a plugin that refuses its
    // settings stops the server rather than failing on somebody's first
    // request.
    let plugins = plugins
        .resolve(&config)
        .context("a plugin refused its configuration")?;
    tracing::info!(plugins = ?plugins.enabled(), "middleware plugins resolved");

    // Wraps the router rather than sitting inside it: middleware added with
    // `Router::layer` runs after route matching, which is too late to decide
    // which route a path should reach.
    //
    // Pre-routing filters sit above canonicalisation so they see the URI the
    // client actually sent — and because they can only reject, canonicalisation
    // still runs underneath whatever they decide.
    let app = RequestFilterLayer::new(plugins.filters())
        .layer(CanonicalPathLayer.layer(crate::api::build_router(state, &plugins)));
    let make_service = ServiceExt::<axum::extract::Request>::into_make_service_with_connect_info::<
        SocketAddr,
    >(app);

    // Caps open sockets. The request-level limits never see a connection that
    // holds a descriptor without completing a request.
    let connection_limit = ConnectionLimitAcceptor::new(config.server.max_connections);

    match &config.tls {
        Some(tls) => {
            let tls_config = RustlsConfig::from_pem_file(&tls.cert_path, &tls.key_path)
                .await
                .context("failed to load the TLS certificate or key")?;

            let acceptor = RustlsAcceptor::new(tls_config)
                .handshake_timeout(config.server.tls_handshake_timeout)
                .acceptor(connection_limit);

            let mut server = axum_server::from_tcp(listener)
                .context("failed to adopt the listener")?
                .acceptor(acceptor);
            apply_deadlines(&mut server, &config);

            server
                .handle(handle)
                .serve(make_service)
                .await
                .context("server error")
        }
        None => {
            let mut server = axum_server::from_tcp(listener)
                .context("failed to adopt the listener")?
                .acceptor(connection_limit);
            apply_deadlines(&mut server, &config);

            server
                .handle(handle)
                .serve(make_service)
                .await
                .context("server error")
        }
    }
}

/// Binds a non-blocking listener. Tokio refuses to adopt a blocking socket.
pub fn bind(addr: SocketAddr) -> anyhow::Result<std::net::TcpListener> {
    let listener =
        std::net::TcpListener::bind(addr).with_context(|| format!("failed to bind {addr}"))?;
    listener
        .set_nonblocking(true)
        .context("failed to put the listener in non-blocking mode")?;
    Ok(listener)
}

/// Connection-level deadlines.
///
/// `header_read_timeout` is the slowloris control: it bounds how long a client
/// may take to finish sending request headers. The request timeout in the
/// middleware stack cannot cover this, because until the headers are complete
/// there is no request for it to time.
fn apply_deadlines<A, Acc>(server: &mut Server<A, Acc>, config: &AppConfig)
where
    A: axum_server::Address,
{
    let deadline: Duration = config.server.header_read_timeout;
    let builder = server.http_builder();
    // hyper only arms these deadlines when a timer is installed; without one it
    // panics on the first connection rather than silently skipping them.
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(deadline);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(Some(deadline))
        .keep_alive_timeout(deadline)
        // One connection can otherwise open and cancel streams faster than the
        // per-connection limit implies any cost — the rapid-reset shape.
        .max_concurrent_streams(config.server.max_concurrent_streams);
}

/// Compile-time proof that the acceptor stack still satisfies what `serve`
/// requires; a mismatch here is far easier to read than the error from the
/// `serve` call itself.
fn _assert_acceptor_bounds<I, S>()
where
    ConnectionLimitAcceptor: Accept<I, S>,
    <ConnectionLimitAcceptor as Accept<I, S>>::Stream: AsyncRead + AsyncWrite + Unpin + Send,
    <ConnectionLimitAcceptor as Accept<I, S>>::Service: SendService<Request<Incoming>> + Send,
    I: AsyncRead + AsyncWrite + Unpin + Send,
    S: MakeService<SocketAddr, Request<Incoming>>,
{
}
