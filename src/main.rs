//! Entry point: load configuration, wire the application, serve it over TLS
//! (or plain HTTP in development), and shut down without dropping requests.

use std::{net::SocketAddr, time::Duration};

use anyhow::Context;
use axum_secure_starter::{
    config::AppConfig, db, repository::Repositories, server, service::AdminBootstrap,
    state::AppState, telemetry,
};
use axum_server::Handle;
use tokio::signal;

/// How often expired refresh tokens are swept out of the database.
const TOKEN_CLEANUP_INTERVAL: Duration = Duration::from_secs(60 * 60);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // A missing .env is fine; real deployments inject the environment directly.
    let _ = dotenvy::dotenv();

    let config = AppConfig::from_env().context("invalid configuration")?;
    telemetry::init(config.environment);

    // Pin the rustls crypto provider explicitly. With a single provider in the
    // build this is redundant today, but it turns a future second provider into
    // a start-up decision rather than a panic on the first TLS handshake.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let config = std::sync::Arc::new(config);
    let pool = db::connect(&config.database).await?;
    let state = AppState::new(config.clone(), Repositories::sqlite(pool));

    if let Some(bootstrap) = &config.bootstrap_admin {
        match state
            .auth()
            .ensure_admin(&bootstrap.email, &bootstrap.password)
            .await?
        {
            AdminBootstrap::Created => tracing::warn!(
                "administrator created from APP_BOOTSTRAP_ADMIN_*; unset both variables now that it exists"
            ),
            AdminBootstrap::Promoted => tracing::warn!(
                "existing account promoted to administrator; its password was left unchanged"
            ),
            AdminBootstrap::AlreadyAdmin => {
                tracing::info!("bootstrap administrator already present; nothing to do")
            }
        }
    }

    tracing::info!(
        concurrent_hashes = config.security.max_concurrent_hashes,
        hash_memory_ceiling_mib = config.security.max_concurrent_hashes
            * axum_secure_starter::security::password::MEMORY_PER_HASH_BYTES
            / (1024 * 1024),
        "password hashing admission limit"
    );

    spawn_token_cleanup(state.clone());

    let listener = server::bind(config.server.addr)?;
    let addr = listener.local_addr().unwrap_or(config.server.addr);

    if config.tls.is_some() {
        tracing::info!(%addr, max_connections = config.server.max_connections, "listening (https)");
    } else {
        tracing::warn!(
            %addr,
            max_connections = config.server.max_connections,
            "listening (http) — TLS is disabled; permitted outside production only"
        );
    }

    let handle: Handle<SocketAddr> = Handle::new();
    tokio::spawn(shutdown_signal(
        handle.clone(),
        config.server.shutdown_grace,
    ));

    server::serve(listener, state, handle).await?;

    tracing::info!("shutdown complete");
    Ok(())
}

/// Periodically deletes refresh tokens that can no longer be redeemed, so the
/// table does not grow without bound.
fn spawn_token_cleanup(state: AppState) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(TOKEN_CLEANUP_INTERVAL);
        // Skip the immediate first tick; start-up is busy enough.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match state.janitor().purge_expired().await {
                Ok(0) => {}
                Ok(removed) => tracing::info!(removed, "purged expired refresh tokens"),
                Err(err) => tracing::error!(error = %err, "refresh token cleanup failed"),
            }
        }
    });
}

/// Waits for SIGINT or SIGTERM, then lets in-flight requests finish.
async fn shutdown_signal(handle: Handle<SocketAddr>, grace: Duration) {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to listen for SIGINT");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to listen for SIGTERM")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received SIGINT"),
        _ = terminate => tracing::info!("received SIGTERM"),
    }

    tracing::info!(grace_secs = grace.as_secs(), "draining connections");
    handle.graceful_shutdown(Some(grace));
}
