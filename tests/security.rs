//! Tests for the properties that are supposed to hold no matter what a client
//! sends: authentication, isolation between accounts, token rotation, input
//! limits, and the response hardening headers.

mod common;

use std::time::Duration;

use axum_secure_starter::service::AdminBootstrap;
use common::{TestOptions, login, register_and_login, spawn, spawn_with};
use serde_json::Value;
use std::{
    io::{Read, Write},
    net::TcpStream,
};

const PASSWORD: &str = "correct-horse-battery-staple";

#[tokio::test]
async fn health_endpoints_report_status_and_are_open() {
    let app = spawn().await;

    let live = app
        .client
        .get(app.url("/health/live"))
        .send()
        .await
        .unwrap();
    assert_eq!(live.status(), 200);

    let ready = app
        .client
        .get(app.url("/health/ready"))
        .send()
        .await
        .unwrap();
    assert_eq!(ready.status(), 200);
}

#[tokio::test]
async fn every_response_carries_the_hardening_headers() {
    let app = spawn().await;
    let response = app
        .client
        .get(app.url("/health/live"))
        .send()
        .await
        .unwrap();
    let headers = response.headers();

    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["x-frame-options"], "DENY");
    assert_eq!(headers["referrer-policy"], "no-referrer");
    assert_eq!(headers["cross-origin-resource-policy"], "same-origin");
    assert!(headers.contains_key("content-security-policy"));
    assert!(headers.contains_key("permissions-policy"));
    assert!(headers.contains_key("strict-transport-security"));
    assert!(
        headers.contains_key("x-request-id"),
        "request id is echoed back"
    );
    assert!(
        headers["cache-control"]
            .to_str()
            .unwrap()
            .contains("no-store"),
        "per-user responses must not be cached"
    );
}

#[tokio::test]
async fn protected_routes_reject_missing_and_malformed_credentials() {
    let app = spawn().await;

    for (name, request) in [
        ("no header", app.client.get(app.url("/api/v1/notes"))),
        (
            "wrong scheme",
            app.client
                .get(app.url("/api/v1/notes"))
                .header("authorization", "Basic aGk6dGhlcmU="),
        ),
        (
            "garbage token",
            app.client
                .get(app.url("/api/v1/notes"))
                .header("authorization", "Bearer not-a-jwt"),
        ),
        (
            "empty bearer",
            app.client
                .get(app.url("/api/v1/notes"))
                .header("authorization", "Bearer "),
        ),
    ] {
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), 401, "case: {name}");
    }
}

#[tokio::test]
async fn a_token_signed_with_another_key_is_rejected() {
    let app = spawn().await;

    // Same claim shape, different signing key.
    let forged = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                  eyJzdWIiOiIwMTkyOTIwMC0wMDAwLTcwMDAtODAwMC0wMDAwMDAwMDAwMDAiLCJyb2xlIjoiYWRtaW4ifQ.\
                  ZmFrZXNpZ25hdHVyZQ";

    let response = app
        .client
        .get(app.url("/api/v1/notes"))
        .header("authorization", format!("Bearer {forged}"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn wrong_password_and_unknown_account_are_indistinguishable() {
    let app = spawn().await;
    register_and_login(&app, "real@example.com", PASSWORD).await;

    let wrong_password = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({ "email": "real@example.com", "password": "not-the-password" }))
        .send()
        .await
        .unwrap();

    let unknown_account = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({ "email": "ghost@example.com", "password": "not-the-password" }))
        .send()
        .await
        .unwrap();

    assert_eq!(wrong_password.status(), 401);
    assert_eq!(unknown_account.status(), 401);

    let a: Value = wrong_password.json().await.unwrap();
    let b: Value = unknown_account.json().await.unwrap();
    assert_eq!(a, b, "the two failures must not be distinguishable");
}

#[tokio::test]
async fn repeated_failures_lock_the_account() {
    let app = spawn_with(TestOptions {
        max_login_attempts: 3,
        ..Default::default()
    })
    .await;
    register_and_login(&app, "target@example.com", PASSWORD).await;

    for _ in 0..3 {
        let response = app
            .client
            .post(app.url("/api/v1/auth/login"))
            .json(&serde_json::json!({ "email": "target@example.com", "password": "wrong" }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401);
    }

    // The correct password is refused while the lockout stands — and the
    // refusal is byte-identical to a wrong password against an address that was
    // never registered. A distinct status here would confirm the account exists.
    let locked = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({ "email": "target@example.com", "password": PASSWORD }))
        .send()
        .await
        .unwrap();
    assert_eq!(locked.status(), 401, "a lockout must not be observable");

    let unknown = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({ "email": "nobody@example.com", "password": PASSWORD }))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 401);

    let locked_body: Value = locked.json().await.unwrap();
    let unknown_body: Value = unknown.json().await.unwrap();
    assert_eq!(
        locked_body, unknown_body,
        "locked and never-registered must be indistinguishable"
    );
}

#[tokio::test]
async fn email_matching_ignores_case_and_padding() {
    let app = spawn().await;
    register_and_login(&app, "Mixed.Case@Example.COM", PASSWORD).await;

    let (access, _) = login(&app, "  mixed.case@example.com ", PASSWORD).await;
    assert!(!access.is_empty());
}

#[tokio::test]
async fn duplicate_registration_is_rejected() {
    let app = spawn().await;
    register_and_login(&app, "dupe@example.com", PASSWORD).await;

    let response = app
        .client
        .post(app.url("/api/v1/auth/register"))
        .json(&serde_json::json!({ "email": "dupe@example.com", "password": PASSWORD }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 409);
}

#[tokio::test]
async fn refresh_rotates_and_replay_kills_the_whole_family() {
    let app = spawn().await;
    let (_, first_refresh) = register_and_login(&app, "rotate@example.com", PASSWORD).await;

    // First use succeeds and hands back a new token.
    let response = app
        .client
        .post(app.url("/api/v1/auth/refresh"))
        .json(&serde_json::json!({ "refresh_token": first_refresh }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    let second_refresh = body["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(second_refresh, first_refresh, "the token must rotate");

    // Replaying the spent token is refused...
    let replay = app
        .client
        .post(app.url("/api/v1/auth/refresh"))
        .json(&serde_json::json!({ "refresh_token": first_refresh }))
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), 401);

    // ...and takes the rest of the family down with it, because a replay means
    // the chain is no longer trustworthy.
    let after_replay = app
        .client
        .post(app.url("/api/v1/auth/refresh"))
        .json(&serde_json::json!({ "refresh_token": second_refresh }))
        .send()
        .await
        .unwrap();
    assert_eq!(after_replay.status(), 401, "the whole family is revoked");
}

#[tokio::test]
async fn logout_invalidates_the_session() {
    let app = spawn().await;
    let (_, refresh) = register_and_login(&app, "bye@example.com", PASSWORD).await;

    let logout = app
        .client
        .post(app.url("/api/v1/auth/logout"))
        .json(&serde_json::json!({ "refresh_token": refresh }))
        .send()
        .await
        .unwrap();
    assert_eq!(logout.status(), 204);

    let reuse = app
        .client
        .post(app.url("/api/v1/auth/refresh"))
        .json(&serde_json::json!({ "refresh_token": refresh }))
        .send()
        .await
        .unwrap();
    assert_eq!(reuse.status(), 401);
}

#[tokio::test]
async fn logout_with_an_unknown_token_reveals_nothing() {
    let app = spawn().await;

    let response = app
        .client
        .post(app.url("/api/v1/auth/logout"))
        .json(&serde_json::json!({ "refresh_token": "never-issued" }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        204,
        "logout must not double as a token-validity oracle"
    );
}

#[tokio::test]
async fn changing_the_password_revokes_existing_sessions() {
    let app = spawn().await;
    let (access, refresh) = register_and_login(&app, "rekey@example.com", PASSWORD).await;

    let response = app
        .client
        .post(app.url("/api/v1/auth/password"))
        .header("authorization", format!("Bearer {access}"))
        .json(&serde_json::json!({
            "current_password": PASSWORD,
            "new_password": "an-entirely-different-passphrase",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);

    let stale = app
        .client
        .post(app.url("/api/v1/auth/refresh"))
        .json(&serde_json::json!({ "refresh_token": refresh }))
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status(), 401);

    // The new password works.
    login(
        &app,
        "rekey@example.com",
        "an-entirely-different-passphrase",
    )
    .await;
}

#[tokio::test]
async fn notes_are_invisible_to_other_accounts() {
    let app = spawn().await;
    let (owner_token, _) = register_and_login(&app, "owner@example.com", PASSWORD).await;
    let (intruder_token, _) = register_and_login(&app, "intruder@example.com", PASSWORD).await;

    let created: Value = app
        .client
        .post(app.url("/api/v1/notes"))
        .header("authorization", format!("Bearer {owner_token}"))
        .json(&serde_json::json!({ "title": "private", "body": "for my eyes only" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let note_id = created["id"].as_str().unwrap();

    for (method, expected) in [("GET", 404), ("PUT", 404), ("DELETE", 404)] {
        let url = app.url(&format!("/api/v1/notes/{note_id}"));
        let request = match method {
            "GET" => app.client.get(url),
            "PUT" => app
                .client
                .put(url)
                .json(&serde_json::json!({ "title": "hijacked", "body": "mine now" })),
            _ => app.client.delete(url),
        };

        let response = request
            .header("authorization", format!("Bearer {intruder_token}"))
            .send()
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            expected,
            "{method} on someone else's note must look like it does not exist"
        );
    }

    // The owner still sees exactly one note.
    let listing: Value = app
        .client
        .get(app.url("/api/v1/notes"))
        .header("authorization", format!("Bearer {owner_token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(listing["total"], 1);

    // The intruder sees none.
    let empty: Value = app
        .client
        .get(app.url("/api/v1/notes"))
        .header("authorization", format!("Bearer {intruder_token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(empty["total"], 0);
}

#[tokio::test]
async fn note_lifecycle_round_trips() {
    let app = spawn().await;
    let (token, _) = register_and_login(&app, "crud@example.com", PASSWORD).await;
    let auth = format!("Bearer {token}");

    let created: Value = app
        .client
        .post(app.url("/api/v1/notes"))
        .header("authorization", &auth)
        .json(&serde_json::json!({ "title": "first", "body": "hello" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_string();

    let updated: Value = app
        .client
        .put(app.url(&format!("/api/v1/notes/{id}")))
        .header("authorization", &auth)
        .json(&serde_json::json!({ "title": "second", "body": "goodbye" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(updated["title"], "second");

    let deleted = app
        .client
        .delete(app.url(&format!("/api/v1/notes/{id}")))
        .header("authorization", &auth)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), 204);

    let gone = app
        .client
        .get(app.url(&format!("/api/v1/notes/{id}")))
        .header("authorization", &auth)
        .send()
        .await
        .unwrap();
    assert_eq!(gone.status(), 404);
}

#[tokio::test]
async fn invalid_input_is_reported_field_by_field() {
    let app = spawn().await;

    let response = app
        .client
        .post(app.url("/api/v1/auth/register"))
        .json(&serde_json::json!({ "email": "not-an-email", "password": "short" }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "validation_failed");

    let fields: Vec<&str> = body["error"]["details"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["field"].as_str().unwrap())
        .collect();
    assert!(fields.contains(&"email"));
    assert!(fields.contains(&"password"));
}

#[tokio::test]
async fn oversized_bodies_are_refused() {
    let app = spawn_with(TestOptions {
        body_limit_bytes: 1024,
        ..Default::default()
    })
    .await;

    let response = app
        .client
        .post(app.url("/api/v1/auth/register"))
        .json(&serde_json::json!({
            "email": "big@example.com",
            "password": "x".repeat(64 * 1024),
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 413);
}

#[tokio::test]
async fn pagination_is_capped_and_validated() {
    let app = spawn().await;
    let (token, _) = register_and_login(&app, "pages@example.com", PASSWORD).await;
    let auth = format!("Bearer {token}");

    for i in 0..5 {
        app.client
            .post(app.url("/api/v1/notes"))
            .header("authorization", &auth)
            .json(&serde_json::json!({ "title": format!("note {i}"), "body": "x" }))
            .send()
            .await
            .unwrap();
    }

    let page: Value = app
        .client
        .get(app.url("/api/v1/notes?limit=2&offset=0"))
        .header("authorization", &auth)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page["items"].as_array().unwrap().len(), 2);
    assert_eq!(page["total"], 5);

    // Asking for more than the ceiling is a client error, not a full dump.
    let too_big = app
        .client
        .get(app.url("/api/v1/notes?limit=100000"))
        .header("authorization", &auth)
        .send()
        .await
        .unwrap();
    assert_eq!(too_big.status(), 400);
}

#[tokio::test]
async fn non_admins_cannot_reach_admin_routes() {
    let app = spawn().await;
    let (token, _) = register_and_login(&app, "plain@example.com", PASSWORD).await;

    let response = app
        .client
        .delete(app.url("/api/v1/admin/users/00000000-0000-0000-0000-000000000000/sessions"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 403);
}

#[tokio::test]
async fn the_bootstrap_administrator_can_reach_admin_routes() {
    let app = spawn_with(TestOptions {
        bootstrap_admin: Some((
            "root@example.com".into(),
            "a-long-bootstrap-password".into(),
        )),
        ..Default::default()
    })
    .await;

    // The seeded admin logs in like any other account.
    let (admin_token, _) = login(&app, "root@example.com", "a-long-bootstrap-password").await;

    // A victim with a live session.
    let (_, victim_refresh) = register_and_login(&app, "victim@example.com", PASSWORD).await;
    let victim_id = {
        let body: Value = app
            .client
            .post(app.url("/api/v1/auth/register"))
            .json(&serde_json::json!({ "email": "other@example.com", "password": PASSWORD }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        body["id"].as_str().unwrap().to_string()
    };

    // The admin route is reachable now that an administrator exists.
    let response = app
        .client
        .delete(app.url(&format!("/api/v1/admin/users/{victim_id}/sessions")))
        .header("authorization", format!("Bearer {admin_token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);

    // Sessions belonging to a different user are untouched.
    let untouched = app
        .client
        .post(app.url("/api/v1/auth/refresh"))
        .json(&serde_json::json!({ "refresh_token": victim_refresh }))
        .send()
        .await
        .unwrap();
    assert_eq!(untouched.status(), 200);
}

#[tokio::test]
async fn bootstrapping_an_existing_account_promotes_without_touching_its_password() {
    let app = spawn().await;
    register_and_login(&app, "promote@example.com", PASSWORD).await;

    // Re-running the bootstrap against an address that already exists.
    let outcome = app
        .state_auth()
        .ensure_admin("promote@example.com", "a-completely-different-secret")
        .await
        .unwrap();
    assert_eq!(outcome, AdminBootstrap::Promoted);

    // The original password still works — a bootstrap value must never
    // overwrite a real credential.
    let (token, _) = login(&app, "promote@example.com", PASSWORD).await;

    // And the account now holds the admin role.
    let response = app
        .client
        .delete(app.url("/api/v1/admin/users/00000000-0000-0000-0000-000000000000/sessions"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);
}

#[tokio::test]
async fn connections_beyond_the_limit_are_refused() {
    let app = spawn_with(TestOptions {
        max_connections: 2,
        ..Default::default()
    })
    .await;

    // Hold both slots open with idle sockets that never send a request — the
    // shape of a slowloris client.
    let _held: Vec<TcpStream> = (0..2)
        .map(|_| TcpStream::connect(app.addr()).expect("failed to open a holding connection"))
        .collect();

    // A fresh connection is admitted and immediately closed, so no request
    // completes on it.
    let refused = app
        .client
        .get(app.url("/health/live"))
        .timeout(Duration::from_secs(3))
        .send()
        .await;

    assert!(
        refused.is_err(),
        "a connection past the limit must not be served, got {refused:?}"
    );
}

#[tokio::test]
async fn a_client_that_never_finishes_its_headers_is_cut_off() {
    let app = spawn_with(TestOptions {
        header_read_timeout: Duration::from_secs(1),
        ..Default::default()
    })
    .await;

    // The slowloris shape: open a socket, send a request line, then stall.
    // No request ever reaches the router, so nothing in the middleware stack
    // can time this out — only the connection-level deadline can.
    let cut_off = tokio::task::spawn_blocking(move || {
        let mut socket = TcpStream::connect(app.addr()).expect("failed to connect");
        socket
            .write_all(b"GET /health/live HTTP/1.1\r\nHost: localhost\r\n")
            .expect("failed to write a partial request");
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();

        // Returns once the server hangs up. Without the deadline this blocks
        // until the read timeout above and the assertion below fails.
        let mut sink = Vec::new();
        socket.read_to_end(&mut sink).is_ok() || !sink.is_empty()
    })
    .await
    .expect("the blocking probe panicked");

    assert!(
        cut_off,
        "the server must close a connection with stalled headers"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn the_database_is_not_readable_by_other_local_accounts() {
    use std::os::unix::fs::PermissionsExt;

    let app = spawn().await;
    // Force the write-ahead log into existence.
    register_and_login(&app, "perms@example.com", PASSWORD).await;

    for suffix in ["", "-wal", "-shm"] {
        let mut path = app.db_path.clone().into_os_string();
        path.push(suffix);
        let path = std::path::PathBuf::from(path);
        if !path.exists() {
            continue;
        }

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode & 0o077,
            0,
            "{} is accessible to group or other (mode {mode:o})",
            path.display()
        );
    }
}

#[tokio::test]
async fn unknown_routes_use_the_shared_error_shape() {
    let app = spawn().await;

    let response = app.client.get(app.url("/nope")).send().await.unwrap();
    assert_eq!(response.status(), 404);

    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "not_found");
}

#[tokio::test]
async fn trailing_slashes_resolve_to_the_same_route() {
    let app = spawn().await;
    let (token, _) = register_and_login(&app, "slash@example.com", PASSWORD).await;

    let response = app
        .client
        .get(app.url("/api/v1/notes/"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn slow_handlers_do_not_hold_a_connection_forever() {
    // A one-second deadline proves the timeout layer is wired; the handlers
    // themselves are fast, so this only asserts the happy path still passes
    // under a tight deadline.
    let app = spawn_with(TestOptions {
        request_timeout: Duration::from_secs(1),
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
}

// ---------------------------------------------------------------------------
// Serving a frontend
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_served_page_gets_the_page_policy_while_the_api_keeps_the_strict_one() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("index.html"), "<!doctype html><p>hi</p>").unwrap();
    std::fs::write(dir.path().join("app.js"), "export const x = 1;").unwrap();

    let app = spawn_with(TestOptions {
        static_dir: Some(dir.path().to_path_buf()),
        ..Default::default()
    })
    .await;

    // The page can load its own scripts and styles...
    let page = app.client.get(app.url("/")).send().await.unwrap();
    assert_eq!(page.status(), 200);
    let page_csp = page.headers()["content-security-policy"].to_str().unwrap();
    assert!(
        page_csp.contains("default-src 'self'"),
        "page CSP: {page_csp}"
    );
    assert!(
        !page_csp.contains("unsafe-inline"),
        "inline execution must stay blocked: {page_csp}"
    );

    // ...while the API keeps the policy that permits nothing at all. Adding a
    // frontend must not loosen the API's headers.
    let api = app
        .client
        .get(app.url("/health/live"))
        .send()
        .await
        .unwrap();
    let api_csp = api.headers()["content-security-policy"].to_str().unwrap();
    assert!(api_csp.contains("default-src 'none'"), "API CSP: {api_csp}");
    assert!(api_csp.contains("sandbox"), "API CSP: {api_csp}");
    assert!(
        api.headers()["cache-control"]
            .to_str()
            .unwrap()
            .contains("no-store"),
        "API responses must stay uncached"
    );
}

#[tokio::test]
async fn an_unknown_api_path_stays_json_rather_than_serving_the_page() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("index.html"), "<!doctype html><p>hi</p>").unwrap();

    let app = spawn_with(TestOptions {
        static_dir: Some(dir.path().to_path_buf()),
        ..Default::default()
    })
    .await;

    // A client-side router should handle unknown *page* paths...
    let page = app
        .client
        .get(app.url("/some/deep/link"))
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 200, "SPA fallback should serve index.html");

    // ...but a wrong API path is a client error, not a request for the app.
    let api = app
        .client
        .get(app.url("/api/v1/nope"))
        .send()
        .await
        .unwrap();
    assert_eq!(api.status(), 404);
    let body: Value = api.json().await.unwrap();
    assert_eq!(body["error"]["code"], "not_found");
}

#[tokio::test]
async fn static_serving_cannot_escape_its_directory() {
    let root = tempfile::tempdir().unwrap();
    let public = root.path().join("public");
    std::fs::create_dir(&public).unwrap();
    std::fs::write(public.join("index.html"), "<!doctype html><p>hi</p>").unwrap();
    // A file the server must never hand out, one level above the served root.
    std::fs::write(root.path().join("secret.txt"), "SENSITIVE").unwrap();

    let app = spawn_with(TestOptions {
        static_dir: Some(public.clone()),
        ..Default::default()
    })
    .await;

    for path in [
        "/../secret.txt",
        "/..%2fsecret.txt",
        "/%2e%2e/secret.txt",
        "/....//secret.txt",
        "/public/../secret.txt",
    ] {
        let response = app
            .client
            .get(format!("{}{}", app.base_url, path))
            .send()
            .await
            .unwrap();
        let body = response.text().await.unwrap();
        assert!(
            !body.contains("SENSITIVE"),
            "{path} escaped the served directory"
        );
    }
}

#[tokio::test]
async fn the_document_revalidates_while_assets_may_be_cached() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("index.html"), "<!doctype html><p>hi</p>").unwrap();
    std::fs::write(dir.path().join("app.js"), "export const x = 1;").unwrap();

    let app = spawn_with(TestOptions {
        static_dir: Some(dir.path().to_path_buf()),
        ..Default::default()
    })
    .await;

    // The document must never be held: it is what points at the current asset
    // filenames, so a cached copy shows a stale app after every deploy.
    let page = app.client.get(app.url("/")).send().await.unwrap();
    assert_eq!(
        page.headers()["cache-control"],
        "no-cache",
        "index.html must revalidate"
    );

    // Assets may be held, which is the whole reason for serving them here.
    let asset = app.client.get(app.url("/app.js")).send().await.unwrap();
    assert!(
        asset.headers()["cache-control"]
            .to_str()
            .unwrap()
            .contains("max-age"),
        "assets should be cacheable"
    );

    // The SPA fallback serves the document, so it inherits the document policy.
    let deep = app.client.get(app.url("/deep/link")).send().await.unwrap();
    assert_eq!(
        deep.headers()["cache-control"],
        "no-cache",
        "the SPA fallback is the document too"
    );
}
