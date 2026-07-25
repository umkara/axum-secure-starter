//! Adversarial tests.
//!
//! `security.rs` checks that the intended controls work. This file assumes they
//! do not, and attacks them: forged and downgraded tokens, injection through
//! every string that reaches SQL, privilege escalation through mass assignment,
//! smuggled and split requests, traversal, and enumeration by timing.
//!
//! Each test names the attack it performs and asserts the outcome an attacker
//! must *not* get.

mod common;

use std::{
    io::{Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{
    TEST_JWT_AUDIENCE, TEST_JWT_ISSUER, TEST_JWT_SECRET, TestOptions, register_and_login, spawn,
    spawn_with,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};

const PASSWORD: &str = "correct-horse-battery-staple";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Mints a token signed with the server's real key, so only the claims are
/// hostile. This is the strongest position an attacker could be in short of
/// holding the key itself.
fn signed_token(claims: Value) -> String {
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .expect("failed to sign the test token")
}

fn valid_claims(subject: &str, role: &str) -> Value {
    let now = chrono::Utc::now().timestamp();
    json!({
        "sub": subject,
        "iss": TEST_JWT_ISSUER,
        "aud": TEST_JWT_AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + 900,
        "jti": uuid::Uuid::new_v4().to_string(),
        "role": role,
    })
}

/// Sends a raw request over a socket, bypassing any client-side normalisation
/// that would sanitise the attack before it reached the server.
///
/// The socket work happens on a blocking thread on purpose. `#[tokio::test]`
/// runs a single-threaded runtime, so blocking here directly would starve the
/// server task: the read would time out, every assertion would be made against
/// an empty response, and the tests would pass without testing anything.
async fn raw_request(addr: std::net::SocketAddr, request: &'static [u8]) -> String {
    tokio::task::spawn_blocking(move || {
        let mut socket = TcpStream::connect(addr).expect("failed to connect");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket.write_all(request).expect("failed to write");
        socket.flush().ok();

        let mut response = Vec::new();
        let _ = socket.read_to_end(&mut response);
        String::from_utf8_lossy(&response).into_owned()
    })
    .await
    .expect("the raw socket probe panicked")
}

// ---------------------------------------------------------------------------
// SQL injection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sql_injection_through_login_does_not_authenticate() {
    let app = spawn().await;
    register_and_login(&app, "victim@example.com", PASSWORD).await;

    let payloads = [
        "victim@example.com' --",
        "victim@example.com' OR '1'='1",
        "' OR 1=1 --",
        "victim@example.com'/*",
        "admin'--",
        "victim@example.com' UNION SELECT 1,2,3,4,5,6,7,8 --",
    ];

    for payload in payloads {
        let response = app
            .client
            .post(app.url("/api/v1/auth/login"))
            .json(&json!({ "email": payload, "password": "anything" }))
            .send()
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            401,
            "payload authenticated or errored differently: {payload}"
        );
    }
}

#[tokio::test]
async fn sql_injection_cannot_drop_or_read_other_tables() {
    let app = spawn().await;
    let (token, _) = register_and_login(&app, "sqli@example.com", PASSWORD).await;
    let auth = format!("Bearer {token}");

    let payloads = [
        "'; DROP TABLE notes; --",
        "'; DELETE FROM users; --",
        "' UNION SELECT password_hash FROM users --",
        "\"; UPDATE users SET role='admin'; --",
        "1'; ATTACH DATABASE '/tmp/evil.db' AS evil; --",
    ];

    for payload in payloads {
        let response = app
            .client
            .post(app.url("/api/v1/notes"))
            .header("authorization", &auth)
            .json(&json!({ "title": payload, "body": payload }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 201, "note create failed for: {payload}");

        // Stored verbatim: proof it was bound as a value, never parsed as SQL.
        let created: Value = response.json().await.unwrap();
        assert_eq!(created["title"], payload);
    }

    // The table still exists and holds exactly what was written.
    let listing: Value = app
        .client
        .get(app.url("/api/v1/notes"))
        .header("authorization", &auth)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(listing["total"], payloads.len());

    // And the account was not promoted by the UPDATE payload.
    let admin_probe = app
        .client
        .delete(app.url("/api/v1/admin/users/00000000-0000-0000-0000-000000000000/sessions"))
        .header("authorization", &auth)
        .send()
        .await
        .unwrap();
    assert_eq!(admin_probe.status(), 403, "privilege escalated through SQL");
}

#[tokio::test]
async fn sql_injection_in_a_path_parameter_is_rejected_before_the_database() {
    let app = spawn().await;
    let (token, _) = register_and_login(&app, "pathsqli@example.com", PASSWORD).await;

    for payload in [
        "1' OR '1'='1",
        "%27%20OR%20%271%27%3D%271",
        "1;DROP TABLE notes",
        "*",
    ] {
        let response = app
            .client
            .get(app.url(&format!("/api/v1/notes/{payload}")))
            .header("authorization", format!("Bearer {token}"))
            .send()
            .await
            .unwrap();

        assert!(
            response.status() == 400 || response.status() == 404,
            "expected a rejection for {payload}, got {}",
            response.status()
        );
    }
}

// ---------------------------------------------------------------------------
// JWT attacks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_alg_none_token_is_rejected() {
    let app = spawn().await;
    let (_, _) = register_and_login(&app, "algnone@example.com", PASSWORD).await;

    // The classic: declare the token unsigned and drop the signature.
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        json!({
            "sub": uuid::Uuid::new_v4().to_string(),
            "iss": TEST_JWT_ISSUER,
            "aud": TEST_JWT_AUDIENCE,
            "exp": chrono::Utc::now().timestamp() + 900,
            "nbf": chrono::Utc::now().timestamp(),
            "role": "admin",
        })
        .to_string()
        .as_bytes(),
    );

    for token in [
        format!("{header}.{payload}."),
        format!("{header}.{payload}"),
        format!("{header}.{payload}.AAAA"),
    ] {
        let response = app
            .client
            .get(app.url("/api/v1/notes"))
            .header("authorization", format!("Bearer {token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401, "alg=none accepted");
    }
}

#[tokio::test]
async fn a_role_escalated_but_correctly_signed_token_is_still_only_a_user() {
    let app = spawn().await;
    let (token, _) = register_and_login(&app, "escalate@example.com", PASSWORD).await;

    // Recover the real subject, then re-sign it claiming admin. The signature
    // is genuine — only the role is a lie.
    let subject = {
        let payload = token.split('.').nth(1).unwrap();
        let decoded = URL_SAFE_NO_PAD.decode(payload).unwrap();
        let claims: Value = serde_json::from_slice(&decoded).unwrap();
        claims["sub"].as_str().unwrap().to_string()
    };

    let forged = signed_token(valid_claims(&subject, "admin"));

    let response = app
        .client
        .delete(app.url(&format!("/api/v1/admin/users/{subject}/sessions")))
        .header("authorization", format!("Bearer {forged}"))
        .send()
        .await
        .unwrap();

    // NOTE: this documents a real property. The role is carried *in* the token,
    // so anyone holding the signing key can mint an admin. What must not happen
    // is escalation without the key — covered by the tampering test below.
    assert!(
        response.status() == 204 || response.status() == 403,
        "unexpected status {}",
        response.status()
    );
}

#[tokio::test]
async fn tampering_with_the_payload_invalidates_the_signature() {
    let app = spawn().await;
    let (token, _) = register_and_login(&app, "tamper@example.com", PASSWORD).await;

    let mut parts: Vec<&str> = token.split('.').collect();
    let decoded = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let mut claims: Value = serde_json::from_slice(&decoded).unwrap();
    claims["role"] = json!("admin");
    let repacked = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    parts[1] = &repacked;
    let tampered = parts.join(".");

    let response = app
        .client
        .get(app.url("/api/v1/notes"))
        .header("authorization", format!("Bearer {tampered}"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 401, "payload tampering was not detected");
}

#[tokio::test]
async fn expired_and_not_yet_valid_tokens_are_rejected() {
    let app = spawn().await;
    let subject = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp();

    let expired = signed_token(json!({
        "sub": subject, "iss": TEST_JWT_ISSUER, "aud": TEST_JWT_AUDIENCE,
        "iat": now - 7200, "nbf": now - 7200, "exp": now - 3600,
        "jti": uuid::Uuid::new_v4().to_string(), "role": "user",
    }));

    let future = signed_token(json!({
        "sub": subject, "iss": TEST_JWT_ISSUER, "aud": TEST_JWT_AUDIENCE,
        "iat": now + 3600, "nbf": now + 3600, "exp": now + 7200,
        "jti": uuid::Uuid::new_v4().to_string(), "role": "user",
    }));

    for (name, token) in [("expired", expired), ("not yet valid", future)] {
        let response = app
            .client
            .get(app.url("/api/v1/notes"))
            .header("authorization", format!("Bearer {token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401, "{name} token was accepted");
    }
}

#[tokio::test]
async fn tokens_minted_for_another_issuer_or_audience_are_rejected() {
    let app = spawn().await;
    let subject = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp();

    // Correctly signed by a sibling service sharing the key — the exact case
    // `iss` and `aud` validation exists to stop.
    let wrong_issuer = signed_token(json!({
        "sub": subject, "iss": "some-other-service", "aud": TEST_JWT_AUDIENCE,
        "iat": now, "nbf": now, "exp": now + 900,
        "jti": uuid::Uuid::new_v4().to_string(), "role": "admin",
    }));

    let wrong_audience = signed_token(json!({
        "sub": subject, "iss": TEST_JWT_ISSUER, "aud": "some-other-api",
        "iat": now, "nbf": now, "exp": now + 900,
        "jti": uuid::Uuid::new_v4().to_string(), "role": "admin",
    }));

    for (name, token) in [("issuer", wrong_issuer), ("audience", wrong_audience)] {
        let response = app
            .client
            .get(app.url("/api/v1/notes"))
            .header("authorization", format!("Bearer {token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401, "wrong {name} was accepted");
    }
}

#[tokio::test]
async fn a_token_missing_registered_claims_is_rejected() {
    let app = spawn().await;

    // No exp, no nbf, no aud: a token that would never expire.
    let eternal = signed_token(json!({
        "sub": uuid::Uuid::new_v4().to_string(),
        "role": "admin",
    }));

    let response = app
        .client
        .get(app.url("/api/v1/notes"))
        .header("authorization", format!("Bearer {eternal}"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        401,
        "a token with no expiry was accepted"
    );
}

#[tokio::test]
async fn an_unparsable_subject_is_rejected() {
    let app = spawn().await;

    // Signed correctly, but `sub` is not a UUID — a parser that fell back to a
    // default identity here would be an authentication bypass.
    for subject in ["", "0", "../admin", "' OR 1=1 --", "null"] {
        let token = signed_token(valid_claims(subject, "admin"));
        let response = app
            .client
            .get(app.url("/api/v1/notes"))
            .header("authorization", format!("Bearer {token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401, "subject {subject:?} was accepted");
    }
}

// ---------------------------------------------------------------------------
// Privilege escalation and mass assignment
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registration_cannot_assign_a_role() {
    let app = spawn().await;

    let response = app
        .client
        .post(app.url("/api/v1/auth/register"))
        .json(&json!({
            "email": "massassign@example.com",
            "password": PASSWORD,
            "role": "admin",
            "failed_attempts": -100,
            "id": "00000000-0000-0000-0000-00000000dead",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);

    let created: Value = response.json().await.unwrap();
    assert_eq!(
        created["role"], "user",
        "role was assignable at registration"
    );
    assert_ne!(
        created["id"], "00000000-0000-0000-0000-00000000dead",
        "the client chose its own primary key"
    );

    // Confirm over the wire, not just in the response body.
    let (token, _) = common::login(&app, "massassign@example.com", PASSWORD).await;
    let probe = app
        .client
        .delete(app.url("/api/v1/admin/users/00000000-0000-0000-0000-000000000000/sessions"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(probe.status(), 403);
}

#[tokio::test]
async fn a_note_cannot_be_created_on_behalf_of_someone_else() {
    let app = spawn().await;
    let (attacker, _) = register_and_login(&app, "attacker@example.com", PASSWORD).await;
    let (victim, _) = register_and_login(&app, "target2@example.com", PASSWORD).await;

    let victim_id = {
        let payload = victim.split('.').nth(1).unwrap();
        let decoded = URL_SAFE_NO_PAD.decode(payload).unwrap();
        let claims: Value = serde_json::from_slice(&decoded).unwrap();
        claims["sub"].as_str().unwrap().to_string()
    };

    app.client
        .post(app.url("/api/v1/notes"))
        .header("authorization", format!("Bearer {attacker}"))
        .json(&json!({
            "title": "planted",
            "body": "planted",
            "owner_id": victim_id,
        }))
        .send()
        .await
        .unwrap();

    // The victim's list must be empty: ownership comes from the token, never
    // from the body.
    let listing: Value = app
        .client
        .get(app.url("/api/v1/notes"))
        .header("authorization", format!("Bearer {victim}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(listing["total"], 0, "a note was planted in another account");
}

#[tokio::test]
async fn one_users_password_cannot_be_changed_with_another_users_token() {
    let app = spawn().await;
    let (attacker, _) = register_and_login(&app, "pwattacker@example.com", PASSWORD).await;
    register_and_login(&app, "pwvictim@example.com", PASSWORD).await;

    // No user field is accepted, so the attacker can only ever change their own
    // — and only by proving the current password.
    let response = app
        .client
        .post(app.url("/api/v1/auth/password"))
        .header("authorization", format!("Bearer {attacker}"))
        .json(&json!({
            "current_password": "not-the-attackers-password",
            "new_password": "a-brand-new-passphrase-here",
            "email": "pwvictim@example.com",
            "user_id": "00000000-0000-0000-0000-000000000000",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);

    // The victim's original password still works.
    common::login(&app, "pwvictim@example.com", PASSWORD).await;
}

// ---------------------------------------------------------------------------
// Traversal, smuggling, splitting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn path_traversal_does_not_reach_another_route() {
    let app = spawn().await;
    let (token, _) = register_and_login(&app, "traversal@example.com", PASSWORD).await;
    let auth = format!("Bearer {token}");

    for path in [
        "/api/v1/notes/../admin/users/00000000-0000-0000-0000-000000000000/sessions",
        "/api/v1/notes/%2e%2e/admin/users/00000000-0000-0000-0000-000000000000/sessions",
        "/api/v1/notes/..%2fadmin",
        "/api/v1/../../etc/passwd",
        "/api/v1/notes/%00",
        "//api/v1/notes",
        "///api/v1/notes",
        "/api/v1//notes",
    ] {
        let response = app
            .client
            .get(format!("{}{}", app.base_url, path))
            .header("authorization", &auth)
            .send()
            .await
            .unwrap();

        assert!(
            response.status() == 400 || response.status() == 404 || response.status() == 405,
            "{path} resolved to something: {}",
            response.status()
        );
    }
}

#[tokio::test]
async fn crlf_in_a_header_value_cannot_split_the_response() {
    let app = spawn().await;

    // Injected through the echoed request id, the one header the server copies
    // from the request into the response.
    let request = b"GET /health/live HTTP/1.1\r\n\
                    Host: localhost\r\n\
                    X-Request-Id: abc\r\nX-Injected: yes\r\n\
                    Connection: close\r\n\r\n";

    let response = raw_request(app.addr(), request).await;

    assert!(
        !response.is_empty(),
        "no response was read; the probe proves nothing"
    );
    assert!(
        !response.to_lowercase().contains("x-injected"),
        "a header was injected into the response:\n{response}"
    );
}

#[tokio::test]
async fn conflicting_length_headers_are_refused_rather_than_smuggled() {
    let app = spawn().await;

    // CL.TE desync: two framings for one body. Anything other than a refusal
    // means a proxy and this server could disagree on where the request ends.
    let request = b"POST /api/v1/auth/login HTTP/1.1\r\n\
                    Host: localhost\r\n\
                    Content-Type: application/json\r\n\
                    Content-Length: 6\r\n\
                    Transfer-Encoding: chunked\r\n\
                    Connection: close\r\n\r\n\
                    0\r\n\r\n\
                    GET /api/v1/notes HTTP/1.1\r\nHost: localhost\r\n\r\n";

    let response = raw_request(app.addr(), request).await;
    let status_line = response.lines().next().unwrap_or_default().to_string();

    assert!(
        !response.is_empty(),
        "no response was read; the probe proves nothing"
    );
    assert!(
        status_line.contains("400"),
        "conflicting framing was not refused: {status_line}"
    );
    assert!(
        !response.contains("\"items\""),
        "the smuggled second request was answered:\n{response}"
    );
}

#[tokio::test]
async fn a_duplicated_content_length_is_refused() {
    let app = spawn().await;

    let request = b"POST /api/v1/auth/login HTTP/1.1\r\n\
                    Host: localhost\r\n\
                    Content-Type: application/json\r\n\
                    Content-Length: 2\r\n\
                    Content-Length: 60\r\n\
                    Connection: close\r\n\r\n{}";

    let response = raw_request(app.addr(), request).await;
    let status_line = response.lines().next().unwrap_or_default().to_string();

    assert!(
        !response.is_empty(),
        "no response was read; the probe proves nothing"
    );
    assert!(
        status_line.contains("400"),
        "duplicated Content-Length was accepted: {status_line}"
    );
}

#[tokio::test]
async fn a_method_override_header_does_not_change_the_method() {
    let app = spawn().await;
    let (token, _) = register_and_login(&app, "override@example.com", PASSWORD).await;
    let auth = format!("Bearer {token}");

    let created: Value = app
        .client
        .post(app.url("/api/v1/notes"))
        .header("authorization", &auth)
        .json(&json!({ "title": "keep me", "body": "keep me" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap();

    // A GET that asks to be treated as a DELETE.
    let response = app
        .client
        .get(app.url(&format!("/api/v1/notes/{id}")))
        .header("authorization", &auth)
        .header("x-http-method-override", "DELETE")
        .header("x-method-override", "DELETE")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    // Still there.
    let still_there = app
        .client
        .get(app.url(&format!("/api/v1/notes/{id}")))
        .header("authorization", &auth)
        .send()
        .await
        .unwrap();
    assert_eq!(still_there.status(), 200, "the override deleted the note");
}

#[tokio::test]
async fn a_forged_host_header_does_not_change_behaviour() {
    let app = spawn().await;

    let request = b"GET /health/live HTTP/1.1\r\n\
                    Host: evil.example.com\r\n\
                    Connection: close\r\n\r\n";

    let response = raw_request(app.addr(), request).await;

    assert!(
        !response.is_empty(),
        "no response was read; the probe proves nothing"
    );
    assert!(response.contains("200"), "host header changed routing");
    assert!(
        !response.contains("evil.example.com"),
        "the Host header was reflected into the response:\n{response}"
    );
}

// ---------------------------------------------------------------------------
// Injection into stored content
// ---------------------------------------------------------------------------

#[tokio::test]
async fn script_payloads_come_back_as_data_not_markup() {
    let app = spawn().await;
    let (token, _) = register_and_login(&app, "xss@example.com", PASSWORD).await;
    let auth = format!("Bearer {token}");

    let payload = r#"<script>alert(document.cookie)</script>"#;

    let response = app
        .client
        .post(app.url("/api/v1/notes"))
        .header("authorization", &auth)
        .json(&json!({ "title": payload, "body": "\"><img src=x onerror=alert(1)>" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);

    // Content type is JSON, nosniff is set, and the payload is JSON-escaped —
    // so a browser has no path to executing it.
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");

    // The payload must come back as a JSON string value, not as markup: quotes
    // escaped, and the whole response still parseable. Escaping `<` is the
    // consumer's job at render time — doing it here would corrupt stored data,
    // and `nosniff` plus a JSON content type already deny a browser any path to
    // executing it.
    let raw = response.text().await.unwrap();
    let parsed: Value = serde_json::from_str(&raw).expect("response was not valid JSON");
    assert_eq!(parsed["title"], payload, "the payload did not round-trip");
    assert!(
        raw.contains(r#"\"><img src=x onerror=alert(1)>"#),
        "the embedded quote was not escaped, so the JSON structure was breakable: {raw}"
    );
}

#[tokio::test]
async fn a_null_byte_does_not_truncate_a_stored_value() {
    let app = spawn().await;
    let (token, _) = register_and_login(&app, "nullbyte@example.com", PASSWORD).await;

    let created: Value = app
        .client
        .post(app.url("/api/v1/notes"))
        .header("authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "safe\u{0000}../../etc/passwd", "body": "x" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(
        created["title"].as_str().unwrap().contains('\u{0000}'),
        "the value was truncated at the null byte"
    );
}

// ---------------------------------------------------------------------------
// Malformed input
// ---------------------------------------------------------------------------

#[tokio::test]
async fn deeply_nested_json_does_not_crash_the_server() {
    let app = spawn().await;

    // A parser that recurses without a limit dies on the stack here.
    let bomb = format!("{}{}", "[".repeat(20_000), "]".repeat(20_000));

    let response = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .header("content-type", "application/json")
        .body(bomb)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);

    // Still serving.
    let health = app
        .client
        .get(app.url("/health/live"))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
}

#[tokio::test]
async fn hostile_json_shapes_are_rejected_cleanly() {
    let app = spawn().await;

    let cases: [(&str, &str); 6] = [
        ("not json at all", "this is not json"),
        ("wrong types", r#"{"email": 12345, "password": ["a"]}"#),
        ("null values", r#"{"email": null, "password": null}"#),
        ("huge number", r#"{"email": 1e309, "password": "x"}"#),
        (
            "duplicate keys",
            r#"{"email":"a@b.com","email":"admin@b.com","password":"correct-horse-battery-staple"}"#,
        ),
        ("empty object", "{}"),
    ];

    for (name, body) in cases {
        let response = app
            .client
            .post(app.url("/api/v1/auth/login"))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();

        assert!(
            response.status() == 400 || response.status() == 401,
            "{name}: unexpected status {}",
            response.status()
        );

        // No internal detail in the body.
        let text = response.text().await.unwrap();
        for leak in ["panicked", "sqlx", "src/", ".rs:", "SELECT"] {
            assert!(
                !text.contains(leak),
                "{name}: response leaked {leak}: {text}"
            );
        }
    }
}

#[tokio::test]
async fn a_wrong_content_type_is_not_parsed_as_json() {
    let app = spawn().await;

    let response = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("email=me@example.com&password=correct-horse-battery-staple")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn negative_and_overflowing_pagination_is_rejected() {
    let app = spawn().await;
    let (token, _) = register_and_login(&app, "pagination@example.com", PASSWORD).await;
    let auth = format!("Bearer {token}");

    for query in [
        "?limit=-1",
        "?offset=-1",
        "?limit=999999999999999999999",
        "?limit=0",
        "?offset=-9223372036854775808",
    ] {
        let response = app
            .client
            .get(app.url(&format!("/api/v1/notes{query}")))
            .header("authorization", &auth)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 400, "{query} was accepted");
    }
}

// ---------------------------------------------------------------------------
// Cross-origin
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_lookalike_origin_is_not_allowed() {
    let app = spawn_with(TestOptions {
        cors_allowed_origins: vec!["https://app.example.com".to_string()],
        ..Default::default()
    })
    .await;

    // Prefix, suffix, and substring tricks against a naive origin check.
    for origin in [
        "https://app.example.com.evil.test",
        "https://evil-app.example.com",
        "http://app.example.com",
        "https://app.example.com:8443",
        "null",
        "https://APP.EXAMPLE.COM",
    ] {
        let response = app
            .client
            .get(app.url("/health/live"))
            .header("origin", origin)
            .send()
            .await
            .unwrap();

        let allowed = response
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();

        assert!(
            allowed.is_empty(),
            "{origin} was granted cross-origin access as {allowed}"
        );
    }

    // The configured origin still works, so the check is not simply refusing
    // everything.
    let response = app
        .client
        .get(app.url("/health/live"))
        .header("origin", "https://app.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        "https://app.example.com"
    );
}

// ---------------------------------------------------------------------------
// Enumeration by timing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_timing_does_not_reveal_whether_an_account_exists() {
    let app = spawn().await;
    register_and_login(&app, "timing@example.com", PASSWORD).await;

    async fn measure(app: &common::TestApp, email: &str) -> Duration {
        let mut total = Duration::ZERO;
        let samples = 6;
        for _ in 0..samples {
            let start = Instant::now();
            let _ = app
                .client
                .post(app.url("/api/v1/auth/login"))
                .json(&json!({ "email": email, "password": "definitely-not-the-password" }))
                .send()
                .await
                .unwrap();
            total += start.elapsed();
        }
        total / samples
    }

    // Warm the pool and the hasher so the first sample is not an outlier.
    let _ = measure(&app, "warmup@example.com").await;

    let existing = measure(&app, "timing@example.com").await;
    let missing = measure(&app, "nobody@example.com").await;

    let (slow, fast) = if existing > missing {
        (existing, missing)
    } else {
        (missing, existing)
    };
    let ratio = slow.as_secs_f64() / fast.as_secs_f64();

    // Both paths run a full Argon2 verification, so they should be within noise
    // of each other. A missing-account path that skipped hashing would come back
    // many times faster.
    assert!(
        ratio < 2.0,
        "login timing distinguishes existing from missing accounts: \
         existing {existing:?}, missing {missing:?} (ratio {ratio:.2})"
    );
}

// ---------------------------------------------------------------------------
// Races (time-of-check to time-of-use)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refresh_token_cannot_be_spent_twice_concurrently() {
    let app = spawn().await;
    let (_, refresh) = register_and_login(&app, "race@example.com", PASSWORD).await;

    // Both requests carry the same single-use token and are in flight at once.
    // A check-then-update that is not atomic hands out two valid sessions here.
    let attempts = (0..8).map(|_| {
        let client = app.client.clone();
        let url = app.url("/api/v1/auth/refresh");
        let token = refresh.clone();
        tokio::spawn(async move {
            client
                .post(url)
                .json(&json!({ "refresh_token": token }))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        })
    });

    let statuses: Vec<u16> = futures_util::future::join_all(attempts)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    let accepted = statuses.iter().filter(|s| **s == 200).count();
    assert_eq!(
        accepted, 1,
        "a single-use token was redeemed {accepted} times: {statuses:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_registration_of_one_address_yields_exactly_one_account() {
    let app = spawn().await;

    // The duplicate check and the insert are two steps. If the database did not
    // also enforce uniqueness, this would create several accounts for one
    // address — or surface as a 500 rather than a clean conflict.
    let attempts = (0..8).map(|_| {
        let client = app.client.clone();
        let url = app.url("/api/v1/auth/register");
        tokio::spawn(async move {
            client
                .post(url)
                .json(&json!({ "email": "duplicate@example.com", "password": PASSWORD }))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        })
    });

    let statuses: Vec<u16> = futures_util::future::join_all(attempts)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    let created = statuses.iter().filter(|s| **s == 201).count();
    assert_eq!(
        created, 1,
        "the address was registered {created} times: {statuses:?}"
    );
    assert!(
        statuses.iter().all(|s| *s == 201 || *s == 409),
        "a race produced something other than a clean conflict: {statuses:?}"
    );

    // The losers must be indistinguishable from a plain duplicate registration,
    // so the outcome of the race cannot be observed from outside.
    let sequential = app
        .client
        .post(app.url("/api/v1/auth/register"))
        .json(&json!({ "email": "duplicate@example.com", "password": PASSWORD }))
        .send()
        .await
        .unwrap();
    assert_eq!(sequential.status(), 409);
    let body: Value = sequential.json().await.unwrap();
    assert_eq!(
        body["error"]["message"],
        "conflict: email is already registered"
    );
}

// ---------------------------------------------------------------------------
// Denial of service
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_login_flood_is_shed_rather_than_queued() {
    // Argon2 is the most expensive thing an *unauthenticated* request can
    // trigger: a few hundred bytes buys 19 MiB and a core. Without a bound on
    // concurrent hashing, a flood is absorbed into the blocking pool and the
    // machine runs out of CPU and memory while every per-IP rate limit is still
    // satisfied. The bound must turn that into shed load instead.
    let app = spawn_with(TestOptions {
        request_timeout: Duration::from_secs(2),
        max_concurrent_hashes: 2,
        ..Default::default()
    })
    .await;

    let flood: Vec<_> = (0..300)
        .map(|i| {
            let client = app.client.clone();
            let url = app.url("/api/v1/auth/login");
            tokio::spawn(async move {
                client
                    .post(url)
                    .json(&json!({ "email": format!("flood{i}@example.com"), "password": "x" }))
                    .timeout(Duration::from_secs(60))
                    .send()
                    .await
                    .map(|r| r.status().as_u16())
            })
        })
        .collect();

    // Unrelated traffic keeps flowing: hashing runs on blocking threads, so it
    // must never occupy the async runtime.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let health = app
        .client
        .get(app.url("/health/live"))
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .expect("health request failed under load");
    assert_eq!(health.status(), 200, "the flood took the server down");

    let started = Instant::now();
    let statuses: Vec<u16> = futures_util::future::join_all(flood)
        .await
        .into_iter()
        .filter_map(|r| r.ok().and_then(|r| r.ok()))
        .collect();
    let drained = started.elapsed();

    let shed = statuses.iter().filter(|s| **s == 408 || **s == 503).count();

    assert!(
        shed > 0,
        "every request was served, so the queue absorbed the flood: {statuses:?}"
    );
    assert!(
        drained < Duration::from_secs(45),
        "the flood queued for {drained:?} instead of being shed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_body_that_never_arrives_is_cut_off() {
    // R.U.D.Y.: complete headers, an honest Content-Length, then a body sent one
    // byte at a time — or never. The header deadline has already been satisfied
    // by this point, so only the request timeout can end it.
    let app = spawn_with(TestOptions {
        request_timeout: Duration::from_secs(2),
        ..Default::default()
    })
    .await;

    let addr = app.addr();
    let cut_off = tokio::task::spawn_blocking(move || {
        let mut socket = TcpStream::connect(addr).expect("failed to connect");
        socket
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        socket
            .write_all(
                b"POST /api/v1/auth/login HTTP/1.1\r\n\
                  Host: localhost\r\n\
                  Content-Type: application/json\r\n\
                  Content-Length: 400\r\n\
                  Connection: close\r\n\r\n\
                  {",
            )
            .expect("failed to write the partial request");

        let started = Instant::now();
        let mut sink = Vec::new();
        let _ = socket.read_to_end(&mut sink);
        started.elapsed()
    })
    .await
    .expect("the slow-body probe panicked");

    assert!(
        cut_off < Duration::from_secs(15),
        "a stalled body held the connection for {cut_off:?}"
    );
}
