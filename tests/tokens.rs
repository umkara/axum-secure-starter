//! Access token formats, over HTTP.
//!
//! `APP_TOKEN_FORMAT` picks how access tokens are written. The unit tests in
//! `src/security` cover each codec on its own; these boot the real server once
//! per format and run the same session through it, because the thing worth
//! proving is that the choice is invisible above the trait — the same login,
//! the same bearer header, the same refresh, whatever the string on the wire
//! turns out to be.

mod common;

use bastion::config::TokenFormat;
use common::{TestOptions, register_and_login, spawn_with};
use serde_json::Value;

const PASSWORD: &str = "correct horse battery staple";

/// Every format the server can be configured with. A format added to
/// `TokenFormat` without an entry here is a format nothing exercises end to
/// end.
const FORMATS: [TokenFormat; 2] = [TokenFormat::Jwt, TokenFormat::PasetoLocal];

async fn spawn_with_format(format: TokenFormat) -> common::TestApp {
    spawn_with(TestOptions {
        token_format: format,
        ..Default::default()
    })
    .await
}

#[tokio::test]
async fn every_format_carries_a_whole_session() {
    for format in FORMATS {
        let app = spawn_with_format(format).await;
        let email = format!("{format}@example.com");

        let (access, refresh) = register_and_login(&app, &email, PASSWORD).await;

        // The token authenticates a write...
        let created = app
            .client
            .post(app.url("/api/v1/notes"))
            .bearer_auth(&access)
            .json(&serde_json::json!({ "title": "first", "body": "hello" }))
            .send()
            .await
            .unwrap();
        assert_eq!(created.status(), 201, "{format}: creating a note");

        // ...and a read of what it wrote.
        let listed = app
            .client
            .get(app.url("/api/v1/notes"))
            .bearer_auth(&access)
            .send()
            .await
            .unwrap();
        assert_eq!(listed.status(), 200, "{format}: listing notes");
        let body: Value = listed.json().await.unwrap();
        assert_eq!(body["items"][0]["title"], "first", "{format}");

        // Rotation is unchanged: refresh tokens are opaque whatever the access
        // token format is.
        let rotated = app
            .client
            .post(app.url("/api/v1/auth/refresh"))
            .json(&serde_json::json!({ "refresh_token": refresh }))
            .send()
            .await
            .unwrap();
        assert_eq!(rotated.status(), 200, "{format}: refreshing");
        let pair: Value = rotated.json().await.unwrap();
        let refreshed_access = pair["access_token"].as_str().unwrap();

        let after_refresh = app
            .client
            .get(app.url("/api/v1/notes"))
            .bearer_auth(refreshed_access)
            .send()
            .await
            .unwrap();
        assert_eq!(
            after_refresh.status(),
            200,
            "{format}: the refreshed token works"
        );
    }
}

#[tokio::test]
async fn a_missing_or_malformed_token_is_refused_the_same_way_by_every_format() {
    for format in FORMATS {
        let app = spawn_with_format(format).await;

        for token in ["", "not-a-token", "v4.local.nonsense", "a.b.c"] {
            let response = app
                .client
                .get(app.url("/api/v1/notes"))
                .bearer_auth(token)
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                401,
                "{format}: `{token}` must not authenticate"
            );

            // The rejection says nothing about *why*, which is what keeps it
            // from being an oracle.
            let body: Value = response.json().await.unwrap();
            assert_eq!(body["error"]["code"], "unauthorized", "{format}");
        }
    }
}

#[tokio::test]
async fn a_token_written_in_another_format_does_not_authenticate() {
    // Both servers share the harness's key, issuer and audience, so the format
    // is the only difference between them. Switching APP_TOKEN_FORMAT has to
    // invalidate the tokens already in circulation rather than half-accept
    // them.
    let jwt = spawn_with_format(TokenFormat::Jwt).await;
    let paseto = spawn_with_format(TokenFormat::PasetoLocal).await;

    let (jwt_token, _) = register_and_login(&jwt, "crossover@example.com", PASSWORD).await;
    let (paseto_token, _) = register_and_login(&paseto, "crossover@example.com", PASSWORD).await;

    let refused = paseto
        .client
        .get(paseto.url("/api/v1/notes"))
        .bearer_auth(&jwt_token)
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 401, "a JWT must not open a PASETO server");

    let refused = jwt
        .client
        .get(jwt.url("/api/v1/notes"))
        .bearer_auth(&paseto_token)
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 401, "nor the other way round");
}

#[tokio::test]
async fn the_paseto_token_names_its_version_and_hides_its_claims() {
    let app = spawn_with_format(TokenFormat::PasetoLocal).await;
    let (access, refresh) = register_and_login(&app, "opaque@example.com", PASSWORD).await;

    assert!(
        access.starts_with("v4.local."),
        "the version and purpose are part of the token, not a header: {access}"
    );

    // A JWT would carry these in readable base64. This one is encrypted, so a
    // client — or anything that logs a header — learns nothing from holding it.
    assert!(
        !access.contains("\"sub\"") && !access.to_lowercase().contains("user"),
        "the claims must not be legible: {access}"
    );

    // The refresh token is unaffected by the access token format: still 32
    // bytes of CSPRNG output, still stored only as a digest.
    assert!(
        !refresh.starts_with("v4.") && !refresh.contains('.'),
        "a refresh token is opaque, not a token format: {refresh}"
    );
}
