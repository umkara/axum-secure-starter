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
const FORMATS: [TokenFormat; 4] = [
    TokenFormat::Jwt,
    TokenFormat::PasetoLocal,
    TokenFormat::PasetoPublic,
    TokenFormat::Opaque,
];

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
async fn a_signed_token_is_accepted_by_the_server_that_minted_it_and_no_other() {
    // Each spawned server generates its own key pair, so these two share an
    // issuer and audience and differ only in key material — the situation a
    // second deployment of the same service is in.
    let ours = spawn_with_format(TokenFormat::PasetoPublic).await;
    let theirs = spawn_with_format(TokenFormat::PasetoPublic).await;

    let (access, _) = register_and_login(&ours, "signed@example.com", PASSWORD).await;
    assert!(access.starts_with("v4.public."), "{access}");

    let accepted = ours
        .client
        .get(ours.url("/api/v1/notes"))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap();
    assert_eq!(accepted.status(), 200);

    let refused = theirs
        .client
        .get(theirs.url("/api/v1/notes"))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap();
    assert_eq!(
        refused.status(),
        401,
        "another key pair must not accept this signature"
    );
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

/// Whether `token` still opens the API.
async fn still_works(app: &common::TestApp, token: &str) -> bool {
    app.client
        .get(app.url("/api/v1/notes"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .status()
        == 200
}

#[tokio::test]
async fn changing_a_password_ends_a_stored_access_token_at_once_and_a_stateless_one_at_expiry() {
    for format in FORMATS {
        let app = spawn_with_format(format).await;
        let email = format!("revoke-{format}@example.com");
        let (access, _) = register_and_login(&app, &email, PASSWORD).await;

        let changed = app
            .client
            .post(app.url("/api/v1/auth/password"))
            .bearer_auth(&access)
            .json(&serde_json::json!({
                "current_password": PASSWORD,
                "new_password": "a-different-long-passphrase",
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(changed.status(), 204, "{format}: changing the password");

        // The difference the format makes, stated as an assertion rather than
        // as documentation: a stored token is gone on the next request, a
        // stateless one keeps working until it expires. Both are defensible;
        // only one of them is what most people assume is happening.
        let survived = still_works(&app, &access).await;
        match format {
            TokenFormat::Opaque => assert!(
                !survived,
                "a stored access token must not survive a password change"
            ),
            _ => assert!(
                survived,
                "{format} is stateless: nothing can withdraw a live token"
            ),
        }
    }
}

#[tokio::test]
async fn logging_out_ends_a_stored_access_token_for_that_session_only() {
    let app = spawn_with_format(TokenFormat::Opaque).await;

    // Two logins for one account: two sessions, as two devices would be.
    let (phone, phone_refresh) = register_and_login(&app, "devices@example.com", PASSWORD).await;
    let (laptop, _) = common::login(&app, "devices@example.com", PASSWORD).await;

    let logged_out = app
        .client
        .post(app.url("/api/v1/auth/logout"))
        .json(&serde_json::json!({ "refresh_token": phone_refresh }))
        .send()
        .await
        .unwrap();
    assert_eq!(logged_out.status(), 204);

    assert!(
        !still_works(&app, &phone).await,
        "logging out must end that device's access token immediately"
    );
    assert!(
        still_works(&app, &laptop).await,
        "and must not touch the user's other sessions"
    );
}

#[tokio::test]
async fn an_administrator_can_end_every_session_a_user_holds() {
    let app = spawn_with(TestOptions {
        token_format: TokenFormat::Opaque,
        bootstrap_admin: Some((
            "admin@example.com".into(),
            "a-long-bootstrap-password".into(),
        )),
        ..Default::default()
    })
    .await;

    let (admin, _) = common::login(&app, "admin@example.com", "a-long-bootstrap-password").await;

    // Registered by hand rather than through the helper, because the response
    // is where the user id comes from.
    let created: Value = app
        .client
        .post(app.url("/api/v1/auth/register"))
        .json(&serde_json::json!({ "email": "victim@example.com", "password": PASSWORD }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().expect("the id is in the response");

    let (victim, _) = common::login(&app, "victim@example.com", PASSWORD).await;
    assert!(
        still_works(&app, &victim).await,
        "precondition: the victim has a live session"
    );

    let revoked = app
        .client
        .delete(app.url(&format!("/api/v1/admin/users/{id}/sessions")))
        .bearer_auth(&admin)
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), 204, "the admin revocation succeeded");

    assert!(
        !still_works(&app, &victim).await,
        "an administrator ending a user's sessions must end them now"
    );
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
