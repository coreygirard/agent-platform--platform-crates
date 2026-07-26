//! Social-Graph **graph-access** client, shared by third-party apps.
//!
//! An app authenticates a user by their opaque **graph-access token** (minted in
//! the browser via SG's graph-OAuth consent flow). This client resolves that
//! token against SG's three graph-access endpoints — the protocol both gotta and
//! porch had copy-pasted (and let drift) into their own `clients/social_graph.rs`:
//!
//! - [`SocialGraphClient::resolve_me`] — `GET /api/graph-access/me` → the caller's
//!   per-app pseudonym ([`AppUserView`]); `None` on 401 (token rejected).
//! - [`SocialGraphClient::register_membership`] — `POST /api/graph-access/membership`
//!   → upsert the caller's graph-app membership (idempotent) so connections can
//!   discover them.
//! - [`SocialGraphClient::connections_members`] — `GET
//!   /api/graph-access/connections/members` → the caller's connections who have
//!   joined this app, as pseudonyms.
//!
//! The client returns the RAW resolved data; each app keeps its own return
//! shaping (a plain pseudonym, or an environment-scoped identity built from
//! [`AppUserView::environment`]) and error mapping. No global `users.id` is ever
//! seen — SG mints a per-(app, user) pseudonym bound to the token server-side.

use serde::Deserialize;

/// SG's `AppUserView` (camelCase wire shape). `id` is the caller's per-app
/// pseudonym. `environment` is the plane SG resolved the identity in (prod vs a
/// `/test/{tenant}` login) — ABSENT today (SG is not yet env-partitioned), which
/// an env-aware app reads as Production. Fields are public so apps shape their own
/// return (pseudonym-only, or an env-scoped identity).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppUserView {
    pub id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
}

#[derive(Deserialize)]
struct Member {
    #[serde(rename = "appUserId")]
    app_user_id: String,
}

/// A graph-access call failed. Its own error type so any consumer maps it (an
/// anyhow app via `?`, an app with its own `ApiError` via `.map_err`).
#[derive(Debug)]
pub enum SgError {
    /// The HTTP request failed to send, or a body failed to decode.
    Transport(reqwest::Error),
    /// SG returned an unexpected status (not 200, and not the 401 that
    /// `resolve_me` maps to `Ok(None)`).
    Status(u16),
}

impl std::fmt::Display for SgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SgError::Transport(e) => write!(f, "social-graph transport: {e}"),
            SgError::Status(code) => write!(f, "social-graph -> {code}"),
        }
    }
}

impl std::error::Error for SgError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SgError::Transport(e) => Some(e),
            SgError::Status(_) => None,
        }
    }
}

/// A graph-access client bound to a Social-Graph base URL.
pub struct SocialGraphClient {
    http: reqwest::Client,
    base_url: String,
}

impl SocialGraphClient {
    pub fn new(http: reqwest::Client, base_url: impl Into<String>) -> Self {
        Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_string(),
        }
    }

    /// Resolve the graph-access token to the caller's [`AppUserView`]. `Ok(None)`
    /// when SG rejects the token (401 → the caller maps to Unauthorized); any
    /// other non-200 is an [`SgError::Status`].
    pub async fn resolve_me(&self, token: &str) -> Result<Option<AppUserView>, SgError> {
        let resp = self
            .http
            .get(format!("{}/api/graph-access/me", self.base_url))
            .bearer_auth(token)
            .send()
            .await
            .map_err(SgError::Transport)?;
        match resp.status().as_u16() {
            200 => Ok(Some(resp.json().await.map_err(SgError::Transport)?)),
            401 => Ok(None),
            other => Err(SgError::Status(other)),
        }
    }

    /// Upsert the caller's graph-app membership (idempotent) so their connections
    /// can discover them. Without it a joined user is invisible in every
    /// connection's audience.
    pub async fn register_membership(
        &self,
        token: &str,
        app_user_id: &str,
        app_display_name: Option<&str>,
    ) -> Result<(), SgError> {
        self.http
            .post(format!("{}/api/graph-access/membership", self.base_url))
            .bearer_auth(token)
            .json(&serde_json::json!({
                "appUserId": app_user_id,
                "appDisplayName": app_display_name,
            }))
            .send()
            .await
            .map_err(SgError::Transport)?
            .error_for_status()
            .map_err(SgError::Transport)?;
        Ok(())
    }

    /// The caller's connections who have JOINED this app, as per-app pseudonyms —
    /// the valid audience / fan-out targets.
    pub async fn connections_members(&self, token: &str) -> Result<Vec<String>, SgError> {
        let members: Vec<Member> = self
            .http
            .get(format!("{}/api/graph-access/connections/members", self.base_url))
            .bearer_auth(token)
            .send()
            .await
            .map_err(SgError::Transport)?
            .error_for_status()
            .map_err(SgError::Transport)?
            .json()
            .await
            .map_err(SgError::Transport)?;
        Ok(members.into_iter().map(|m| m.app_user_id).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn resolve_me_returns_view_on_200_and_none_on_401() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/graph-access/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "psd_alice",
                "displayName": "Alice",
            })))
            .mount(&server)
            .await;
        let c = SocialGraphClient::new(reqwest::Client::new(), server.uri());
        let v = c.resolve_me("tok").await.unwrap().unwrap();
        assert_eq!(v.id, "psd_alice");
        assert_eq!(v.display_name.as_deref(), Some("Alice"));
        assert!(v.environment.is_none());

        let server401 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/graph-access/me"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server401)
            .await;
        let c401 = SocialGraphClient::new(reqwest::Client::new(), server401.uri());
        assert!(c401.resolve_me("bad").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn connections_members_maps_app_user_ids() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/graph-access/connections/members"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                { "appUserId": "psd_bob", "displayName": "B" },
                { "appUserId": "psd_carol", "displayName": "C" },
            ])))
            .mount(&server)
            .await;
        let c = SocialGraphClient::new(reqwest::Client::new(), server.uri());
        assert_eq!(
            c.connections_members("tok").await.unwrap(),
            vec!["psd_bob".to_string(), "psd_carol".to_string()]
        );
    }

    #[tokio::test]
    async fn register_membership_posts_the_pseudonym_and_name() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/graph-access/membership"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let c = SocialGraphClient::new(reqwest::Client::new(), server.uri());
        c.register_membership("tok", "psd_bob", Some("Bob")).await.unwrap();
    }
}
