//! Shared chirp-auth request-plumbing for agent-platform backends.
//!
//! Drive and Pigeon (and the others) carried near-identical auth glue:
//! - the same `Authorization: Bearer` extraction,
//! - the same trusted-header dev decoder (with the 128-char / no-control-char
//!   uid+agent validation),
//! - the same `x-user-id` / `x-agent-id` / `x-approval-grant` / `x-user-can-write`
//!   header names,
//! - the same "machine acting on behalf of a human via a grant" resolution.
//!
//! This crate is the single source of truth for that plumbing. The
//! product-specific parts (which token audiences to accept, how grants are
//! stored, the concrete `AuthenticatedUser` type) stay in each backend; this
//! crate generalizes only the parts that were genuinely duplicated.

use platform_http_error::ApiError;
use uuid::Uuid;

/// Re-export of the canonical bearer-token extractor. Both backends had a
/// hand-rolled `bearer_token`; `chirp-auth-client` already ships the RFC-7235
/// case-insensitive version, so we re-export it rather than fork it.
///
/// Returns the token with the `Bearer ` scheme stripped and trimmed, or
/// `None` when the header is absent / non-bearer / empty.
pub use chirp_auth_client::bearer_token;

// ---- Header name constants (single source of truth) --------------------

/// Trusted-header user id. Bypasses token verification — only honored when a
/// deployment explicitly opts into trusted-header auth.
pub const USER_ID_HEADER: &str = "x-user-id";
/// Software-actor (agent) id. Defaults to the user id when absent.
pub const AGENT_ID_HEADER: &str = "x-agent-id";
/// App-native approval grant id (the grant lives in the backend's own store).
pub const APPROVAL_GRANT_HEADER: &str = "x-approval-grant";
/// Granite-issued grant id; the backend consults Granite as the lifecycle
/// authority for the grant. Mutually exclusive with [`APPROVAL_GRANT_HEADER`].
pub const GRANITE_GRANT_HEADER: &str = "x-granite-grant";
/// Whether the trusted-header user may write. Truthy: `1`/`true`/`yes`.
pub const CAN_WRITE_HEADER: &str = "x-user-can-write";

/// Maximum length, in characters, of a trusted-header `uid`/`agent_id`. Caps
/// the size of an attacker-influenced identifier and rejects pathological
/// inputs before they reach the store.
///
/// Gated with the trusted-header decoder it serves, so it does not linger in a
/// normal release build.
#[cfg(any(test, feature = "dev-trusted-headers"))]
const MAX_ID_CHARS: usize = 128;

// ---- Trusted-header dev decoder ----------------------------------------

/// A request authenticated purely from trusted headers. Produced by
/// [`decode_trusted_headers`]. This is the dev/integration-test bypass path:
/// it trusts `x-user-id` et al. without verifying a token, so a backend must
/// only ever reach it when it has explicitly opted into trusted-header auth
/// (e.g. behind the `dev-trusted-headers` feature + a `*_TRUSTED_HEADER_AUTH`
/// env flag, exactly as the backends gate it today).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedHeaderUser {
    /// Human user id (`x-user-id`).
    pub uid: String,
    /// Software-actor id (`x-agent-id`); defaults to `uid` when absent.
    pub agent_id: String,
    /// Whether the caller may write (`x-user-can-write`).
    pub can_write: bool,
    /// App-native grant id (`x-approval-grant`), if present.
    pub approval_grant_id: Option<String>,
}

/// Validate a trusted-header identifier: non-empty after trim, at most
/// [`MAX_ID_CHARS`] characters, and free of control characters. Returns the
/// trimmed value, or `Unauthorized` on violation.
///
/// Gated with [`decode_trusted_headers`]: it is the only caller, and the dev
/// bypass must not exist in a normal release build.
#[cfg(any(test, feature = "dev-trusted-headers"))]
fn validated_id(raw: &str) -> Result<String, ApiError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.chars().count() > MAX_ID_CHARS
        || trimmed.chars().any(char::is_control)
    {
        return Err(ApiError::Unauthorized);
    }
    Ok(trimmed.to_owned())
}

/// Decode a [`TrustedHeaderUser`] from request headers, applying the same
/// validation drive/pigeon used: `x-user-id` is required and validated;
/// `x-agent-id` (if present) is validated and otherwise defaults to the uid;
/// `x-user-can-write` is truthy for `1`/`true`/`yes`; `x-approval-grant` is
/// trimmed and dropped if empty.
///
/// Returns `Unauthorized` when `x-user-id` is missing/empty or any provided
/// id fails validation.
///
/// # Safe by construction
///
/// This function — the dev/integration-test auth bypass — is compiled only
/// under `test` or the `dev-trusted-headers` feature. In a normal release
/// build it does not exist, so a consumer that forgets to gate its call site
/// gets a missing-symbol compile error instead of silently shipping a
/// production auth bypass.
#[cfg(any(test, feature = "dev-trusted-headers"))]
pub fn decode_trusted_headers(
    headers: &http::HeaderMap,
) -> Result<TrustedHeaderUser, ApiError> {
    let uid_raw = headers
        .get(USER_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(ApiError::Unauthorized)?;
    let uid = validated_id(uid_raw)?;

    let can_write = headers
        .get(CAN_WRITE_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .map(|value| matches!(value, "1" | "true" | "yes"))
        .unwrap_or(false);

    let agent_id = match headers.get(AGENT_ID_HEADER).and_then(|v| v.to_str().ok()) {
        Some(raw) => validated_id(raw)?,
        None => uid.clone(),
    };

    let approval_grant_id = headers
        .get(APPROVAL_GRANT_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());

    Ok(TrustedHeaderUser {
        uid,
        agent_id,
        can_write,
        approval_grant_id,
    })
}

// ---- Generic on-behalf-of grant resolution -----------------------------

/// A grant looked up from a backend's own store. The only field the shared
/// resolution logic needs is the owner the grant authorizes acting as.
pub trait Grant {
    /// The uid the grant authorizes the requester to act on behalf of.
    fn owner_uid(&self) -> &str;
}

/// Per-app grant lookup. Each backend implements this over its own store;
/// [`apply_on_behalf_of_grant`] is parameterized over it so the
/// machine-acting-on-behalf-of-a-human resolution lives in one place.
#[async_trait::async_trait]
pub trait GrantStore {
    /// The grant type this store yields.
    type Grant: Grant;

    /// Look up a grant by id that names `requester_chirp_sub` as its subject.
    /// Returns `Ok(None)` when no such grant exists; `Err` only on a real
    /// store failure.
    async fn lookup_grant_for_subject(
        &self,
        grant_id: Uuid,
        requester_chirp_sub: &str,
    ) -> Result<Option<Self::Grant>, ApiError>;
}

/// The identity inputs to [`apply_on_behalf_of_grant`], and the place it
/// writes its result. `uid` is overwritten with the grant's owner when the
/// machine is acting on a human's behalf; `approval_grant_id` is always
/// populated from the header (the chirp-auth path leaves it unset otherwise).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnBehalfOf {
    /// Effective owner uid. Starts as the token's owner_sub (for a machine,
    /// the human who registered the client) and is overridden to the grant's
    /// `owner_uid` when a valid grant names this caller as subject.
    pub uid: String,
    /// The machine's own chirp sub. Equal to `uid` for a human identity —
    /// which is exactly how this function detects "no grant resolution
    /// needed".
    pub agent_id: String,
    /// Populated from [`APPROVAL_GRANT_HEADER`].
    pub approval_grant_id: Option<String>,
}

/// Resolve the effective owner for a machine-identity request that presents
/// an `x-approval-grant` header, using the backend's own [`GrantStore`].
///
/// This is the byte-shared core of drive's and pigeon's
/// `apply_on_behalf_of_grant` (minus drive's extra Granite-bridge branch,
/// which stays in drive because it's drive-specific):
///
/// 1. Always copy the `x-approval-grant` header into `ctx.approval_grant_id`
///    — the chirp-auth verify path leaves it `None`, and the downstream
///    per-operation grant check needs it.
/// 2. No-op for human identities (`uid == agent_id`): a human acting as
///    itself needs no grant.
/// 3. No-op for a missing or malformed (non-UUID) grant header, a
///    lookup-miss, or a store error — preserving the un-escalated identity
///    (the per-operation check downstream will refuse if escalation was
///    actually required).
/// 4. On a valid grant naming this caller as subject, override `ctx.uid` with
///    the grant's `owner_uid`.
///
/// The per-operation scope/resource check still runs later in the route
/// handler; this only resolves *who* the machine is acting on behalf of.
pub async fn apply_on_behalf_of_grant<S: GrantStore + ?Sized>(
    store: &S,
    headers: &http::HeaderMap,
    ctx: &mut OnBehalfOf,
) -> Result<(), ApiError> {
    let grant_header = headers
        .get(APPROVAL_GRANT_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    ctx.approval_grant_id = grant_header.clone();

    // Human identity: uid == agent_id. Acting as itself, no grant needed.
    if ctx.uid == ctx.agent_id {
        return Ok(());
    }
    let Some(grant_header) = grant_header else {
        return Ok(());
    };
    let Ok(grant_id) = Uuid::parse_str(&grant_header) else {
        return Ok(());
    };
    let grant = match store.lookup_grant_for_subject(grant_id, &ctx.agent_id).await {
        Ok(Some(grant)) => grant,
        Ok(None) => return Ok(()),
        Err(_) => return Ok(()),
    };
    ctx.uid = grant.owner_uid().to_owned();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn bearer_reexport_strips_scheme() {
        let h = hm(&[("authorization", "Bearer abc.def.ghi")]);
        assert_eq!(bearer_token(&h), Some("abc.def.ghi"));
    }

    #[test]
    fn trusted_headers_minimal() {
        let h = hm(&[("x-user-id", "user-1")]);
        let u = decode_trusted_headers(&h).unwrap();
        assert_eq!(u.uid, "user-1");
        assert_eq!(u.agent_id, "user-1"); // defaults to uid
        assert!(!u.can_write);
        assert_eq!(u.approval_grant_id, None);
    }

    #[test]
    fn trusted_headers_full() {
        let h = hm(&[
            ("x-user-id", "user-1"),
            ("x-agent-id", "agent-9"),
            ("x-user-can-write", "true"),
            ("x-approval-grant", "  grant-xyz  "),
        ]);
        let u = decode_trusted_headers(&h).unwrap();
        assert_eq!(u.agent_id, "agent-9");
        assert!(u.can_write);
        assert_eq!(u.approval_grant_id.as_deref(), Some("grant-xyz"));
    }

    #[test]
    fn trusted_headers_missing_uid_rejected() {
        assert!(matches!(
            decode_trusted_headers(&HeaderMap::new()),
            Err(ApiError::Unauthorized)
        ));
    }

    #[test]
    fn trusted_headers_control_char_rejected() {
        // A control char can't be set via HeaderValue::from_str, so build the
        // value from raw bytes (a tab is a visible-via-to_str control char)
        // to exercise the validation path directly.
        let mut h = HeaderMap::new();
        h.insert(
            http::HeaderName::from_static("x-user-id"),
            http::HeaderValue::from_static("ok"),
        );
        h.insert(
            http::HeaderName::from_static("x-agent-id"),
            http::HeaderValue::from_bytes(b"bad\tid").unwrap(),
        );
        assert!(matches!(
            decode_trusted_headers(&h),
            Err(ApiError::Unauthorized)
        ));
    }

    #[test]
    fn trusted_headers_overlong_uid_rejected() {
        let long = "x".repeat(MAX_ID_CHARS + 1);
        let h = hm(&[("x-user-id", long.as_str())]);
        assert!(matches!(
            decode_trusted_headers(&h),
            Err(ApiError::Unauthorized)
        ));
    }

    struct TestGrant {
        owner: String,
    }
    impl Grant for TestGrant {
        fn owner_uid(&self) -> &str {
            &self.owner
        }
    }

    struct TestStore {
        // grant_id -> (subject, owner) the store will match
        expect_subject: String,
        owner: String,
    }
    #[async_trait::async_trait]
    impl GrantStore for TestStore {
        type Grant = TestGrant;
        async fn lookup_grant_for_subject(
            &self,
            _grant_id: Uuid,
            requester_chirp_sub: &str,
        ) -> Result<Option<TestGrant>, ApiError> {
            if requester_chirp_sub == self.expect_subject {
                Ok(Some(TestGrant {
                    owner: self.owner.clone(),
                }))
            } else {
                Ok(None)
            }
        }
    }

    fn machine_ctx(grant: &str) -> (HeaderMap, OnBehalfOf) {
        (
            hm(&[("x-approval-grant", grant)]),
            OnBehalfOf {
                uid: "owner_sub_from_token".into(),
                agent_id: "agent_machine_sub".into(),
                approval_grant_id: None,
            },
        )
    }

    #[tokio::test]
    async fn human_identity_is_noop() {
        let store = TestStore {
            expect_subject: "anything".into(),
            owner: "should-not-apply".into(),
        };
        let h = hm(&[("x-approval-grant", "550e8400-e29b-41d4-a716-446655440000")]);
        let mut ctx = OnBehalfOf {
            uid: "human-1".into(),
            agent_id: "human-1".into(), // uid == agent_id => human
            approval_grant_id: None,
        };
        apply_on_behalf_of_grant(&store, &h, &mut ctx).await.unwrap();
        assert_eq!(ctx.uid, "human-1"); // unchanged
        // header still copied through
        assert!(ctx.approval_grant_id.is_some());
    }

    #[tokio::test]
    async fn valid_grant_overrides_uid() {
        let store = TestStore {
            expect_subject: "agent_machine_sub".into(),
            owner: "target-human".into(),
        };
        let (h, mut ctx) = machine_ctx("550e8400-e29b-41d4-a716-446655440000");
        apply_on_behalf_of_grant(&store, &h, &mut ctx).await.unwrap();
        assert_eq!(ctx.uid, "target-human");
        assert_eq!(
            ctx.approval_grant_id.as_deref(),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
    }

    #[tokio::test]
    async fn malformed_grant_id_is_noop() {
        let store = TestStore {
            expect_subject: "agent_machine_sub".into(),
            owner: "target-human".into(),
        };
        let (h, mut ctx) = machine_ctx("not-a-uuid");
        apply_on_behalf_of_grant(&store, &h, &mut ctx).await.unwrap();
        assert_eq!(ctx.uid, "owner_sub_from_token"); // unchanged
    }

    #[tokio::test]
    async fn lookup_miss_is_noop() {
        let store = TestStore {
            expect_subject: "some-other-subject".into(),
            owner: "target-human".into(),
        };
        let (h, mut ctx) = machine_ctx("550e8400-e29b-41d4-a716-446655440000");
        apply_on_behalf_of_grant(&store, &h, &mut ctx).await.unwrap();
        assert_eq!(ctx.uid, "owner_sub_from_token"); // unchanged
    }

    #[tokio::test]
    async fn missing_grant_header_is_noop() {
        let store = TestStore {
            expect_subject: "agent_machine_sub".into(),
            owner: "target-human".into(),
        };
        let h = HeaderMap::new();
        let mut ctx = OnBehalfOf {
            uid: "owner_sub_from_token".into(),
            agent_id: "agent_machine_sub".into(),
            approval_grant_id: None,
        };
        apply_on_behalf_of_grant(&store, &h, &mut ctx).await.unwrap();
        assert_eq!(ctx.uid, "owner_sub_from_token");
        assert_eq!(ctx.approval_grant_id, None);
    }
}
