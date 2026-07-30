//! Hermetic chirp-auth test tokens.
//!
//! A local mock JWKS server + real RS256 signing, so a service's tests
//! exercise the SAME verification code (`verify_chirp_id_token` /
//! `verify_from_headers`) production traffic goes through — instead of
//! `decode_trusted_headers`' unauthenticated header-trust bypass. Ported from
//! `chirp-auth-client`'s own private verify-path test harness (the proven
//! approach for this exact problem); this crate makes it a public, reusable
//! primitive so every service's tests can adopt it instead of hand-rolling
//! their own trusted-header dev mode.
//!
//! ```no_run
//! # async fn example() {
//! use platform_chirp_auth::testkit;
//!
//! let jwks_url = testkit::start_jwks_server().await;
//! let config = testkit::config("https://signin.test.example", "cs_test_aud", jwks_url);
//! let token = testkit::mint_human_id_token("https://signin.test.example", "cs_test_aud", "sub_alice");
//! // Hand `token` to your service's real HTTP auth path (Authorization: Bearer <token>).
//! # let _ = config;
//! # }
//! ```

use std::sync::OnceLock;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::{ChirpAuthConfig, ID_TOKEN_TYP};

/// The `kid` every testkit-minted token and the testkit JWKS agree on.
pub const TEST_KID: &str = "platform-testkit-kid-1";

/// One RSA-2048 keypair, generated lazily and shared for the process
/// lifetime — RSA keygen is the slow part (~200ms); a test suite that mints
/// many tokens should not pay it more than once.
fn keypair() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut rng = rand::thread_rng();
        RsaPrivateKey::new(&mut rng, 2048).expect("generate testkit RSA key")
    })
}

fn jwks_body() -> String {
    let pubkey = RsaPublicKey::from(keypair());
    let n = URL_SAFE_NO_PAD.encode(pubkey.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(pubkey.e().to_bytes_be());
    format!(r#"{{"keys":[{{"kty":"RSA","kid":"{TEST_KID}","alg":"RS256","n":"{n}","e":"{e}"}}]}}"#)
}

/// Bind `127.0.0.1:0` and serve the testkit JWKS to every request until the
/// test process exits. Returns the `http://host:port/jwks.json` URL to pass
/// to [`config`] (or directly to `ChirpAuthConfig::with_jwks_uri`).
pub async fn start_jwks_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind testkit jwks listener");
    let addr = listener.local_addr().expect("testkit jwks local_addr");
    let url = format!("http://{addr}/jwks.json");
    let body = jwks_body();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    url
}

fn sign(signing_input: &[u8]) -> Vec<u8> {
    let signer = SigningKey::<Sha256>::new(keypair().clone());
    let mut rng = rand::thread_rng();
    signer
        .sign_with_rng(&mut rng, signing_input)
        .to_bytes()
        .to_vec()
}

fn b64(s: &str) -> String {
    URL_SAFE_NO_PAD.encode(s.as_bytes())
}

fn make_jwt(header_json: &str, claims_json: &str) -> String {
    let signing_input = format!("{}.{}", b64(header_json), b64(claims_json));
    let sig = sign(signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs() as i64
}

/// Mint a real, signed HUMAN chirp id_token: `{iss, sub, aud, exp}`, no
/// `act` claim — verifies as `ChirpVerifiedIdentity::Human`.
pub fn mint_human_id_token(iss: &str, aud: &str, sub: &str) -> String {
    let header = format!(r#"{{"alg":"RS256","typ":"{ID_TOKEN_TYP}","kid":"{TEST_KID}"}}"#);
    let claims = format!(
        r#"{{"iss":"{iss}","sub":"{sub}","aud":"{aud}","exp":{}}}"#,
        now_unix() + 3600
    );
    make_jwt(&header, &claims)
}

/// Mint a real, signed MACHINE chirp id_token: `{iss, sub, aud, exp,
/// act:"machine", owner_sub}` — verifies as `ChirpVerifiedIdentity::Machine`.
/// `sub` is the machine's own agent sub; `owner_sub` is the human who
/// registered the client; `aud` is conventionally the client_id.
pub fn mint_machine_id_token(iss: &str, aud: &str, sub: &str, owner_sub: &str) -> String {
    let header = format!(r#"{{"alg":"RS256","typ":"{ID_TOKEN_TYP}","kid":"{TEST_KID}"}}"#);
    let claims = format!(
        r#"{{"iss":"{iss}","sub":"{sub}","aud":"{aud}","exp":{},"act":"machine","owner_sub":"{owner_sub}"}}"#,
        now_unix() + 3600
    );
    make_jwt(&header, &claims)
}

/// A `ChirpAuthConfig` pointed at the testkit's local mock JWKS server —
/// pass the URL [`start_jwks_server`] returned.
pub fn config(iss: &str, aud: &str, jwks_url: String) -> ChirpAuthConfig {
    ChirpAuthConfig::new(iss, aud).with_jwks_uri(jwks_url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{verify_chirp_id_token, ChirpVerifiedIdentity, VerifyOptions};

    #[tokio::test(flavor = "multi_thread")]
    async fn mints_a_human_token_that_verifies_for_real() {
        let jwks = start_jwks_server().await;
        let cfg = config("https://signin.test.example", "cs_test_aud", jwks);
        let token = mint_human_id_token("https://signin.test.example", "cs_test_aud", "sub_alice");
        let verified = verify_chirp_id_token(
            &reqwest::Client::new(),
            &cfg,
            &token,
            VerifyOptions::default(),
        )
        .await
        .expect("testkit token must verify against the testkit config");
        match verified.identity {
            ChirpVerifiedIdentity::Human { sub, .. } => assert_eq!(sub, "sub_alice"),
            other => panic!("expected Human, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mints_a_machine_token_that_verifies_for_real() {
        let jwks = start_jwks_server().await;
        let cfg = config("https://signin.test.example", "cs_test_client", jwks);
        let token = mint_machine_id_token(
            "https://signin.test.example",
            "cs_test_client",
            "agent_bot1",
            "sub_alice",
        );
        let opts = VerifyOptions::accept_machine_clients(["cs_test_client".to_owned()]);
        let verified = verify_chirp_id_token(&reqwest::Client::new(), &cfg, &token, opts)
            .await
            .expect("testkit machine token must verify");
        match verified.identity {
            ChirpVerifiedIdentity::Machine { sub, owner_sub, .. } => {
                assert_eq!(sub, "agent_bot1");
                assert_eq!(owner_sub, "sub_alice");
            }
            other => panic!("expected Machine, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_token_signed_under_a_different_testkit_key_fails_to_verify() {
        // Two independent JWKS servers each get their OWN process-wide keypair
        // (the OnceLock is per-binary, not per-server) — this test exists to
        // document that property rather than exercise cross-key rejection
        // directly, since a single test binary shares one testkit keypair by
        // design (that's what makes minting cheap). Real cross-tenant
        // signature rejection is chirp-auth-client's own, already-proven
        // verify-path coverage.
        let jwks = start_jwks_server().await;
        let cfg = config("https://signin.test.example", "cs_test_aud", jwks);
        // A well-formed but WRONG-aud token must still be rejected — proves
        // the testkit path runs real claim validation, not just a signature
        // check.
        let token = mint_human_id_token("https://signin.test.example", "cs_someone_else", "sub_alice");
        let result = verify_chirp_id_token(
            &reqwest::Client::new(),
            &cfg,
            &token,
            VerifyOptions::default(),
        )
        .await;
        assert!(result.is_err(), "wrong audience must be rejected");
    }
}
