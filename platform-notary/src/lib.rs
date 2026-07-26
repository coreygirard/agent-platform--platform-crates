//! The notary signing seam shared by third-party apps.
//!
//! An app notary-signs each record's immutable core so a recipient can verify
//! attribution against the app's published JWKS. The signing key is either a
//! local in-process Ed25519 key (dev/test) or a KMS-custodied ES256 key
//! (production) — both produce the same [`attestation_envelope`] detached-JWS
//! attestation. This enum unifies them behind one `async` API (async because the
//! KMS path is one `Sign` call per attestation; the local path resolves
//! in-process). It was near-identical, copy-pasted `notary.rs` in every app.
//!
//! [`Notary::sign`] is generic over `AttestableCore`, so the app's own record
//! core (its app-specific fields + canonical serialization) stays in the app —
//! this crate is only the key seam.

pub use attestation_envelope::kms::KmsNotary;
pub use attestation_envelope::NotaryKey;
use attestation_envelope::{AttestableCore, Attestation};

/// The notary key. `Local` = in-process Ed25519 (dev/test; `kid` changes per
/// process, so clients fetch the JWKS fresh). `Kms` = ES256 whose private key
/// never leaves AWS KMS (production; stable `kid` across cold starts).
pub enum Notary {
    Local(NotaryKey),
    Kms(KmsNotary),
}

impl Notary {
    /// The key id stamped on every attestation and published in the JWKS.
    #[must_use]
    pub fn kid(&self) -> &str {
        match self {
            Notary::Local(k) => k.kid(),
            Notary::Kms(k) => k.kid(),
        }
    }

    /// The JWKS published at `/.well-known/jwks.json` for client-side verify
    /// (an `OKP`/Ed25519 key locally, an `EC`/P-256 key under KMS).
    #[must_use]
    pub fn jwks(&self) -> serde_json::Value {
        match self {
            Notary::Local(k) => k.jwks(),
            Notary::Kms(k) => k.jwks(),
        }
    }

    /// Notary-sign a record core. The KMS path makes one `Sign` call and can fail
    /// on a KMS/transport error; the local path is infallible.
    pub async fn sign<C: AttestableCore>(&self, core: &C) -> anyhow::Result<Attestation> {
        match self {
            Notary::Local(k) => Ok(k.sign(core)),
            Notary::Kms(k) => Ok(k.sign(core).await?),
        }
    }
}
