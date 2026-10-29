//! Hardware attestation for HUS submissions.
//!
//! A HUS proof shows that a vector matches its commitment, not that the
//! vector came from a real capture. This crate checks the other half: that
//! the submission was produced by the integrator's unmodified app on a
//! genuine device with a locked bootloader, for exactly this submission.
//!
//! The device's attestation must carry
//! `hus_sdk::attestation_challenge(...)` for the submission, so one genuine
//! attestation can't be paired with a made-up vector, another proof, another
//! owner or another challenge.
//!
//! Supported: Android Key Attestation (a fresh Keystore key whose
//! certificate chain ends in a Google root) and Apple App Attest (a fresh
//! App Attest key, chain to Apple's App Attestation root).
//!
//! What it does not prove: that a real face was in front of the camera
//! (that is HUS's liveness, in the SDK), or that the device's secure
//! hardware is not itself compromised.

mod android;
mod apple;
pub mod cbor;
pub mod der;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use x509_parser::pem::parse_x509_pem;

pub use android::{AndroidVerdict, SecurityLevel};
pub use apple::AppleVerdict;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestError {
    Malformed(&'static str),
    Chain(String),
    UntrustedRoot,
    Revoked(String),
    RevocationListStale,
    NoAttestationExtension,
    ChallengeMismatch,
    SecurityLevel(String),
    BootState(String),
    App(String),
    PatchLevel(String),
    Policy(String),
}

impl std::fmt::Display for AttestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttestError::Malformed(w) => write!(f, "malformed attestation: {w}"),
            AttestError::Chain(w) => write!(f, "certificate chain: {w}"),
            AttestError::UntrustedRoot => write!(f, "chain does not end in a trusted root"),
            AttestError::Revoked(s) => write!(f, "certificate {s} is revoked"),
            AttestError::RevocationListStale => write!(f, "revocation list is too old"),
            AttestError::NoAttestationExtension => write!(f, "leaf has no key attestation"),
            AttestError::ChallengeMismatch => write!(f, "attestation is for another submission"),
            AttestError::SecurityLevel(w) => write!(f, "security level: {w}"),
            AttestError::BootState(w) => write!(f, "device boot state: {w}"),
            AttestError::App(w) => write!(f, "app identity: {w}"),
            AttestError::PatchLevel(w) => write!(f, "patch level: {w}"),
            AttestError::Policy(w) => write!(f, "policy: {w}"),
        }
    }
}

impl std::error::Error for AttestError {}

/// A device's attestation for one submission, as clients send it.
///
/// JSON: `{"format":"android-key","chain":["<base64 DER>", ...]}`, leaf first
/// (the certificate of the fresh Keystore key), root last; or
/// `{"format":"apple-app-attest","object":"<base64 attestation object>"}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "format", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Attestation {
    AndroidKey {
        #[serde(with = "b64_list")]
        chain: Vec<Vec<u8>>,
    },
    AppleAppAttest {
        #[serde(with = "b64_one")]
        object: Vec<u8>,
    },
}

impl Attestation {
    /// The hash stored on chain with the registration. Anyone holding the
    /// published attestation can recompute it.
    ///
    /// Android: `SHA-256("hus.attestation.android-key.v1" ‖ for each cert:
    /// u32 LE len ‖ DER)`. Apple: `SHA-256("hus.attestation.apple-app-attest.v1"
    /// ‖ u32 LE len ‖ attestation object)`.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        match self {
            Attestation::AndroidKey { chain } => {
                h.update(b"hus.attestation.android-key.v1");
                for c in chain {
                    h.update((c.len() as u32).to_le_bytes());
                    h.update(c);
                }
            }
            Attestation::AppleAppAttest { object } => {
                h.update(b"hus.attestation.apple-app-attest.v1");
                h.update((object.len() as u32).to_le_bytes());
                h.update(object);
            }
        }
        h.finalize().into()
    }
}

mod b64_one {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        base64::engine::general_purpose::STANDARD
            .decode(String::deserialize(d)?)
            .map_err(serde::de::Error::custom)
    }
}

mod b64_list {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        let e = base64::engine::general_purpose::STANDARD;
        s.collect_seq(v.iter().map(|c| e.encode(c)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        let e = base64::engine::general_purpose::STANDARD;
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|s| e.decode(s).map_err(serde::de::Error::custom))
            .collect()
    }
}

/// What the integrator accepts. It names the integrator's own app; HUS
/// has no built-in app identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub android: Option<AndroidPolicy>,
    #[serde(default)]
    pub apple: Option<ApplePolicy>,
    /// The revocation list must be at most this old (seconds).
    #[serde(default = "default_revocation_max_age")]
    pub revocation_max_age_secs: i64,
}

fn default_revocation_max_age() -> i64 {
    48 * 3600
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AndroidPolicy {
    /// Every package in the attestation must be one of these.
    pub package_names: Vec<String>,
    /// SHA-256 of the app's signing certificate(s), hex. Every digest in the
    /// attestation must be one of these.
    pub signing_cert_sha256: Vec<String>,
    /// `trusted-environment` (default) or `strong-box`. Software keystores
    /// are never accepted.
    #[serde(default)]
    pub min_security_level: SecurityLevel,
    /// Lowest attestation version (3 = Keymaster 4, Android 9).
    #[serde(default = "default_min_attestation_version")]
    pub min_attestation_version: i64,
    /// Lowest OS security patch, YYYYMM.
    pub min_os_patch_level: Option<i64>,
    /// Lowest vendor patch, YYYYMMDD.
    pub min_vendor_patch_level: Option<i64>,
    /// Lowest boot patch, YYYYMMDD.
    pub min_boot_patch_level: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplePolicy {
    /// The app's App IDs, `TEAMID.bundle.id`.
    pub app_ids: Vec<String>,
    /// Accept attestations from development builds (App Attest's sandbox).
    /// Never in production.
    #[serde(default)]
    pub allow_development: bool,
}

fn default_min_attestation_version() -> i64 {
    3
}

impl Policy {
    pub fn from_json(s: &str) -> Result<Self, AttestError> {
        let p: Policy = serde_json::from_str(s).map_err(|e| AttestError::Policy(e.to_string()))?;
        if let Some(a) = &p.android {
            if a.package_names.is_empty() || a.signing_cert_sha256.is_empty() {
                return Err(AttestError::Policy(
                    "android needs at least one package name and signing digest".into(),
                ));
            }
            for d in &a.signing_cert_sha256 {
                if hex::decode(d.trim_start_matches("0x")).map(|b| b.len()) != Ok(32) {
                    return Err(AttestError::Policy(format!("signing digest {d} is not 32 bytes hex")));
                }
            }
        }
        if let Some(a) = &p.apple {
            let ok = |id: &String| {
                id.split_once('.').is_some_and(|(team, bundle)| {
                    team.len() == 10 && team.bytes().all(|b| b.is_ascii_alphanumeric()) && !bundle.is_empty()
                })
            };
            if a.app_ids.is_empty() || !a.app_ids.iter().all(ok) {
                return Err(AttestError::Policy("apple needs App IDs of the form TEAMID.bundle.id".into()));
            }
        }
        if p.android.is_none() && p.apple.is_none() {
            return Err(AttestError::Policy("no platform is allowed".into()));
        }
        Ok(p)
    }
}

/// Root keys a chain may end in.
#[derive(Debug, Clone)]
pub struct TrustAnchors {
    roots: Vec<Anchor>,
    /// Apple App Attestation roots, DER.
    apple: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct Anchor {
    spki: Vec<u8>,
}

const APPLE_ROOTS: &[&str] = &[include_str!("../roots/apple-app-attestation-root.pem")];

fn pem_der(pem: &str) -> Vec<u8> {
    let (_, p) = parse_x509_pem(pem.as_bytes()).expect("embedded root PEM");
    p.contents
}

const GOOGLE_ROOTS: &[&str] = &[
    include_str!("../roots/google-rsa-2022.pem"),
    include_str!("../roots/google-key-attestation-ca1.pem"),
];

impl TrustAnchors {
    /// Google's hardware attestation roots, as published at
    /// https://android.googleapis.com/attestation/root (fetched 2026-10-29).
    /// Matched by public key, so re-issued certificates of the same RSA root
    /// key are covered.
    pub fn google() -> Self {
        let roots = GOOGLE_ROOTS
            .iter()
            .map(|pem| {
                let (_, p) = parse_x509_pem(pem.as_bytes()).expect("embedded root PEM");
                let c = p.parse_x509().expect("embedded root certificate");
                Anchor { spki: c.public_key().raw.to_vec() }
            })
            .collect();
        TrustAnchors { roots, apple: APPLE_ROOTS.iter().map(|p| pem_der(p)).collect() }
    }

    /// Other roots, for tests only.
    #[cfg(any(test, feature = "test-roots"))]
    pub fn for_tests(roots_der: &[Vec<u8>]) -> Self {
        let roots = roots_der
            .iter()
            .map(|d| {
                let (_, c) = x509_parser::parse_x509_certificate(d).expect("test root");
                Anchor { spki: c.public_key().raw.to_vec() }
            })
            .collect();
        TrustAnchors { roots, apple: Vec::new() }
    }

    /// Other Apple roots, for tests only.
    #[cfg(any(test, feature = "test-roots"))]
    pub fn with_apple_roots_for_tests(mut self, roots_der: Vec<Vec<u8>>) -> Self {
        self.apple = roots_der;
        self
    }

    /// Whether `cert` is signed by an Apple root (matched by name and key).
    fn apple_signed(&self, cert: &x509_parser::certificate::X509Certificate) -> bool {
        self.apple.iter().any(|d| {
            x509_parser::parse_x509_certificate(d).is_ok_and(|(_, r)| {
                r.subject().as_raw() == cert.issuer().as_raw() && cert.verify_signature(Some(r.public_key())).is_ok()
            })
        })
    }

    fn contains(&self, spki: &[u8]) -> bool {
        self.roots.iter().any(|a| a.spki == spki)
    }
}

/// Google's attestation status list
/// (https://android.googleapis.com/attestation/status).
#[derive(Debug, Clone)]
pub struct RevocationList {
    serials: HashSet<String>,
    fetched_at: i64,
}

#[derive(Deserialize)]
struct StatusFile {
    entries: std::collections::HashMap<String, serde_json::Value>,
}

impl RevocationList {
    pub const URL: &'static str = "https://android.googleapis.com/attestation/status";

    /// Every listed entry (REVOKED or SUSPENDED) is refused.
    pub fn from_json(body: &[u8], fetched_at: i64) -> Result<Self, AttestError> {
        let f: StatusFile =
            serde_json::from_slice(body).map_err(|_| AttestError::Malformed("status list"))?;
        let serials = f.entries.into_keys().map(|k| k.to_ascii_lowercase()).collect();
        Ok(RevocationList { serials, fetched_at })
    }

    pub fn fetched_at(&self) -> i64 {
        self.fetched_at
    }

    pub fn len(&self) -> usize {
        self.serials.len()
    }

    pub fn is_empty(&self) -> bool {
        self.serials.is_empty()
    }

    /// Google keys the list by lowercase hex serial, but the live list also
    /// has decimal-looking keys, so both spellings are checked.
    fn is_listed(&self, hex: &str, dec: &str) -> bool {
        self.serials.contains(hex) || self.serials.contains(dec)
    }
}

/// The checks passed; what the attestation says.
#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub attestation_hash: [u8; 32],
    pub android: Option<AndroidVerdict>,
    pub apple: Option<AppleVerdict>,
}

/// Check `attestation` for the submission whose
/// `hus_sdk::attestation_challenge` is `expected_challenge`.
pub fn verify(
    attestation: &Attestation,
    expected_challenge: &[u8; 32],
    policy: &Policy,
    anchors: &TrustAnchors,
    revocations: &RevocationList,
    now_unix: i64,
) -> Result<Verdict, AttestError> {
    match attestation {
        Attestation::AndroidKey { chain } => {
            // Google's revocation list covers Android only.
            if now_unix - revocations.fetched_at > policy.revocation_max_age_secs {
                return Err(AttestError::RevocationListStale);
            }
            let p = policy
                .android
                .as_ref()
                .ok_or_else(|| AttestError::Policy("android is not allowed".into()))?;
            let v = android::verify(chain, expected_challenge, p, anchors, revocations, now_unix)?;
            Ok(Verdict { attestation_hash: attestation.hash(), android: Some(v), apple: None })
        }
        Attestation::AppleAppAttest { object } => {
            let p = policy.apple.as_ref().ok_or_else(|| AttestError::Policy("apple is not allowed".into()))?;
            let v = apple::verify(object, expected_challenge, p, anchors, now_unix)?;
            Ok(Verdict { attestation_hash: attestation.hash(), android: None, apple: Some(v) })
        }
    }
}
