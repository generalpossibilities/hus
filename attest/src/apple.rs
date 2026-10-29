//! Apple App Attest.
//!
//! Steps from Apple's "Validating apps that connect to your server" and its
//! attestation object validation guide (whose sample is a test vector here).
//! The app passes HUS's `attestation_challenge` as `clientDataHash` to
//! `DCAppAttestService.attestKey`, so the nonce is
//! `SHA-256(authData ‖ attestation_challenge)`.
//!
//! Not checked: the receipt (it is for Apple's fraud-metric service, not for
//! trust) and assertions (HUS uses one attestation per submission).

use crate::cbor::{self, Value};
use crate::{ApplePolicy, AttestError, TrustAnchors};
use serde::Serialize;
use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;

pub const NONCE_OID: &str = "1.2.840.113635.100.8.2";
const AAGUID_PRODUCTION: &[u8; 16] = b"appattest\0\0\0\0\0\0\0";
const AAGUID_DEVELOPMENT: &[u8; 16] = b"appattestdevelop";

#[derive(Debug, Clone, Serialize)]
pub struct AppleVerdict {
    pub app_id: String,
    /// Made by a development build (sandbox App Attest environment).
    pub development: bool,
    /// SHA-256 of the attested key (the app's key identifier), hex.
    pub key_id: String,
}

fn malformed(w: &'static str) -> AttestError {
    AttestError::Malformed(w)
}

pub(crate) fn verify(
    object: &[u8],
    expected_challenge: &[u8; 32],
    policy: &ApplePolicy,
    anchors: &TrustAnchors,
    now: i64,
) -> Result<AppleVerdict, AttestError> {
    verify_client_data(object, expected_challenge, policy, anchors, now)
}

/// [`verify`] with the raw `clientDataHash` bytes the app passed (Apple's
/// sample passes its challenge string itself).
pub(crate) fn verify_client_data(
    object: &[u8],
    client_data_hash: &[u8],
    policy: &ApplePolicy,
    anchors: &TrustAnchors,
    now: i64,
) -> Result<AppleVerdict, AttestError> {
    let obj = cbor::decode(object)?;
    if obj.get("fmt") != Some(&Value::Text("apple-appattest")) {
        return Err(malformed("not an apple-appattest object"));
    }
    let stmt = obj.get("attStmt").ok_or_else(|| malformed("no attStmt"))?;
    let auth_data = obj.get("authData").and_then(Value::bytes).ok_or_else(|| malformed("no authData"))?;
    let x5c: Vec<&[u8]> = match stmt.get("x5c") {
        Some(Value::Array(a)) => a.iter().map(|v| v.bytes().ok_or_else(|| malformed("x5c entry"))).collect::<Result<_, _>>()?,
        _ => return Err(malformed("no x5c")),
    };

    // 1. credCert ← intermediate ← Apple's App Attestation root, all in date.
    let chain = check_chain(&x5c, anchors, now)?;
    let cred = &chain[0];

    // 2–4. The nonce in credCert is SHA-256(authData ‖ clientDataHash).
    let mut h = Sha256::new();
    h.update(auth_data);
    h.update(client_data_hash);
    let nonce: [u8; 32] = h.finalize().into();
    if nonce_of(cred)? != nonce {
        return Err(AttestError::ChallengeMismatch);
    }

    // authData: rpIdHash(32) flags(1) signCount(4) aaguid(16) credIdLen(2) credId ...
    if auth_data.len() < 55 {
        return Err(malformed("authData too short"));
    }
    let rp_id_hash = &auth_data[..32];
    let counter = u32::from_be_bytes(auth_data[33..37].try_into().expect("4 bytes"));
    let aaguid = &auth_data[37..53];
    let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let cred_id = auth_data.get(55..55 + cred_len).ok_or_else(|| malformed("authData credential id"))?;

    // 5. The key identifier is SHA-256 of credCert's public key (X9.62 point).
    let point = cred.public_key().subject_public_key.data.as_ref();
    if point.len() != 65 || point[0] != 4 {
        return Err(malformed("credCert key is not an uncompressed P-256 point"));
    }
    let key_id: [u8; 32] = Sha256::digest(point).into();
    if cred_id != key_id {
        return Err(malformed("credential id is not the attested key"));
    }

    // 6. The App ID (TEAMID.bundle.id) is one of the integrator's.
    let app_id = policy
        .app_ids
        .iter()
        .find(|id| Sha256::digest(id.as_bytes()).as_slice() == rp_id_hash)
        .ok_or_else(|| AttestError::App("App ID is not in the policy".into()))?;

    // 7. A fresh key: counter 0.
    if counter != 0 {
        return Err(malformed("counter is not 0"));
    }

    // 8. Production, unless the policy allows development builds.
    let development = match aaguid {
        a if a == AAGUID_PRODUCTION => false,
        a if a == AAGUID_DEVELOPMENT => true,
        _ => return Err(malformed("unknown aaguid")),
    };
    if development && !policy.allow_development {
        return Err(AttestError::App("made by a development build".into()));
    }

    Ok(AppleVerdict { app_id: app_id.clone(), development, key_id: hex::encode(key_id) })
}

fn chain_err(s: impl Into<String>) -> AttestError {
    AttestError::Chain(s.into())
}

fn check_chain<'a>(x5c: &[&'a [u8]], anchors: &TrustAnchors, now: i64) -> Result<Vec<X509Certificate<'a>>, AttestError> {
    if x5c.len() != 2 {
        return Err(chain_err("x5c must be the credential certificate and one intermediate"));
    }
    let mut chain = Vec::with_capacity(2);
    for (i, d) in x5c.iter().enumerate() {
        let (rest, c) = x509_parser::parse_x509_certificate(d).map_err(|e| chain_err(format!("certificate {i}: {e}")))?;
        if !rest.is_empty() {
            return Err(chain_err(format!("certificate {i}: trailing bytes")));
        }
        chain.push(c);
    }
    let (cred, inter) = (&chain[0], &chain[1]);
    if cred.issuer().as_raw() != inter.subject().as_raw() {
        return Err(chain_err("credential certificate is not issued by the intermediate"));
    }
    cred.verify_signature(Some(inter.public_key()))
        .map_err(|e| chain_err(format!("credential certificate signature: {e}")))?;
    if !inter.basic_constraints().ok().flatten().map(|b| b.value.ca).unwrap_or(false) {
        return Err(chain_err("intermediate is not a CA"));
    }
    if !anchors.apple_signed(inter) {
        return Err(AttestError::UntrustedRoot);
    }
    for (i, c) in chain.iter().enumerate() {
        let v = c.validity();
        if now < v.not_before.timestamp() || now > v.not_after.timestamp() {
            return Err(chain_err(format!("certificate {i} is not in date")));
        }
    }
    Ok(chain)
}

/// The nonce in credCert: extension 1.2.840.113635.100.8.2, a SEQUENCE
/// holding `[1] EXPLICIT OCTET STRING`.
fn nonce_of(cred: &X509Certificate) -> Result<[u8; 32], AttestError> {
    let ext = cred
        .extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == NONCE_OID)
        .ok_or(AttestError::NoAttestationExtension)?;
    use crate::der::{self, CLASS_CONTEXT, OCTET_STRING, SEQUENCE};
    let (seq, rest) = der::expect(ext.value, SEQUENCE)?;
    if !rest.is_empty() {
        return Err(malformed("nonce extension"));
    }
    let (tagged, rest) = der::read(seq.value)?;
    if !rest.is_empty() || tagged.class != CLASS_CONTEXT || tagged.tag != 1 || !tagged.constructed {
        return Err(malformed("nonce extension"));
    }
    let (octets, rest) = der::expect(tagged.value, OCTET_STRING)?;
    if !rest.is_empty() {
        return Err(malformed("nonce extension"));
    }
    octets.value.try_into().map_err(|_| malformed("nonce is not 32 bytes"))
}

#[cfg(test)]
#[path = "apple/tests.rs"]
mod tests;
