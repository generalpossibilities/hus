//! Android Key Attestation.
//!
//! Schema: https://source.android.com/docs/security/features/keystore/attestation
//! Trust and revocation: https://developer.android.com/privacy-and-security/security-key-attestation

use crate::der::{self, Tlv, CLASS_CONTEXT, OCTET_STRING, SEQUENCE, SET};
use crate::{AndroidPolicy, AttestError, RevocationList, TrustAnchors};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use x509_parser::certificate::X509Certificate;

pub const KEY_DESCRIPTION_OID: &str = "1.3.6.1.4.1.11129.2.1.17";
const MAX_CHAIN: usize = 10;

// AuthorizationList tags.
const TAG_ORIGIN: u32 = 702;
const TAG_ROOT_OF_TRUST: u32 = 704;
const TAG_OS_PATCH_LEVEL: u32 = 706;
const TAG_APPLICATION_ID: u32 = 709;
const TAG_VENDOR_PATCH_LEVEL: u32 = 718;
const TAG_BOOT_PATCH_LEVEL: u32 = 719;

const ORIGIN_GENERATED: i64 = 0;
const BOOT_VERIFIED: i64 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityLevel {
    Software = 0,
    #[default]
    TrustedEnvironment = 1,
    StrongBox = 2,
}

impl SecurityLevel {
    fn from_enum(v: i64) -> Result<Self, AttestError> {
        match v {
            0 => Ok(SecurityLevel::Software),
            1 => Ok(SecurityLevel::TrustedEnvironment),
            2 => Ok(SecurityLevel::StrongBox),
            _ => Err(AttestError::Malformed("security level")),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AndroidVerdict {
    pub attestation_version: i64,
    pub security_level: SecurityLevel,
    pub package_names: Vec<String>,
    pub os_patch_level: Option<i64>,
    /// SHA-256 of the manufacturer's boot key, hex.
    pub verified_boot_key: String,
}

pub(crate) fn verify(
    chain_der: &[Vec<u8>],
    expected_challenge: &[u8; 32],
    policy: &AndroidPolicy,
    anchors: &TrustAnchors,
    revocations: &RevocationList,
    now: i64,
) -> Result<AndroidVerdict, AttestError> {
    let chain = check_chain(chain_der, anchors, revocations, now)?;
    let kd = KeyDescription::from_leaf(&chain[0])?;
    check_key_description(&kd, expected_challenge, policy)
}

fn chain_err(s: impl Into<String>) -> AttestError {
    AttestError::Chain(s.into())
}

fn check_chain<'a>(
    chain_der: &'a [Vec<u8>],
    anchors: &TrustAnchors,
    revocations: &RevocationList,
    now: i64,
) -> Result<Vec<X509Certificate<'a>>, AttestError> {
    if chain_der.len() < 2 || chain_der.len() > MAX_CHAIN {
        return Err(chain_err(format!("needs 2..={MAX_CHAIN} certificates")));
    }
    let mut chain = Vec::with_capacity(chain_der.len());
    for (i, d) in chain_der.iter().enumerate() {
        let (rest, c) = x509_parser::parse_x509_certificate(d)
            .map_err(|e| chain_err(format!("certificate {i}: {e}")))?;
        if !rest.is_empty() {
            return Err(chain_err(format!("certificate {i}: trailing bytes")));
        }
        chain.push(c);
    }

    let root = chain.last().expect("len checked");
    if !anchors.contains(&root.public_key().raw) {
        return Err(AttestError::UntrustedRoot);
    }

    let last = chain.len() - 1;
    for i in 0..last {
        let (child, parent) = (&chain[i], &chain[i + 1]);
        if child.issuer().as_raw() != parent.subject().as_raw() {
            return Err(chain_err(format!("certificate {i} is not issued by {}", i + 1)));
        }
        child
            .verify_signature(Some(parent.public_key()))
            .map_err(|e| chain_err(format!("certificate {i} signature: {e}")))?;
        let ca = parent
            .basic_constraints()
            .map_err(|e| chain_err(format!("certificate {}: {e}", i + 1)))?
            .map(|b| b.value.ca)
            .unwrap_or(false);
        if !ca {
            return Err(chain_err(format!("certificate {} is not a CA", i + 1)));
        }
    }

    // As Google's verifier does: the leaf's dates are set on the device and
    // mean nothing, and the root is trusted by key. Every other certificate
    // must be in date, except that factory-provisioned chains (their keys
    // can't be rotated) may have expired.
    let factory = is_factory_provisioned(&chain[last - 1]);
    for (i, c) in chain.iter().enumerate().take(last).skip(1) {
        let v = c.validity();
        if now < v.not_before.timestamp() {
            return Err(chain_err(format!("certificate {i} is not valid yet")));
        }
        if now > v.not_after.timestamp() && !factory {
            return Err(chain_err(format!("certificate {i} has expired")));
        }
    }

    for c in &chain {
        let hex = c.tbs_certificate.serial.to_str_radix(16);
        let dec = c.tbs_certificate.serial.to_str_radix(10);
        if revocations.is_listed(&hex, &dec) {
            return Err(AttestError::Revoked(hex));
        }
    }

    // Only the leaf may describe a key. A chain with the extension higher up
    // came from an app-provided attest key, which this check doesn't accept.
    for (i, c) in chain.iter().enumerate().skip(1) {
        if c.extensions().iter().any(|e| e.oid.to_id_string() == KEY_DESCRIPTION_OID) {
            return Err(chain_err(format!("certificate {i} also carries a key attestation")));
        }
    }
    Ok(chain)
}

/// A factory-provisioned intermediate (the one right under the root) names
/// the device's batch by a serialNumber attribute; remotely provisioned
/// chains have "Droid CA2" there instead.
fn is_factory_provisioned(intermediate: &X509Certificate<'_>) -> bool {
    intermediate
        .subject()
        .iter_attributes()
        .any(|a| a.attr_type().to_id_string() == "2.5.4.5")
}

/// The parts of KeyDescription this check reads.
#[derive(Debug)]
struct KeyDescription {
    attestation_version: i64,
    attestation_security_level: SecurityLevel,
    keymint_security_level: SecurityLevel,
    challenge: Vec<u8>,
    software: AuthList,
    hardware: AuthList,
}

#[derive(Debug, Default)]
struct AuthList {
    origin: Option<i64>,
    root_of_trust: Option<RootOfTrust>,
    os_patch_level: Option<i64>,
    application_id: Option<ApplicationId>,
    vendor_patch_level: Option<i64>,
    boot_patch_level: Option<i64>,
}

#[derive(Debug)]
struct RootOfTrust {
    verified_boot_key: Vec<u8>,
    device_locked: bool,
    verified_boot_state: i64,
}

#[derive(Debug, PartialEq, Eq)]
struct ApplicationId {
    package_names: Vec<String>,
    signature_digests: Vec<Vec<u8>>,
}

fn bad(what: &'static str) -> AttestError {
    AttestError::Malformed(what)
}

impl KeyDescription {
    fn from_leaf(leaf: &X509Certificate<'_>) -> Result<Self, AttestError> {
        let mut found = leaf
            .extensions()
            .iter()
            .filter(|e| e.oid.to_id_string() == KEY_DESCRIPTION_OID);
        let ext = found.next().ok_or(AttestError::NoAttestationExtension)?;
        if found.next().is_some() {
            return Err(bad("two key attestation extensions"));
        }
        Self::parse(ext.value)
    }

    fn parse(der_bytes: &[u8]) -> Result<Self, AttestError> {
        let (seq, rest) = der::expect(der_bytes, SEQUENCE)?;
        if !rest.is_empty() {
            return Err(bad("trailing bytes after KeyDescription"));
        }
        let f = der::items(seq.value)?;
        if f.len() < 8 {
            return Err(bad("KeyDescription too short"));
        }
        let challenge = der::octets(&f[4])?.to_vec();
        for (i, t) in [(6, &f[6]), (7, &f[7])] {
            if t.class != 0 || t.tag != SEQUENCE || !t.constructed {
                return Err(AttestError::Malformed(if i == 6 {
                    "softwareEnforced"
                } else {
                    "hardwareEnforced"
                }));
            }
        }
        Ok(KeyDescription {
            attestation_version: der::int(&f[0])?,
            attestation_security_level: SecurityLevel::from_enum(der::int(&f[1])?)?,
            keymint_security_level: SecurityLevel::from_enum(der::int(&f[3])?)?,
            challenge,
            software: AuthList::parse(f[6].value)?,
            hardware: AuthList::parse(f[7].value)?,
        })
    }
}

impl AuthList {
    fn parse(value: &[u8]) -> Result<Self, AttestError> {
        let mut by_tag: HashMap<u32, Tlv<'_>> = HashMap::new();
        for item in der::items(value)? {
            if item.class != CLASS_CONTEXT || !item.constructed {
                return Err(bad("authorization list entry"));
            }
            let (inner, rest) = der::read(item.value)?;
            if !rest.is_empty() {
                return Err(bad("authorization list entry trailing bytes"));
            }
            if by_tag.insert(item.tag, inner).is_some() {
                return Err(bad("repeated authorization tag"));
            }
        }
        let int_at = |tag| by_tag.get(&tag).map(der::int).transpose();
        Ok(AuthList {
            origin: int_at(TAG_ORIGIN)?,
            os_patch_level: int_at(TAG_OS_PATCH_LEVEL)?,
            vendor_patch_level: int_at(TAG_VENDOR_PATCH_LEVEL)?,
            boot_patch_level: int_at(TAG_BOOT_PATCH_LEVEL)?,
            root_of_trust: by_tag.get(&TAG_ROOT_OF_TRUST).map(RootOfTrust::parse).transpose()?,
            application_id: by_tag
                .get(&TAG_APPLICATION_ID)
                .map(ApplicationId::parse)
                .transpose()?,
        })
    }
}

impl RootOfTrust {
    fn parse(t: &Tlv<'_>) -> Result<Self, AttestError> {
        if t.class != 0 || t.tag != SEQUENCE || !t.constructed {
            return Err(bad("rootOfTrust"));
        }
        let f = der::items(t.value)?;
        if f.len() < 3 {
            return Err(bad("rootOfTrust too short"));
        }
        Ok(RootOfTrust {
            verified_boot_key: der::octets(&f[0])?.to_vec(),
            device_locked: der::boolean(&f[1])?,
            verified_boot_state: der::int(&f[2])?,
        })
    }
}

impl ApplicationId {
    /// The value is an OCTET STRING holding a DER AttestationApplicationId.
    fn parse(t: &Tlv<'_>) -> Result<Self, AttestError> {
        let inner = der::octets(t)?;
        let (seq, rest) = der::expect(inner, SEQUENCE)?;
        if !rest.is_empty() {
            return Err(bad("attestationApplicationId trailing bytes"));
        }
        let f = der::items(seq.value)?;
        if f.len() != 2 {
            return Err(bad("attestationApplicationId fields"));
        }
        let (infos, digests) = (&f[0], &f[1]);
        if infos.tag != SET || digests.tag != SET || !infos.constructed || !digests.constructed {
            return Err(bad("attestationApplicationId sets"));
        }
        let mut package_names = Vec::new();
        for info in der::items(infos.value)? {
            if info.tag != SEQUENCE || !info.constructed {
                return Err(bad("package info"));
            }
            let p = der::items(info.value)?;
            let name = p.first().ok_or(bad("package info"))?;
            if name.tag != OCTET_STRING {
                return Err(bad("package name"));
            }
            let name = std::str::from_utf8(name.value).map_err(|_| bad("package name"))?;
            package_names.push(name.to_string());
        }
        let signature_digests = der::items(digests.value)?
            .iter()
            .map(|d| der::octets(d).map(<[u8]>::to_vec))
            .collect::<Result<_, _>>()?;
        Ok(ApplicationId { package_names, signature_digests })
    }
}

fn check_key_description(
    kd: &KeyDescription,
    expected_challenge: &[u8],
    p: &AndroidPolicy,
) -> Result<AndroidVerdict, AttestError> {
    if kd.challenge.as_slice() != expected_challenge {
        return Err(AttestError::ChallengeMismatch);
    }
    if kd.attestation_version < p.min_attestation_version {
        return Err(AttestError::SecurityLevel(format!(
            "attestation version {} is below {}",
            kd.attestation_version, p.min_attestation_version
        )));
    }
    let min = p.min_security_level.max(SecurityLevel::TrustedEnvironment);
    let level = kd.attestation_security_level.min(kd.keymint_security_level);
    if level < min {
        return Err(AttestError::SecurityLevel(format!("{level:?} is below {min:?}")));
    }

    let hw = &kd.hardware;
    if hw.origin.is_some_and(|o| o != ORIGIN_GENERATED) {
        return Err(AttestError::SecurityLevel("key was not generated on the device".into()));
    }
    let rot = hw
        .root_of_trust
        .as_ref()
        .ok_or_else(|| AttestError::BootState("no hardware-enforced root of trust".into()))?;
    if !rot.device_locked {
        return Err(AttestError::BootState("bootloader is unlocked".into()));
    }
    if rot.verified_boot_state != BOOT_VERIFIED {
        return Err(AttestError::BootState(format!(
            "verified boot state is {}, not Verified",
            rot.verified_boot_state
        )));
    }

    // The platform keystore writes the app id; KeyMint signs it into the
    // certificate. Older devices put it in softwareEnforced.
    let app = hw
        .application_id
        .as_ref()
        .or(kd.software.application_id.as_ref())
        .ok_or_else(|| AttestError::App("no attestationApplicationId".into()))?;
    if app.package_names.is_empty() {
        return Err(AttestError::App("no package listed".into()));
    }
    for name in &app.package_names {
        if !p.package_names.iter().any(|n| n == name) {
            return Err(AttestError::App(format!("package {name} is not allowed")));
        }
    }
    if app.signature_digests.is_empty() {
        return Err(AttestError::App("no signing certificate listed".into()));
    }
    let allowed: Vec<Vec<u8>> = p
        .signing_cert_sha256
        .iter()
        .filter_map(|d| hex::decode(d.trim_start_matches("0x")).ok())
        .collect();
    for d in &app.signature_digests {
        if !allowed.contains(d) {
            return Err(AttestError::App(format!("signing certificate {} is not allowed", hex::encode(d))));
        }
    }

    let need = |name: &str, have: Option<i64>, min: Option<i64>| -> Result<(), AttestError> {
        match (min, have) {
            (None, _) => Ok(()),
            (Some(m), Some(h)) if h >= m => Ok(()),
            (Some(m), Some(h)) => Err(AttestError::PatchLevel(format!("{name} {h} is below {m}"))),
            (Some(_), None) => Err(AttestError::PatchLevel(format!("{name} is not attested"))),
        }
    };
    need("OS patch level", hw.os_patch_level, p.min_os_patch_level)?;
    need("vendor patch level", hw.vendor_patch_level, p.min_vendor_patch_level)?;
    need("boot patch level", hw.boot_patch_level, p.min_boot_patch_level)?;

    Ok(AndroidVerdict {
        attestation_version: kd.attestation_version,
        security_level: level,
        package_names: app.package_names.clone(),
        os_patch_level: hw.os_patch_level,
        verified_boot_key: hex::encode(&rot.verified_boot_key),
    })
}

#[cfg(test)]
mod tests;
