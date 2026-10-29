//! Synthetic chains built with rcgen, carrying a hand-encoded KeyDescription.
//! A real-device chain belongs here too once the app produces one.

use super::*;
use crate::{verify, Attestation, AttestError, Policy, RevocationList, TrustAnchors};
use rcgen::{
    date_time_ymd, BasicConstraints, Certificate, CertificateParams, CustomExtension, DnType, IsCa,
    KeyPair, SerialNumber, PKCS_ECDSA_P256_SHA256,
};

const NOW: i64 = 1_793_000_000; // 2026-10-26
const PACKAGE: &str = "com.example.app";
const DIGEST: [u8; 32] = [0xd1; 32];
const CHALLENGE: [u8; 32] = [0xc4; 32];

// ── DER writer ───────────────────────────────────────────────

fn tlv(id: &[u8], content: &[u8]) -> Vec<u8> {
    let mut out = id.to_vec();
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let b = (n as u32).to_be_bytes();
        let skip = b.iter().take_while(|x| **x == 0).count();
        out.push(0x80 | (4 - skip) as u8);
        out.extend_from_slice(&b[skip..]);
    }
    out.extend_from_slice(content);
    out
}

fn int_bytes(v: i64) -> Vec<u8> {
    let b = v.to_be_bytes();
    let mut i = 0;
    while i < 7 && ((b[i] == 0 && b[i + 1] & 0x80 == 0) || (b[i] == 0xff && b[i + 1] & 0x80 != 0)) {
        i += 1;
    }
    b[i..].to_vec()
}
fn int(v: i64) -> Vec<u8> {
    tlv(&[0x02], &int_bytes(v))
}
fn enumerated(v: i64) -> Vec<u8> {
    tlv(&[0x0a], &int_bytes(v))
}
fn octets(b: &[u8]) -> Vec<u8> {
    tlv(&[0x04], b)
}
fn boolean(v: bool) -> Vec<u8> {
    tlv(&[0x01], &[if v { 0xff } else { 0 }])
}
fn seq(items: &[Vec<u8>]) -> Vec<u8> {
    tlv(&[0x30], &items.concat())
}
fn set(items: &[Vec<u8>]) -> Vec<u8> {
    tlv(&[0x31], &items.concat())
}
fn ctx(tag: u32, inner: Vec<u8>) -> Vec<u8> {
    let id = if tag < 31 {
        vec![0xa0 | tag as u8]
    } else {
        let mut t = vec![(tag & 0x7f) as u8];
        let mut rest = tag >> 7;
        while rest > 0 {
            t.push(0x80 | (rest & 0x7f) as u8);
            rest >>= 7;
        }
        t.reverse();
        let mut id = vec![0xbf];
        id.extend(t);
        id
    };
    tlv(&id, &inner)
}

// ── KeyDescription ───────────────────────────────────────────

#[derive(Clone)]
struct Kd {
    version: i64,
    att_level: i64,
    km_level: i64,
    challenge: Vec<u8>,
    sw: Vec<(u32, Vec<u8>)>,
    hw: Vec<(u32, Vec<u8>)>,
}

fn app_id(packages: &[&str], digests: &[[u8; 32]]) -> Vec<u8> {
    let infos: Vec<_> = packages.iter().map(|p| seq(&[octets(p.as_bytes()), int(1)])).collect();
    let ds: Vec<_> = digests.iter().map(|d| octets(d)).collect();
    octets(&seq(&[set(&infos), set(&ds)]))
}

fn root_of_trust(locked: bool, state: i64) -> Vec<u8> {
    seq(&[octets(&[7; 32]), boolean(locked), enumerated(state), octets(&[8; 32])])
}

impl Kd {
    fn good() -> Self {
        Kd {
            version: 100,
            att_level: 1,
            km_level: 1,
            challenge: CHALLENGE.to_vec(),
            sw: vec![(TAG_APPLICATION_ID, app_id(&[PACKAGE], &[DIGEST]))],
            hw: vec![
                (TAG_ORIGIN, int(0)),
                (TAG_ROOT_OF_TRUST, root_of_trust(true, 0)),
                (TAG_OS_PATCH_LEVEL, int(202609)),
                (TAG_VENDOR_PATCH_LEVEL, int(20260901)),
                (TAG_BOOT_PATCH_LEVEL, int(20260901)),
            ],
        }
    }

    fn set_hw(mut self, tag: u32, v: Vec<u8>) -> Self {
        self.hw.retain(|(t, _)| *t != tag);
        self.hw.push((tag, v));
        self.hw.sort_by_key(|(t, _)| *t);
        self
    }

    fn der(&self) -> Vec<u8> {
        let list = |l: &[(u32, Vec<u8>)]| {
            seq(&l.iter().map(|(t, v)| ctx(*t, v.clone())).collect::<Vec<_>>())
        };
        seq(&[
            int(self.version),
            enumerated(self.att_level),
            int(self.version),
            enumerated(self.km_level),
            octets(&self.challenge),
            octets(&[]),
            list(&self.sw),
            list(&self.hw),
        ])
    }
}

// ── Chains ───────────────────────────────────────────────────

struct Ca {
    cert: Certificate,
    key: KeyPair,
}

fn ca(name: &str, serial: u8, issuer: Option<&Ca>, valid_until: i32) -> Ca {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, name);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.serial_number = Some(SerialNumber::from_slice(&[0x10, serial]));
    p.not_before = date_time_ymd(2020, 1, 1);
    p.not_after = date_time_ymd(valid_until, 1, 1);
    let cert = match issuer {
        None => p.self_signed(&key).unwrap(),
        Some(i) => p.signed_by(&key, &i.cert, &i.key).unwrap(),
    };
    Ca { cert, key }
}

fn leaf(kd: &[u8], issuer: &Ca, extra_ext: bool) -> Vec<u8> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, "Android Keystore Key");
    p.serial_number = Some(SerialNumber::from_slice(&[0x01]));
    let oid = [1, 3, 6, 1, 4, 1, 11129, 2, 1, 17];
    p.custom_extensions = vec![CustomExtension::from_oid_content(&oid, kd.to_vec())];
    if extra_ext {
        p.custom_extensions.push(CustomExtension::from_oid_content(&oid, kd.to_vec()));
    }
    p.signed_by(&key, &issuer.cert, &issuer.key).unwrap().der().to_vec()
}

struct Fixture {
    root: Ca,
    chain: Vec<Vec<u8>>,
}

fn fixture(kd: &Kd) -> Fixture {
    let root = ca("Test Root", 1, None, 2040);
    let inter = ca("Test Intermediate", 2, Some(&root), 2040);
    let chain = vec![leaf(&kd.der(), &inter, false), inter.cert.der().to_vec(), root.cert.der().to_vec()];
    Fixture { root, chain }
}

fn policy() -> Policy {
    Policy::from_json(&format!(
        r#"{{"android":{{"package_names":["{PACKAGE}"],"signing_cert_sha256":["{}"],
            "min_os_patch_level":202601}}}}"#,
        hex::encode(DIGEST)
    ))
    .unwrap()
}

fn no_revocations() -> RevocationList {
    RevocationList::from_json(br#"{"entries":{}}"#, NOW).unwrap()
}

fn run(f: &Fixture) -> Result<crate::Verdict, AttestError> {
    run_with(f, &policy(), &no_revocations())
}

fn run_with(f: &Fixture, p: &Policy, r: &RevocationList) -> Result<crate::Verdict, AttestError> {
    let anchors = TrustAnchors::for_tests(&[f.root.cert.der().to_vec()]);
    verify(&Attestation::AndroidKey { chain: f.chain.clone() }, &CHALLENGE, p, &anchors, r, NOW)
}

// ── Tests ────────────────────────────────────────────────────

#[test]
fn genuine_attestation_passes() {
    let f = fixture(&Kd::good());
    let v = run(&f).unwrap();
    let a = v.android.unwrap();
    assert_eq!(a.package_names, vec![PACKAGE.to_string()]);
    assert_eq!(a.security_level, SecurityLevel::TrustedEnvironment);
    assert_eq!(a.os_patch_level, Some(202609));
    assert_eq!(v.attestation_hash, Attestation::AndroidKey { chain: f.chain }.hash());
}

#[test]
fn app_id_in_hardware_list_is_read() {
    let mut kd = Kd::good();
    kd.sw.clear();
    let kd = kd.set_hw(TAG_APPLICATION_ID, app_id(&[PACKAGE], &[DIGEST]));
    assert!(run(&fixture(&kd)).is_ok());
}

#[test]
fn untrusted_root_rejected() {
    let f = fixture(&Kd::good());
    let other = ca("Other Root", 9, None, 2040);
    let anchors = TrustAnchors::for_tests(&[other.cert.der().to_vec()]);
    let r = verify(
        &Attestation::AndroidKey { chain: f.chain.clone() },
        &CHALLENGE,
        &policy(),
        &anchors,
        &no_revocations(),
        NOW,
    );
    assert_eq!(r.unwrap_err(), AttestError::UntrustedRoot);
}

#[test]
fn chain_without_root_rejected() {
    let mut f = fixture(&Kd::good());
    f.chain.pop();
    assert_eq!(run(&f).unwrap_err(), AttestError::UntrustedRoot);
}

#[test]
fn forged_signature_rejected() {
    // Same issuer name, different key: the leaf doesn't verify under the
    // intermediate that is presented.
    let root = ca("Test Root", 1, None, 2040);
    let inter = ca("Test Intermediate", 2, Some(&root), 2040);
    let forger = ca("Test Intermediate", 2, Some(&root), 2040);
    let chain = vec![leaf(&Kd::good().der(), &forger, false), inter.cert.der().to_vec(), root.cert.der().to_vec()];
    let f = Fixture { root, chain };
    assert!(matches!(run(&f).unwrap_err(), AttestError::Chain(m) if m.contains("signature")));
}

#[test]
fn revoked_certificate_rejected_in_both_spellings() {
    let f = fixture(&Kd::good());
    // The intermediate's serial is 0x1002 = 4098.
    for key in ["1002", "4098"] {
        let r = RevocationList::from_json(
            format!(r#"{{"entries":{{"{key}":{{"status":"REVOKED"}}}}}}"#).as_bytes(),
            NOW,
        )
        .unwrap();
        assert!(matches!(run_with(&f, &policy(), &r).unwrap_err(), AttestError::Revoked(_)), "{key}");
    }
}

#[test]
fn stale_revocation_list_rejected() {
    let f = fixture(&Kd::good());
    let r = RevocationList::from_json(br#"{"entries":{}}"#, NOW - 3 * 24 * 3600).unwrap();
    assert_eq!(run_with(&f, &policy(), &r).unwrap_err(), AttestError::RevocationListStale);
}

#[test]
fn expired_intermediate_rejected() {
    let root = ca("Test Root", 1, None, 2040);
    let inter = ca("Test Intermediate", 2, Some(&root), 2025);
    let chain = vec![leaf(&Kd::good().der(), &inter, false), inter.cert.der().to_vec(), root.cert.der().to_vec()];
    let f = Fixture { root, chain };
    assert!(matches!(run(&f).unwrap_err(), AttestError::Chain(m) if m.contains("expired")));
}

#[test]
fn attestation_above_the_leaf_rejected() {
    let root = ca("Test Root", 1, None, 2040);
    let inter = ca("Test Intermediate", 2, Some(&root), 2040);
    // An "attest key" style chain: a second key-description cert in the middle.
    let mid_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, "Attest Key");
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.serial_number = Some(SerialNumber::from_slice(&[0x33]));
    p.custom_extensions = vec![CustomExtension::from_oid_content(
        &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
        Kd::good().der(),
    )];
    let mid = p.signed_by(&mid_key, &inter.cert, &inter.key).unwrap();
    let mid_ca = Ca { cert: mid, key: mid_key };
    let chain = vec![
        leaf(&Kd::good().der(), &mid_ca, false),
        mid_ca.cert.der().to_vec(),
        inter.cert.der().to_vec(),
        root.cert.der().to_vec(),
    ];
    let f = Fixture { root, chain };
    assert!(matches!(run(&f).unwrap_err(), AttestError::Chain(m) if m.contains("also carries")));
}

#[test]
fn two_extensions_rejected() {
    let root = ca("Test Root", 1, None, 2040);
    let inter = ca("Test Intermediate", 2, Some(&root), 2040);
    let chain = vec![leaf(&Kd::good().der(), &inter, true), inter.cert.der().to_vec(), root.cert.der().to_vec()];
    let f = Fixture { root, chain };
    assert!(run(&f).is_err());
}

#[test]
fn wrong_challenge_rejected() {
    let mut kd = Kd::good();
    kd.challenge = vec![0xee; 32];
    assert_eq!(run(&fixture(&kd)).unwrap_err(), AttestError::ChallengeMismatch);
}

#[test]
fn software_keystore_rejected() {
    let mut kd = Kd::good();
    kd.att_level = 0;
    kd.km_level = 0;
    assert!(matches!(run(&fixture(&kd)).unwrap_err(), AttestError::SecurityLevel(_)));
    let mut kd = Kd::good();
    kd.att_level = 0; // KeyMint in the TEE but attestation signed in software
    assert!(matches!(run(&fixture(&kd)).unwrap_err(), AttestError::SecurityLevel(_)));
}

#[test]
fn strongbox_policy_rejects_tee() {
    let mut p = policy();
    p.android.as_mut().unwrap().min_security_level = SecurityLevel::StrongBox;
    let f = fixture(&Kd::good());
    assert!(matches!(run_with(&f, &p, &no_revocations()).unwrap_err(), AttestError::SecurityLevel(_)));
    let mut kd = Kd::good();
    kd.att_level = 2;
    kd.km_level = 2;
    assert!(run_with(&fixture(&kd), &p, &no_revocations()).is_ok());
}

#[test]
fn old_attestation_version_rejected() {
    let mut kd = Kd::good();
    kd.version = 2;
    assert!(matches!(run(&fixture(&kd)).unwrap_err(), AttestError::SecurityLevel(_)));
}

#[test]
fn imported_key_rejected() {
    let kd = Kd::good().set_hw(TAG_ORIGIN, int(2));
    assert!(matches!(run(&fixture(&kd)).unwrap_err(), AttestError::SecurityLevel(_)));
}

#[test]
fn unlocked_bootloader_rejected() {
    let kd = Kd::good().set_hw(TAG_ROOT_OF_TRUST, root_of_trust(false, 0));
    assert!(matches!(run(&fixture(&kd)).unwrap_err(), AttestError::BootState(m) if m.contains("unlocked")));
}

#[test]
fn unverified_boot_rejected() {
    for state in [1, 2, 3] {
        let kd = Kd::good().set_hw(TAG_ROOT_OF_TRUST, root_of_trust(true, state));
        assert!(matches!(run(&fixture(&kd)).unwrap_err(), AttestError::BootState(_)), "{state}");
    }
}

#[test]
fn root_of_trust_only_in_software_list_rejected() {
    let mut kd = Kd::good();
    kd.hw.retain(|(t, _)| *t != TAG_ROOT_OF_TRUST);
    kd.sw.push((TAG_ROOT_OF_TRUST, root_of_trust(true, 0)));
    assert!(matches!(run(&fixture(&kd)).unwrap_err(), AttestError::BootState(_)));
}

#[test]
fn wrong_package_rejected() {
    let mut kd = Kd::good();
    kd.sw = vec![(TAG_APPLICATION_ID, app_id(&["com.evil.app"], &[DIGEST]))];
    assert!(matches!(run(&fixture(&kd)).unwrap_err(), AttestError::App(_)));
    // A shared-uid sibling that isn't allowed fails too.
    let mut kd = Kd::good();
    kd.sw = vec![(TAG_APPLICATION_ID, app_id(&[PACKAGE, "com.evil.app"], &[DIGEST]))];
    assert!(matches!(run(&fixture(&kd)).unwrap_err(), AttestError::App(_)));
}

#[test]
fn wrong_signing_key_rejected() {
    let mut kd = Kd::good();
    kd.sw = vec![(TAG_APPLICATION_ID, app_id(&[PACKAGE], &[[0x99; 32]]))];
    assert!(matches!(run(&fixture(&kd)).unwrap_err(), AttestError::App(_)));
    let mut kd = Kd::good();
    kd.sw = vec![(TAG_APPLICATION_ID, app_id(&[PACKAGE], &[]))];
    assert!(matches!(run(&fixture(&kd)).unwrap_err(), AttestError::App(_)));
}

#[test]
fn missing_app_id_rejected() {
    let mut kd = Kd::good();
    kd.sw.clear();
    assert!(matches!(run(&fixture(&kd)).unwrap_err(), AttestError::App(_)));
}

#[test]
fn stale_or_missing_patch_level_rejected() {
    let kd = Kd::good().set_hw(TAG_OS_PATCH_LEVEL, int(202412));
    assert!(matches!(run(&fixture(&kd)).unwrap_err(), AttestError::PatchLevel(_)));
    let mut kd = Kd::good();
    kd.hw.retain(|(t, _)| *t != TAG_OS_PATCH_LEVEL);
    assert!(matches!(run(&fixture(&kd)).unwrap_err(), AttestError::PatchLevel(_)));
}

#[test]
fn repeated_tag_rejected() {
    let mut kd = Kd::good();
    kd.hw.push((TAG_OS_PATCH_LEVEL, int(202609)));
    assert!(matches!(run(&fixture(&kd)).unwrap_err(), AttestError::Malformed(_)));
}

#[test]
fn json_round_trip_and_hash() {
    let f = fixture(&Kd::good());
    let a = Attestation::AndroidKey { chain: f.chain.clone() };
    let j = serde_json::to_string(&a).unwrap();
    assert!(j.starts_with(r#"{"format":"android-key","chain":[""#));
    assert_eq!(serde_json::from_str::<Attestation>(&j).unwrap(), a);
    let mut other = f.chain.clone();
    other.swap(1, 2);
    assert_ne!(a.hash(), Attestation::AndroidKey { chain: other }.hash());
    assert!(serde_json::from_str::<Attestation>(r#"{"format":"none"}"#).is_err());
}

#[test]
fn policy_validation() {
    assert!(Policy::from_json(r#"{}"#).is_err());
    assert!(Policy::from_json(r#"{"android":{"package_names":[],"signing_cert_sha256":[]}}"#).is_err());
    assert!(Policy::from_json(r#"{"android":{"package_names":["a"],"signing_cert_sha256":["abcd"]}}"#).is_err());
    assert!(Policy::from_json(&format!(
        r#"{{"android":{{"package_names":["a"],"signing_cert_sha256":["{}"],"allow_unlocked":true}}}}"#,
        hex::encode(DIGEST)
    ))
    .is_err());
    let p = Policy::from_json(&format!(
        r#"{{"android":{{"package_names":["a"],"signing_cert_sha256":["{}"]}}}}"#,
        hex::encode(DIGEST)
    ))
    .unwrap();
    assert_eq!(p.android.unwrap().min_security_level, SecurityLevel::TrustedEnvironment);
    assert!(Policy::from_json(include_str!("../../policy.example.json")).is_ok());
}

#[test]
fn google_roots_load() {
    let a = TrustAnchors::google();
    assert_eq!(a.roots.len(), 2);
}

#[test]
fn expired_factory_intermediate_accepted() {
    // Factory-provisioned batch keys can't be rotated, so Google accepts
    // their expired intermediates (unless revoked).
    let root = ca("Test Root", 1, None, 2040);
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CustomDnType(vec![2, 5, 4, 5]), "e18c4f2ca699739a");
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.serial_number = Some(SerialNumber::from_slice(&[0x22]));
    p.not_before = date_time_ymd(2018, 1, 1);
    p.not_after = date_time_ymd(2025, 1, 1);
    let inter = Ca { cert: p.signed_by(&key, &root.cert, &root.key).unwrap(), key };
    let chain = vec![leaf(&Kd::good().der(), &inter, false), inter.cert.der().to_vec(), root.cert.der().to_vec()];
    assert!(run(&Fixture { root, chain }).is_ok());
}

// ── Real devices ─────────────────────────────────────────────
//
// Chains from Google's own verifier test data
// (github.com/android/keyattestation, testdata/, Apache-2.0), with the
// values Google decoded from them. Each is checked at the time it was made.

mod real {
    use super::super::*;
    use crate::{RevocationList, TrustAnchors};
    use base64::Engine as _;

    struct Sample {
        chain: Vec<Vec<u8>>,
        json: serde_json::Value,
    }

    fn load(name: &str) -> Sample {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/google-keyattestation/");
        let pem = std::fs::read(format!("{dir}{name}.pem")).unwrap();
        let chain = x509_parser::pem::Pem::iter_from_buffer(&pem)
            .map(|p| p.unwrap().contents)
            .collect();
        let json = serde_json::from_slice(&std::fs::read(format!("{dir}{name}.json")).unwrap()).unwrap();
        Sample { chain, json }
    }

    fn b64(s: &serde_json::Value) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD.decode(s.as_str().unwrap()).unwrap()
    }

    impl Sample {
        fn created(&self) -> i64 {
            let ms: i64 = self.json["softwareEnforced"]["creationDateTime"].as_str().unwrap().parse().unwrap();
            ms / 1000
        }
        fn app(&self) -> &serde_json::Value {
            &self.json["softwareEnforced"]["attestationApplicationId"]
        }
        fn policy(&self) -> AndroidPolicy {
            AndroidPolicy {
                package_names: vec![self.app()["packages"][0]["name"].as_str().unwrap().into()],
                signing_cert_sha256: vec![hex::encode(b64(&self.app()["signatures"][0]))],
                min_security_level: SecurityLevel::TrustedEnvironment,
                min_attestation_version: 3,
                min_os_patch_level: None,
                min_vendor_patch_level: None,
                min_boot_patch_level: None,
            }
        }
    }

    const ALL: &[&str] = &[
        "blueline_sdk28_TEE_EC_NONE",
        "akita_sdk34_TEE_EC_NONE",
        "caiman_sdk36_TEE_EC_RKP",
        "caiman_sdk36_SB_EC_RKP",
        "frankel_sdk37_TEE_EC_2026",
    ];

    fn empty_list(at: i64) -> RevocationList {
        RevocationList::from_json(br#"{"entries":{}}"#, at).unwrap()
    }

    #[test]
    fn chains_verify_under_google_roots() {
        for name in ALL {
            let s = load(name);
            let r = check_chain(&s.chain, &TrustAnchors::google(), &empty_list(s.created()), s.created());
            assert!(r.is_ok(), "{name}: {:?}", r.err());
        }
    }

    #[test]
    fn key_descriptions_match_googles_decoding() {
        for name in ALL {
            let s = load(name);
            let (_, leaf) = x509_parser::parse_x509_certificate(&s.chain[0]).unwrap();
            let kd = KeyDescription::from_leaf(&leaf).unwrap();
            let j = &s.json;
            assert_eq!(kd.attestation_version.to_string(), j["attestationVersion"].as_str().unwrap(), "{name}");
            let level = |v: &serde_json::Value| match v.as_str().unwrap() {
                "TRUSTED_ENVIRONMENT" => SecurityLevel::TrustedEnvironment,
                "STRONG_BOX" => SecurityLevel::StrongBox,
                _ => SecurityLevel::Software,
            };
            assert_eq!(kd.attestation_security_level, level(&j["attestationSecurityLevel"]), "{name}");
            assert_eq!(kd.keymint_security_level, level(&j["keyMintSecurityLevel"]), "{name}");
            assert_eq!(kd.challenge, b64(&j["attestationChallenge"]), "{name}");
            let app = kd.software.application_id.as_ref().unwrap();
            assert_eq!(app.package_names[0], s.app()["packages"][0]["name"].as_str().unwrap(), "{name}");
            assert_eq!(app.signature_digests[0], b64(&s.app()["signatures"][0]), "{name}");
            let hw = &j["hardwareEnforced"];
            assert_eq!(kd.hardware.os_patch_level.unwrap().to_string(), hw["osPatchLevel"].as_str().unwrap(), "{name}");
            assert_eq!(kd.hardware.origin, Some(ORIGIN_GENERATED), "{name}");
            let rot = kd.hardware.root_of_trust.as_ref().unwrap();
            assert_eq!(rot.device_locked, hw["rootOfTrust"]["deviceLocked"].as_bool().unwrap(), "{name}");
            assert_eq!(rot.verified_boot_key, b64(&hw["rootOfTrust"]["verifiedBootKey"]), "{name}");
            let state = ["VERIFIED", "SELF_SIGNED", "UNVERIFIED", "FAILED"][rot.verified_boot_state as usize];
            assert_eq!(state, hw["rootOfTrust"]["verifiedBootState"].as_str().unwrap(), "{name}");
        }
    }

    #[test]
    fn locked_devices_pass_and_unlocked_ones_fail() {
        for name in ALL {
            let s = load(name);
            let (_, leaf) = x509_parser::parse_x509_certificate(&s.chain[0]).unwrap();
            let kd = KeyDescription::from_leaf(&leaf).unwrap();
            let r = check_key_description(&kd, &b64(&s.json["attestationChallenge"]), &s.policy());
            if s.json["hardwareEnforced"]["rootOfTrust"]["deviceLocked"].as_bool().unwrap() {
                assert!(r.is_ok(), "{name}: {:?}", r.err());
            } else {
                assert!(matches!(r, Err(AttestError::BootState(_))), "{name}: {r:?}");
            }
            // Another challenge never passes.
            let r = check_key_description(&kd, &[0u8; 32], &s.policy());
            assert_eq!(r.unwrap_err(), AttestError::ChallengeMismatch, "{name}");
        }
    }

    #[test]
    fn rkp_chain_expires() {
        // RKP intermediates are short-lived and must be in date.
        let s = load("caiman_sdk36_TEE_EC_RKP");
        let later = s.created() + 400 * 24 * 3600;
        let r = check_chain(&s.chain, &TrustAnchors::google(), &empty_list(later), later);
        assert!(matches!(r, Err(AttestError::Chain(m)) if m.contains("expired")));
    }

    #[test]
    fn factory_chain_survives_expiry() {
        let s = load("blueline_sdk28_TEE_EC_NONE");
        let later = s.created() + 12 * 365 * 24 * 3600;
        assert!(check_chain(&s.chain, &TrustAnchors::google(), &empty_list(later), later).is_ok());
    }

    #[test]
    fn real_chain_revocation() {
        let s = load("caiman_sdk36_TEE_EC_RKP");
        let (_, att) = x509_parser::parse_x509_certificate(&s.chain[1]).unwrap();
        let serial = att.tbs_certificate.serial.to_str_radix(16);
        let list = RevocationList::from_json(
            format!(r#"{{"entries":{{"{serial}":{{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}}}}"#).as_bytes(),
            s.created(),
        )
        .unwrap();
        let r = check_chain(&s.chain, &TrustAnchors::google(), &list, s.created());
        assert!(matches!(r, Err(AttestError::Revoked(_))), "{r:?}");
    }
}
