//! Apple's own sample from its attestation object validation guide (a real
//! attestation, April 2026), plus synthetic chains built with rcgen for each
//! rejection.

use super::*;
use crate::{verify, Attestation, Policy, RevocationList};
use rcgen::{
    date_time_ymd, BasicConstraints, Certificate, CertificateParams, CustomExtension, DnType, IsCa, KeyPair,
    PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384,
};

// ── Apple's sample ───────────────────────────────────────────

const GUIDE: &[u8] = include_bytes!("../../testdata/apple/apple-guide-attestation.cbor");
const GUIDE_APP: &str = "1234567890.com.example.myapp";
const GUIDE_CLIENT_DATA: &[u8] = b"example_server_challenge";
const GUIDE_TIME: i64 = 1_776_800_000; // 2026-04-21, inside the credential certificate's 3 days

fn guide_policy(app: &str) -> ApplePolicy {
    ApplePolicy { app_ids: vec![app.into()], allow_development: false }
}

#[test]
fn apples_sample_verifies_under_apples_root() {
    let v = verify_client_data(GUIDE, GUIDE_CLIENT_DATA, &guide_policy(GUIDE_APP), &TrustAnchors::google(), GUIDE_TIME)
        .unwrap();
    assert_eq!(v.app_id, GUIDE_APP);
    assert!(!v.development);
    // The guide's key identifier, zgSY9YSD+7TaDXssY6WlOPVS1K3Lmk+pFhlcSWE+ZV0=.
    assert_eq!(v.key_id, "ce0498f58483fbb4da0d7b2c63a5a538f552d4adcb9a4fa916195c49613e655d");
}

#[test]
fn apples_sample_is_refused_for_another_request_app_or_time() {
    let anchors = TrustAnchors::google();
    let p = guide_policy(GUIDE_APP);
    assert_eq!(
        verify_client_data(GUIDE, b"another_challenge", &p, &anchors, GUIDE_TIME).unwrap_err(),
        AttestError::ChallengeMismatch
    );
    assert!(matches!(
        verify_client_data(GUIDE, GUIDE_CLIENT_DATA, &guide_policy("1234567890.com.example.other"), &anchors, GUIDE_TIME),
        Err(AttestError::App(_))
    ));
    assert!(matches!(
        verify_client_data(GUIDE, GUIDE_CLIENT_DATA, &p, &anchors, GUIDE_TIME + 30 * 86_400),
        Err(AttestError::Chain(_))
    ));
    // Without Apple's root nothing is trusted.
    assert_eq!(
        verify_client_data(GUIDE, GUIDE_CLIENT_DATA, &p, &TrustAnchors::for_tests(&[]), GUIDE_TIME).unwrap_err(),
        AttestError::UntrustedRoot
    );
}

// ── Synthetic chains ─────────────────────────────────────────

const APP: &str = "ABCDE12345.com.example.app";
const CHALLENGE: [u8; 32] = [0x5a; 32];
const NOW: i64 = 1_793_000_000; // 2026-10-26

struct Ca {
    cert: Certificate,
    key: KeyPair,
}

fn ca(name: &str, issuer: Option<&Ca>) -> Ca {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, name);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.not_before = date_time_ymd(2020, 1, 1);
    p.not_after = date_time_ymd(2040, 1, 1);
    let cert = match issuer {
        None => p.self_signed(&key).unwrap(),
        Some(i) => p.signed_by(&key, &i.cert, &i.key).unwrap(),
    };
    Ca { cert, key }
}

#[derive(Clone)]
struct Make {
    app: &'static str,
    aaguid: [u8; 16],
    counter: u32,
    wrong_cred_id: bool,
    challenge: [u8; 32],
}

impl Default for Make {
    fn default() -> Self {
        Make { app: APP, aaguid: *AAGUID_PRODUCTION, counter: 0, wrong_cred_id: false, challenge: CHALLENGE }
    }
}

fn cbor_head(major: u8, n: usize) -> Vec<u8> {
    match n {
        0..=23 => vec![(major << 5) | n as u8],
        24..=0xff => vec![(major << 5) | 24, n as u8],
        _ => vec![(major << 5) | 25, (n >> 8) as u8, n as u8],
    }
}

fn cbor_text(s: &str) -> Vec<u8> {
    [cbor_head(3, s.len()), s.as_bytes().to_vec()].concat()
}

fn cbor_bytes(b: &[u8]) -> Vec<u8> {
    [cbor_head(2, b.len()), b.to_vec()].concat()
}

/// An attestation object as App Attest makes one, signed by `inter`.
fn object(m: &Make, inter: &Ca) -> Vec<u8> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let point = key.public_key_raw().to_vec();
    let mut cred_id: [u8; 32] = Sha256::digest(&point).into();
    if m.wrong_cred_id {
        cred_id[0] ^= 1;
    }
    let mut auth = Sha256::digest(m.app.as_bytes()).to_vec();
    auth.push(0x40);
    auth.extend_from_slice(&m.counter.to_be_bytes());
    auth.extend_from_slice(&m.aaguid);
    auth.extend_from_slice(&32u16.to_be_bytes());
    auth.extend_from_slice(&cred_id);
    auth.extend_from_slice(&[0xa0]); // stand-in for the COSE key
    let nonce = Sha256::digest([auth.as_slice(), &m.challenge].concat());
    // SEQUENCE { [1] { OCTET STRING nonce } }
    let ext = [&[0x30, 0x24, 0xa1, 0x22, 0x04, 0x20][..], &nonce].concat();

    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, hex::encode(cred_id));
    p.not_before = date_time_ymd(2026, 10, 25);
    p.not_after = date_time_ymd(2026, 10, 28);
    p.custom_extensions = vec![CustomExtension::from_oid_content(&[1, 2, 840, 113635, 100, 8, 2], ext)];
    let cred = p.signed_by(&key, &inter.cert, &inter.key).unwrap();

    let mut o = cbor_head(5, 3);
    o.extend(cbor_text("fmt"));
    o.extend(cbor_text("apple-appattest"));
    o.extend(cbor_text("attStmt"));
    o.extend(cbor_head(5, 2));
    o.extend(cbor_text("x5c"));
    o.extend(cbor_head(4, 2));
    o.extend(cbor_bytes(cred.der()));
    o.extend(cbor_bytes(inter.cert.der()));
    o.extend(cbor_text("receipt"));
    o.extend(cbor_bytes(b"receipt"));
    o.extend(cbor_text("authData"));
    o.extend(cbor_bytes(&auth));
    o
}

struct World {
    root: Ca,
    inter: Ca,
}

fn world() -> World {
    let root = ca("Test App Attestation Root", None);
    let inter = ca("Test App Attestation CA", Some(&root));
    World { root, inter }
}

fn anchors(w: &World) -> TrustAnchors {
    TrustAnchors::for_tests(&[]).with_apple_roots_for_tests(vec![w.root.cert.der().to_vec()])
}

fn policy(dev: bool) -> Policy {
    Policy::from_json(&format!(r#"{{"apple":{{"app_ids":["{APP}"],"allow_development":{dev}}}}}"#)).unwrap()
}

fn check(w: &World, m: &Make, dev: bool) -> Result<crate::Verdict, AttestError> {
    let a = Attestation::AppleAppAttest { object: object(m, &w.inter) };
    // Apple attestations don't depend on Google's revocation list, however old.
    let stale = RevocationList::from_json(br#"{"entries":{}}"#, 0).unwrap();
    verify(&a, &CHALLENGE, &policy(dev), &anchors(w), &stale, NOW)
}

#[test]
fn an_attestation_for_this_request_passes() {
    let w = world();
    let v = check(&w, &Make::default(), false).unwrap();
    assert_eq!(v.apple.unwrap().app_id, APP);
    assert!(v.android.is_none());
}

#[test]
fn every_rejection() {
    let w = world();
    let cases: Vec<(Make, &str)> = vec![
        (Make { challenge: [0x11; 32], ..Make::default() }, "challenge"),
        (Make { app: "ABCDE12345.com.example.other", ..Make::default() }, "app id"),
        (Make { counter: 1, ..Make::default() }, "counter"),
        (Make { wrong_cred_id: true, ..Make::default() }, "credential id"),
        (Make { aaguid: *AAGUID_DEVELOPMENT, ..Make::default() }, "development build"),
        (Make { aaguid: *b"somethingelse\0\0\0", ..Make::default() }, "aaguid"),
    ];
    for (m, what) in cases {
        assert!(check(&w, &m, false).is_err(), "{what} should be refused");
    }
    // Development builds pass only when the policy allows them.
    let dev = Make { aaguid: *AAGUID_DEVELOPMENT, ..Make::default() };
    assert!(check(&w, &dev, true).unwrap().apple.unwrap().development);
}

#[test]
fn another_ca_or_no_apple_policy_is_refused() {
    let w = world();
    let other = world();
    let a = Attestation::AppleAppAttest { object: object(&Make::default(), &other.inter) };
    let list = RevocationList::from_json(br#"{"entries":{}}"#, NOW).unwrap();
    assert_eq!(verify(&a, &CHALLENGE, &policy(false), &anchors(&w), &list, NOW).unwrap_err(), AttestError::UntrustedRoot);

    let android_only = Policy::from_json(
        r#"{"android":{"package_names":["a.b"],"signing_cert_sha256":["0000000000000000000000000000000000000000000000000000000000000000"]}}"#,
    )
    .unwrap();
    let a = Attestation::AppleAppAttest { object: object(&Make::default(), &w.inter) };
    assert!(matches!(verify(&a, &CHALLENGE, &android_only, &anchors(&w), &list, NOW), Err(AttestError::Policy(_))));
}

#[test]
fn the_wire_format_round_trips_and_hashes_by_format() {
    let a: Attestation = serde_json::from_str(r#"{"format":"apple-app-attest","object":"AQID"}"#).unwrap();
    assert_eq!(a, Attestation::AppleAppAttest { object: vec![1, 2, 3] });
    assert_eq!(serde_json::to_string(&a).unwrap(), r#"{"format":"apple-app-attest","object":"AQID"}"#);
    let android = Attestation::AndroidKey { chain: vec![vec![1, 2, 3]] };
    assert_ne!(a.hash(), android.hash());
}

#[test]
fn policies_need_well_formed_app_ids() {
    for bad in [r#"{"apple":{"app_ids":[]}}"#, r#"{"apple":{"app_ids":["com.example.app"]}}"#, r#"{}"#] {
        assert!(Policy::from_json(bad).is_err(), "{bad}");
    }
}
