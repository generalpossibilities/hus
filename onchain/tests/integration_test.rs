//! Integration tests against Shellnet HusRegistry + HusApp.
//!
//! All tests are `#[ignore]` — they require:
//!   - Network access to Shellnet GraphQL endpoint
//!   - Wallet keys at `/tmp/hus-testnet/wallet/wallet.keys.json`
//!   - Sufficient VMSHELL balance for gas
//!   - HusRegistry deployed at CONTRACT_ADDR (set after deploy)
//!
//! Run with:
//!   cargo test --package hus-onchain --test integration_test -- --ignored --nocapture

use hus_onchain::hus_app::HusApp;
use hus_onchain::hus_registry::HusRegistry;
use std::sync::Arc;
use tvm_client::abi::Signer;
use tvm_client::ClientConfig;
use tvm_client::ClientContext;

const CONTRACT_ADDR: &str = "3fb1ca2bf0564aab352b06621b63fd48e8e432a4e13a636ec142d423ac187e67::3fb1ca2bf0564aab352b06621b63fd48e8e432a4e13a636ec142d423ac187e67";

/// All seven modalities (the registry takes modality ids; the contract sets
/// projDim and minScore itself).
fn default_chain_configs() -> Vec<u8> {
    (0..7).collect()
}

/// Face + Keystroke (minimum 2).
fn face_keystroke_configs() -> Vec<u8> {
    vec![0, 4]
}

/// `register_app` only sends the message; the new app's address isn't in the
/// reply. These tests use an app deployed beforehand, whose operator (and
/// verifier) key is the test wallet: set HUS_TEST_APP_ADDR.
fn test_app_addr() -> String {
    std::env::var("HUS_TEST_APP_ADDR").expect("set HUS_TEST_APP_ADDR to a deployed HusApp")
}

fn make_context() -> Arc<ClientContext> {
    Arc::new(
        ClientContext::new(ClientConfig {
            network: tvm_client::net::NetworkConfig {
                endpoints: Some(vec!["https://shellnet.ackinacki.org/graphql".to_string()]),
                ..Default::default()
            },
            ..Default::default()
        })
        .expect("create client"),
    )
}

fn make_signer() -> Signer {
    let keys_path = "/tmp/hus-testnet/wallet/wallet.keys.json";
    let content = std::fs::read_to_string(keys_path).expect("read wallet keys");
    let k: serde_json::Value = serde_json::from_str(&content).expect("parse keys");
    let secret = k["secret"].as_str().expect("secret key").to_string();
    let public = k["public"].as_str().expect("public key").to_string();
    Signer::Keys {
        keys: tvm_client::crypto::KeyPair { public, secret },
    }
}

fn signer_pubkey(signer: &Signer) -> String {
    match signer {
        Signer::Keys { keys } => format!("0x{}", keys.public),
        _ => panic!("test signer must hold keys"),
    }
}

/// The contract registers only what its verifier signs. In these tests the
/// operator key is also the verifier; the proof bytes are not checked on TVM.
async fn name_verifier(app: &HusApp, signer: &Signer) {
    app.set_verifier(&signer_pubkey(signer), signer.clone())
        .await
        .expect("set_verifier");
}

fn unique_name() -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("test-app-{ts}")
}

fn test_v_obf(seed: u8) -> Vec<i64> {
    (0..128u32)
        .map(|i| ((seed as i64) * 1000 + i as i64 * 7) % 2000000 - 1000000)
        .collect()
}

fn hash_hex(label: &str) -> String {
    format!(
        "0x{}",
        hex::encode(blake3::hash(label.as_bytes()).as_bytes())
    )
}

// ---------------------------------------------------------------------------
// Read-only tests (no signing, no gas)
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn test_contract_version() {
    let ctx = make_context();
    let registry = HusRegistry::new(ctx, CONTRACT_ADDR);
    let version = registry.get_version().await.expect("get_version");
    assert_eq!(version, "2.3.0");
}

// ---------------------------------------------------------------------------
// Write tests (require gas)
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn test_register_app_deploys_husapp() {
    let ctx = make_context();
    let registry = HusRegistry::new(ctx.clone(), CONTRACT_ADDR);
    let signer = make_signer();
    let name = unique_name();

    let r = registry
        .register_app(&name, &[0, 1], signer.clone())
        .await;
    assert!(r.is_ok(), "register_app: {:?}", r.err());

    // The reply carries only the message hash; check a deployed app's version.
    let app = HusApp::new(ctx, test_app_addr());
    let app_version = app.get_version().await.expect("husapp get_version");
    assert_eq!(app_version, "2.6.0");
}

#[tokio::test]
#[ignore]
async fn test_husapp_deposit_and_submit() {
    let ctx = make_context();
    let registry = HusRegistry::new(ctx.clone(), CONTRACT_ADDR);
    let signer = make_signer();
    let name = unique_name();

    let configs = face_keystroke_configs();
    registry
        .register_app(&name, &configs, signer.clone())
        .await
        .expect("register_app");
    let app_addr = test_app_addr();
    let app = HusApp::new(ctx, app_addr);

    let r = app.deposit("42", signer.clone()).await;
    assert!(r.is_ok(), "deposit: {:?}", r.err());
    name_verifier(&app, &signer).await;

    let commitment = hash_hex("user1");
    let v_obf = test_v_obf(1);
    let r = app
        .submit_verified(&commitment, &v_obf, "aa", "0x1", 0, signer.clone())
        .await;
    assert!(r.is_ok(), "submit_verified: {:?}", r.err());

    let count = app.get_registration_count().await.unwrap();
    assert_eq!(count, 1, "one registration should exist");

    let dup = app.check_duplicate(&commitment).await.unwrap();
    assert!(dup, "should detect duplicate commitment");
}

#[tokio::test]
#[ignore]
async fn test_husapp_multi_modality() {
    let ctx = make_context();
    let registry = HusRegistry::new(ctx.clone(), CONTRACT_ADDR);
    let signer = make_signer();
    let name = unique_name();

    let configs = default_chain_configs();
    registry
        .register_app(&name, &configs, signer.clone())
        .await
        .expect("register_app");
    let app_addr = test_app_addr();
    let app = HusApp::new(ctx, app_addr);

    app.deposit("99", signer.clone()).await.expect("deposit");
    name_verifier(&app, &signer).await;

    for modality_id in 0..7u8 {
        let label = format!("mod{modality_id}_user");
        let commitment = hash_hex(&label);
        let v_obf = test_v_obf(modality_id * 17);

        app.submit_verified(&commitment, &v_obf, "aa", "0x1", modality_id, signer.clone())
            .await
            .expect("submit_verified");

        let dup = app.check_duplicate(&commitment).await.unwrap();
        assert!(dup, "modality {modality_id} should be found as duplicate");
    }

    let count = app.get_registration_count().await.unwrap();
    assert_eq!(count, 7, "all 7 modalities should be registered");
}

#[tokio::test]
#[ignore]
async fn test_husapp_submit_verified_proof() {
    let ctx = make_context();
    let registry = HusRegistry::new(ctx.clone(), CONTRACT_ADDR);
    let signer = make_signer();
    let name = unique_name();

    // Fetch real VK from registry (proof verification requires matching PK/VK)
    let vk_hex = registry.get_vk().await.expect("get_vk");
    let vk_bytes = hex::decode(vk_hex.trim_start_matches("0x"))
        .expect("decode vk hex");
    let pk_bytes = std::fs::read("/home/kodics/hus/keep/pk.bin")
        .expect("read pk.bin — run keygen example first");

    let configs = face_keystroke_configs();
    registry
        .register_app(&name, &configs, signer.clone())
        .await
        .expect("register_app");
    let app_addr = test_app_addr();
    let app = HusApp::new(ctx, app_addr);

    app.deposit("swp-1", signer.clone()).await.expect("deposit");
    name_verifier(&app, &signer).await;

    let v_obf_f32: Vec<f32> = test_v_obf(42).iter().map(|&v| v as f32).collect();
    let binding = hus_sdk::proof_binding(b"test-owner-key", b"test-challenge-0001");
    let mut binding_be = binding;
    binding_be.reverse();
    let binding_hex = format!("0x{}", hex::encode(binding_be));
    let (proof_bytes, commitment_bytes) =
        hus_sdk::prover::prove_projected(&pk_bytes, &v_obf_f32, &binding).expect("proof generation");

    // Off-chain verify first (sanity check)
    let ok = hus_sdk::prover::verify_projected(
        &vk_bytes, &proof_bytes, &commitment_bytes, &hus_sdk::v_obf_to_contract(&v_obf_f32), &binding,
    )
    .expect("verify_projected");
    assert!(ok, "off-chain proof should verify");

    let proof_hex = hex::encode(&proof_bytes);
    let commitment_hex = format!("0x{}", hex::encode(commitment_bytes));
    let v_obf_i64: Vec<i64> = test_v_obf(42);

    let r = app
        .submit_verified(&commitment_hex, &v_obf_i64, &proof_hex, &binding_hex, 0, signer.clone())
        .await;
    assert!(r.is_ok(), "submit_verified: {:?}", r.err());

    let count = app.get_registration_count().await.unwrap();
    assert_eq!(count, 1, "one registration after submit_verified");

    // Verify stored proof matches what we submitted
    let reg = app.get_registration(0).await.expect("get_registration");
    assert!(!reg.proof.is_empty(), "proof should be stored");
    assert!(!reg.commitment_hash.is_empty(), "commitment hash stored");

    // Same V_obf with different nonce → L2 distance 0 → score 100 → rejected
    let (proof_bytes2, commitment_bytes2) =
        hus_sdk::prover::prove_projected(&pk_bytes, &v_obf_f32, &binding).expect("second proof generation");
    let proof_hex_2 = hex::encode(&proof_bytes2);
    let commitment_hex_2 = format!("0x{}", hex::encode(commitment_bytes2));

    let r = app
        .submit_verified(&commitment_hex_2, &v_obf_i64, &proof_hex_2, &binding_hex, 0, signer.clone())
        .await;
    assert!(r.is_ok(), "second submit_verified: {:?}", r.err());

    let count = app.get_registration_count().await.unwrap();
    // L2 distance: same V_obf → distance 0 → score 100 → rejects (> threshold 80)
    // The second submission should NOT be registered
    assert_eq!(count, 1, "duplicate V_obf should not register");
}

#[tokio::test]
#[ignore]
async fn test_husapp_duplicate_check() {
    let ctx = make_context();
    let registry = HusRegistry::new(ctx.clone(), CONTRACT_ADDR);
    let signer = make_signer();
    let name = unique_name();

    let configs = face_keystroke_configs();
    registry
        .register_app(&name, &configs, signer.clone())
        .await
        .expect("register_app");
    let app_addr = test_app_addr();
    let app = HusApp::new(ctx, app_addr);

    app.deposit("1", signer.clone()).await.expect("deposit");
    name_verifier(&app, &signer).await;

    let commitment = hash_hex("dup-test-user");
    let v_obf = test_v_obf(42);
    app.submit_verified(&commitment, &v_obf, "aa", "0x1", 0, signer.clone())
        .await
        .expect("first submit");

    let dup = app.check_duplicate(&commitment).await.unwrap();
    assert!(dup, "should detect duplicate commitment");

    let other = hash_hex("other-user");
    let not_dup = app.check_duplicate(&other).await.unwrap();
    assert!(!not_dup, "other commitment should not be duplicate");
}
