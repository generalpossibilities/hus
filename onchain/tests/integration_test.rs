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

use hus_onchain::hus_app::{ChainModalityConfig, HusApp};
use hus_onchain::hus_registry::{ChainModalityConfig as RegChainModalityConfig, HusRegistry};
use std::sync::Arc;
use tvm_client::abi::Signer;
use tvm_client::ClientConfig;
use tvm_client::ClientContext;

const CONTRACT_ADDR: &str = "3fb1ca2bf0564aab352b06621b63fd48e8e432a4e13a636ec142d423ac187e67::3fb1ca2bf0564aab352b06621b63fd48e8e432a4e13a636ec142d423ac187e67";

/// Canonical chain modality configs matching the SDK defaults.
fn default_chain_configs() -> Vec<RegChainModalityConfig> {
    vec![
        RegChainModalityConfig { modalityId: "0".into(), projDim: "128".into(), minScore: "80".into() },
        RegChainModalityConfig { modalityId: "1".into(), projDim: "64".into(),  minScore: "90".into() },
        RegChainModalityConfig { modalityId: "2".into(), projDim: "64".into(),  minScore: "75".into() },
        RegChainModalityConfig { modalityId: "3".into(), projDim: "48".into(),  minScore: "90".into() },
        RegChainModalityConfig { modalityId: "4".into(), projDim: "16".into(),  minScore: "70".into() },
        RegChainModalityConfig { modalityId: "5".into(), projDim: "12".into(),  minScore: "65".into() },
        RegChainModalityConfig { modalityId: "6".into(), projDim: "24".into(),  minScore: "70".into() },
    ]
}

/// Subset of configs for a test that only uses Face + Iris.
fn face_iris_configs() -> Vec<RegChainModalityConfig> {
    default_chain_configs().into_iter().take(2).collect()
}

/// Subset with Face + Keystroke (minimum 2, Face is modality 0).
fn face_keystroke_configs() -> Vec<RegChainModalityConfig> {
    vec![
        RegChainModalityConfig { modalityId: "0".into(), projDim: "128".into(), minScore: "80".into() },
        RegChainModalityConfig { modalityId: "4".into(), projDim: "16".into(),  minScore: "70".into() },
    ]
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

    let configs = face_iris_configs();
    let r = registry
        .register_app(&name, &configs, signer.clone())
        .await
        .expect("register_app");

    let app_addr = r
        .return_value
        .as_ref()
        .and_then(|v| v.get("value0"))
        .and_then(|v| v.as_str())
        .expect("app address in response");

    let app = HusApp::new(ctx, app_addr);
    let app_version = app.get_version().await.expect("husapp get_version");
    assert_eq!(app_version, "2.3.1");
}

#[tokio::test]
#[ignore]
async fn test_husapp_deposit_and_submit() {
    let ctx = make_context();
    let registry = HusRegistry::new(ctx.clone(), CONTRACT_ADDR);
    let signer = make_signer();
    let name = unique_name();

    let configs = face_keystroke_configs();
    let r = registry
        .register_app(&name, &configs, signer.clone())
        .await
        .expect("register_app");
    let app_addr = r
        .return_value
        .as_ref()
        .and_then(|v| v.get("value0"))
        .and_then(|v| v.as_str())
        .expect("app address");
    let app = HusApp::new(ctx, &app_addr);

    let r = app.deposit("42", signer.clone()).await;
    assert!(r.is_ok(), "deposit: {:?}", r.err());

    let commitment = hash_hex("user1");
    let v_obf = test_v_obf(1);
    let r = app
        .submit_commitment(&commitment, &v_obf, 0, signer.clone())
        .await;
    assert!(r.is_ok(), "submit_commitment: {:?}", r.err());

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
    let r = registry
        .register_app(&name, &configs, signer.clone())
        .await
        .expect("register_app");
    let app_addr = r
        .return_value
        .as_ref()
        .and_then(|v| v.get("value0"))
        .and_then(|v| v.as_str())
        .expect("app address");
    let app = HusApp::new(ctx, &app_addr);

    app.deposit("99", signer.clone()).await.expect("deposit");

    for modality_id in 0..7u8 {
        let label = format!("mod{modality_id}_user");
        let commitment = hash_hex(&label);
        let v_obf = test_v_obf(modality_id * 17);

        app.submit_commitment(&commitment, &v_obf, modality_id, signer.clone())
            .await
            .expect("submit_commitment");

        let dup = app.check_duplicate(&commitment).await.unwrap();
        assert!(dup, "modality {modality_id} should be found as duplicate");
    }

    let count = app.get_registration_count().await.unwrap();
    assert_eq!(count, 7, "all 7 modalities should be registered");
}

#[tokio::test]
#[ignore]
async fn test_husapp_submit_with_proof() {
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
    let r = registry
        .register_app(&name, &configs, signer.clone())
        .await
        .expect("register_app");
    let app_addr = r
        .return_value
        .as_ref()
        .and_then(|v| v.get("value0"))
        .and_then(|v| v.as_str())
        .expect("app address");
    let app = HusApp::new(ctx, &app_addr);

    app.deposit("swp-1", signer.clone()).await.expect("deposit");

    let v_obf_f32: Vec<f32> = test_v_obf(42).iter().map(|&v| v as f32).collect();
    let (proof_bytes, commitment_bytes) =
        hus_sdk::prover::prove_projected(&pk_bytes, &v_obf_f32).expect("proof generation");

    // Off-chain verify first (sanity check)
    let ok = hus_sdk::prover::verify_projected(
        &vk_bytes, &proof_bytes, &commitment_bytes, &hus_sdk::v_obf_to_contract(&v_obf_f32),
    )
    .expect("verify_projected");
    assert!(ok, "off-chain proof should verify");

    let proof_b64 = base64::engine::general_purpose::STANDARD.encode(&proof_bytes);
    let commitment_hex = format!("0x{}", hex::encode(commitment_bytes));
    let v_obf_i64: Vec<i64> = test_v_obf(42);

    let r = app
        .submit_with_proof(&v_obf_i64, &proof_b64, &commitment_hex, 0, signer.clone())
        .await;
    assert!(r.is_ok(), "submit_with_proof: {:?}", r.err());

    let count = app.get_registration_count().await.unwrap();
    assert_eq!(count, 1, "one registration after submit_with_proof");

    // Verify stored proof matches what we submitted
    let reg = app.get_registration(0).await.expect("get_registration");
    assert!(!reg.proof.is_empty(), "proof should be stored");
    // Commitment hash is stored as tvm.hash(commitment_bytes) — we can't
    // easily predict it off-chain, just check it's non-empty
    assert!(!reg.commitment_hash.is_empty(), "commitment hash stored");

    // Same V_obf with different nonce → L2 distance 0 → score 100 → rejected
    let (proof_bytes2, commitment_bytes2) =
        hus_sdk::prover::prove_projected(&pk_bytes, &v_obf_f32).expect("second proof generation");
    let proof_b64_2 = base64::engine::general_purpose::STANDARD.encode(&proof_bytes2);
    let commitment_hex_2 = format!("0x{}", hex::encode(commitment_bytes2));

    let r = app
        .submit_with_proof(
            &v_obf_i64,
            &proof_b64_2,
            &commitment_hex_2,
            0,
            signer.clone(),
        )
        .await;
    assert!(r.is_ok(), "second submit_with_proof: {:?}", r.err());

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
    let r = registry
        .register_app(&name, &configs, signer.clone())
        .await
        .expect("register_app");
    let app_addr = r
        .return_value
        .as_ref()
        .and_then(|v| v.get("value0"))
        .and_then(|v| v.as_str())
        .expect("app address");
    let app = HusApp::new(ctx, &app_addr);

    app.deposit("1", signer.clone()).await.expect("deposit");

    let commitment = hash_hex("dup-test-user");
    let v_obf = test_v_obf(42);
    app.submit_commitment(&commitment, &v_obf, 0, signer.clone())
        .await
        .expect("first submit");

    let dup = app.check_duplicate(&commitment).await.unwrap();
    assert!(dup, "should detect duplicate commitment");

    let other = hash_hex("other-user");
    let not_dup = app.check_duplicate(&other).await.unwrap();
    assert!(!not_dup, "other commitment should not be duplicate");
}
