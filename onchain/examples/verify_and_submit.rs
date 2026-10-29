/// Verifier example: check one device's request (its Groth16 proof and its
/// hardware attestation), then register it on HusApp with submitVerified,
/// signed by the app's verifier key. This is what the gateway's `/submit`
/// does, without the gateway.
///
/// NOTE: `gosh.vergrth16` (on-chain Groth16 verification) uses built-in VKs
/// for ZkLogin, not custom circuit VKs, and attestations can't be checked on
/// chain at all. So the verifier checks both off-chain and the contract
/// stores the proof and the attestation hash for anyone to re-check. A
/// request that fails either check is never submitted.
///
/// The request is the JSON a device sends to the gateway's `/submit`:
/// `{app_address, commitment, v_obf, proof, modality_id, owner_pubkey,
/// challenge, attestation}`. It has to come from a real device: the
/// attestation covers this exact proof and vector.
///
/// Requires an already-deployed HusApp with modality configs whose verifier
/// (`setVerifier`) is the key in <keys_json>.
///
/// Usage:
///   cargo run --example verify_and_submit -p hus-onchain -- \
///     <endpoint> <keys_json> <request_json> <attest_policy_json> <revocation_status_json>
///
/// <revocation_status_json> is a fresh copy of
/// https://android.googleapis.com/attestation/status; its file time counts
/// as the fetch time.
use std::sync::Arc;
use std::time::SystemTime;

use hus_onchain::HusApp;
use hus_sdk::prover::verify_projected;
use tvm_client::abi::Signer;
use tvm_client::ClientConfig;
use tvm_client::ClientContext;

#[derive(serde::Deserialize)]
struct Request {
    app_address: String,
    commitment: String,
    v_obf: Vec<i64>,
    proof: String,
    modality_id: u8,
    owner_pubkey: String,
    challenge: String,
    attestation: hus_attest::Attestation,
}

fn unix(t: SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    hex::decode(s.trim_start_matches("0x"))
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| format!("{s} is not 32 bytes hex"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        return Err("usage: verify_and_submit <endpoint> <keys_json> <request_json> <attest_policy_json> <revocation_status_json>".into());
    }
    let (endpoint, keys_path, request_path, policy_path, status_path) =
        (&args[1], &args[2], &args[3], &args[4], &args[5]);

    let req: Request = serde_json::from_str(&std::fs::read_to_string(request_path)?)?;
    let policy = hus_attest::Policy::from_json(&std::fs::read_to_string(policy_path)?)?;
    let status_time = unix(std::fs::metadata(status_path)?.modified()?);
    let revocations = hus_attest::RevocationList::from_json(&std::fs::read(status_path)?, status_time)?;

    let commitment = hex32(&req.commitment)?;
    let proof_bytes = hex::decode(req.proof.trim_start_matches("0x"))?;
    let owner_pubkey = hex::decode(req.owner_pubkey.trim_start_matches("0x"))?;
    let challenge = hex::decode(req.challenge.trim_start_matches("0x"))?;
    if challenge.len() < 16 {
        return Err("challenge must be at least 16 bytes".into());
    }
    let binding = hus_sdk::proof_binding(&owner_pubkey, &challenge);

    let vk_path = "keep/vk.hex";
    let vk_hex = std::fs::read_to_string(vk_path).map_err(|e| format!("read VK file {vk_path}: {e}"))?;
    let vk_bytes = hex::decode(vk_hex.trim()).map_err(|e| format!("decode VK hex: {e}"))?;

    // 1. The proof. Never submit one that doesn't verify.
    if !verify_projected(&vk_bytes, &proof_bytes, &commitment, &req.v_obf, &binding)
        .map_err(|e| format!("verify: {e}"))?
    {
        return Err("proof did not verify; not submitting".into());
    }
    println!("Proof: verified");

    // 2. The device. Its attestation must be for exactly this request.
    let expected = hus_sdk::attestation_challenge(
        &req.app_address,
        req.modality_id,
        &commitment,
        &req.v_obf,
        &proof_bytes,
        &binding,
    );
    let verdict = hus_attest::verify(
        &req.attestation,
        &expected,
        &policy,
        &hus_attest::TrustAnchors::google(),
        &revocations,
        unix(SystemTime::now()),
    )
    .map_err(|e| format!("attestation: {e}; not submitting"))?;
    println!("Attestation: passed ({:?})", verdict.android);

    let ctx = Arc::new(ClientContext::new(ClientConfig {
        network: tvm_client::net::NetworkConfig {
            endpoints: Some(vec![endpoint.to_string()]),
            ..Default::default()
        },
        ..Default::default()
    })?);
    let k: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(keys_path)?)?;
    let signer = Signer::Keys {
        keys: tvm_client::crypto::KeyPair {
            public: k["public"].as_str().unwrap_or("").to_string(),
            secret: k["secret"].as_str().unwrap_or("").to_string(),
        },
    };
    let app = HusApp::new(ctx, &req.app_address);

    let mut binding_be = binding;
    binding_be.reverse();
    println!("Submitting to HusApp via submitVerified: {}", req.app_address);
    let output = app
        .submit_verified(
            &format!("0x{}", hex::encode(commitment)),
            &req.v_obf,
            &hex::encode(&proof_bytes),
            &format!("0x{}", hex::encode(binding_be)),
            &format!("0x{}", hex::encode(verdict.attestation_hash)),
            req.modality_id,
            signer,
        )
        .await
        .map_err(|e| format!("submit: {e}"))?;

    println!("Result: isUnique={}, score={}", output["isUnique"], output["score"]);
    println!(
        "Publish the attestation with hash {} so others can re-check it.",
        hex::encode(verdict.attestation_hash)
    );
    Ok(())
}
