/// End-to-end example: generate a Groth16 proof bound to an owner key and a
/// challenge, verify it off-chain, then register it on HusApp with
/// submitVerified, signed by the app's verifier key.
///
/// NOTE: `gosh.vergrth16` (on-chain Groth16 verification) uses built-in VKs
/// for ZkLogin, not custom circuit VKs. So the verifier checks the proof
/// off-chain and the contract stores it with the vector for anyone to
/// re-check. A proof that fails verification is never submitted.
///
/// Requires an already-deployed HusApp with modality configs whose verifier
/// (`setVerifier`) is the key in <keys_json>.
///
/// Usage:
///   cargo run --example verify_and_submit -p hus-onchain -- \
///     <endpoint> <keys_json> <husapp_addr> <modality_id>
use std::sync::Arc;

use std::time::SystemTime;

use hus_onchain::HusApp;
use hus_sdk::prover::{prove_projected, verify_projected};
use tvm_client::abi::Signer;
use tvm_client::ClientConfig;
use tvm_client::ClientContext;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let endpoint = args.get(1).map(|s| s.as_str())
        .unwrap_or("https://shellnet.ackinacki.org/graphql");
    let keys_path = args.get(2).map(|s| s.as_str())
        .unwrap_or("/tmp/hus-testnet/wallet/wallet.keys.json");
    let husapp_addr = args.get(3).map(|s| s.as_str())
        .unwrap_or("");
    let modality_id: u8 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);

    let ctx = Arc::new(ClientContext::new(ClientConfig {
        network: tvm_client::net::NetworkConfig {
            endpoints: Some(vec![endpoint.to_string()]),
            ..Default::default()
        },
        ..Default::default()
    })?);

    let keys_content = std::fs::read_to_string(keys_path)?;
    let k: serde_json::Value = serde_json::from_str(&keys_content)?;
    let signer = Signer::Keys {
        keys: tvm_client::crypto::KeyPair {
            public: k["public"].as_str().unwrap_or("").to_string(),
            secret: k["secret"].as_str().unwrap_or("").to_string(),
        },
    };

    let app = HusApp::new(ctx.clone(), husapp_addr);

    // Generate a mock V_obf (in production this comes from BioHashing)
    // Must use 128-dim for circuit (MAX_PROJ_DIM), matches modality 0 (projDim=128)
    let seed = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().subsec_nanos();
    let v_obf: Vec<f32> = (0..128).map(|i| (i as f32 + seed as f32 * 0.001) % 10.0).collect();

    // Generate a Groth16 proof
    // In production, use the proving key fetched from chain or from a file
    let pk_path = "keep/pk.bin";
    let pk = std::fs::read(pk_path)
        .map_err(|e| format!("read PK file {pk_path}: {e}"))?;

    println!("PK size: {} bytes", pk.len());
    println!("Generating proof...");

    // In production the verifier issues a fresh challenge per attempt, and the
    // owner key is the key that will control the account.
    let mut challenge = [0u8; 32];
    getrandom::getrandom(&mut challenge).map_err(|e| format!("challenge: {e}"))?;
    let owner_pubkey = hex::decode(k["public"].as_str().unwrap_or("")).unwrap_or_default();
    let binding = hus_sdk::proof_binding(&owner_pubkey, &challenge);

    let (proof_bytes, commitment) =
        prove_projected(&pk, &v_obf, &binding).map_err(|e| format!("prove: {e}"))?;

    println!("Proof: {} bytes (compressed)", proof_bytes.len());
    println!("Commitment: 0x{}", hex::encode(&commitment));

    // Verify proof off-chain (Groth16 verification using the VK)
    let vk_path = "keep/vk.hex";
    let vk_hex = std::fs::read_to_string(vk_path)
        .map_err(|e| format!("read VK file {vk_path}: {e}"))?;
    let vk_bytes = hex::decode(vk_hex.trim())
        .map_err(|e| format!("decode VK hex: {e}"))?;

    println!("VK: {} bytes, Proof: {} bytes, Commitment: {} bytes",
        vk_bytes.len(), proof_bytes.len(), commitment.len());

    // Off-chain verification. Never submit a proof that doesn't verify.
    let v_obf_scaled = hus_sdk::v_obf_to_contract(&v_obf);
    if !verify_projected(&vk_bytes, &proof_bytes, &commitment, &v_obf_scaled, &binding)
        .map_err(|e| format!("verify: {e}"))?
    {
        return Err("proof did not verify; not submitting".into());
    }
    println!("Off-chain proof verification: passed");

    let mut binding_be = binding;
    binding_be.reverse();
    println!("Submitting to HusApp via submitVerified: {husapp_addr}");
    let output = app
        .submit_verified(
            &format!("0x{}", hex::encode(commitment)),
            &v_obf_scaled,
            &hex::encode(&proof_bytes),
            &format!("0x{}", hex::encode(binding_be)),
            modality_id,
            signer,
        )
        .await
        .map_err(|e| format!("submit: {e}"))?;

    println!("Result: isUnique={}, score={}", output["isUnique"], output["score"]);
    Ok(())
}
