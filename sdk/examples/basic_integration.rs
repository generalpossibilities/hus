/// Basic integration example — uniqueness oracle pipeline with BioHashing.
///
/// HUS does NOT authenticate users. It answers one question:
/// "Has this biometric appeared before on this app?"
///
/// Liveness is mandatory for every modality before projection.
/// Apps must select 2+ of 7 modalities for their users.
///
/// Run: cargo run --example basic_integration -p hus-sdk
use ark_bn254::{Bn254, Fr};
use ark_ff::Field;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use hus_sdk::capture::{Capture, MockCapture};
use hus_sdk::circuit::r1cs::HusCircuit;
use hus_sdk::extract::get_extractor;
use hus_sdk::projection::derive_and_project;
use hus_sdk::prover::prove_projected;
use hus_sdk::{HusClient, Modality, ModalityProof, ModalitySelection};

fn seed_fn(m: Modality) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = m as u8;
    s
}

fn main() {
    println!("=== HUS Uniqueness Oracle Example (BioHashing) ===\n");

    // Step 1: App selects 2+ modalities (7 available: Face, Iris, Voice,
    //          Fingerprint, Keystroke, TouchGesture, Gait)
    let selection = ModalitySelection::new(vec![
        Modality::Keystroke,
        Modality::TouchGesture,
        Modality::Gait,
    ])
    .expect("need 2+ modalities");

    let configs = selection.configs().to_vec();
    for cfg in &configs {
        println!(
            "[1] Modality: {:12}  raw_dim={:4}  proj_dim={:3}  threshold={:.1}",
            cfg.modality.name(),
            cfg.raw_dim,
            cfg.proj_dim,
            cfg.threshold,
        );
    }

    // Step 2: Generate proving & verifying keys (once per deployment)
    let (pk, _vk) = generate_test_keys();
    println!("[2] Proving key generated (k=12)");

    // Step 3: Create client with mandatory liveness seed
    let client = HusClient::new(
        "app_alpha_dao_2026".into(),
        selection,
        [0x42u8; 32], // liveness seed
    );
    println!(
        "[3] Client initialized: {} modalities",
        client.modalities().len()
    );

    // Step 4: Per-modality liveness (MANDATORY — enforced by HusClient)
    let mut liveness_results = Vec::new();
    for cfg in &configs {
        let mut session = client.create_liveness_session(cfg.modality);
        println!(
            "[4] Liveness ({:12}): {} challenges",
            cfg.modality.name(),
            session.challenge_count()
        );
        let mut capturer = MockCapture::new(cfg.modality);
        let raw = capturer.capture().expect("capture failed");
        for i in 0..session.challenge_count() {
            session.verify_response(i, &raw).expect("verify failed");
        }
        let result = session.finalize();
        println!(
            "     Score: {}/100 — {}",
            result.score,
            if result.passed { "PASSED" } else { "FAILED" }
        );
        liveness_results.push(result);
    }
    client
        .require_all_liveness(&liveness_results)
        .expect("liveness failed for one or more modalities");

    // Step 5: Capture + extraction
    let mut embeddings = std::collections::BTreeMap::new();
    let mut passed_flags = Vec::new();

    for cfg in &configs {
        let mut capturer = MockCapture::new(cfg.modality);
        let raw = capturer.capture().expect("capture failed");
        let extractor = get_extractor(cfg.modality).expect("extractor");
        let embedding = extractor.extract(&raw).expect("extraction failed");
        println!(
            "[5] {:12}: embedding {} dims",
            cfg.modality.name(),
            embedding.vector.len()
        );
        embeddings.insert(cfg.modality, embedding.vector);
        passed_flags.push(true);
    }

    // Step 6: Quality gate — check enough modalities passed
    let gate = client.check_quality_gate(&passed_flags);
    println!("\n=== Quality Gate ===");
    println!(
        "  Passed: {}/{} — {}",
        gate.passed_count,
        gate.required_count,
        if gate.all_passed {
            "OK"
        } else {
            "INSUFFICIENT"
        }
    );
    if !gate.all_passed {
        return;
    }

    // Step 7: BioHashing projection + Groth16 proof per modality
    let mut proofs: Vec<ModalityProof> = Vec::new();
    for cfg in &configs {
        let embedding = &embeddings[&cfg.modality];
        let seed = seed_fn(cfg.modality);
        let v_obf = derive_and_project(&seed, embedding, cfg.proj_dim).unwrap();
        let (proof_bytes, commitment_hash) = prove_projected(&pk, &v_obf).expect("prove_projected");

        let comm_hex: String = commitment_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        println!(
            "\n[7] {:12}: v_obf={:3} dims, proof={:4} bytes, commitment=0x{}",
            cfg.modality.name(),
            v_obf.len(),
            proof_bytes.len(),
            comm_hex,
        );
        proofs.push(ModalityProof {
            modality: cfg.modality,
            proof_bytes,
            commitment_hash,
            v_obf,
        });
    }

    // Step 8: On-chain duplicate check + submit (simulated)
    println!("\n=== On-Chain Registry ===");
    for mp in &proofs {
        let comm_hex: String = mp
            .commitment_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        println!(
            "  {:12}: commitment=0x{}  v_obf_dims={}",
            mp.modality.name(),
            comm_hex,
            mp.v_obf.len(),
        );
    }
    println!("\n  ✅ All commitments would be submitted on-chain");
    println!("\n=== Uniqueness oracle complete ===");
}

fn generate_test_keys() -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::rngs::OsRng;
    let circuit = HusCircuit {
        v_obf: vec![Fr::ZERO; 128],
        nonce: Fr::ZERO,
        commitment: Fr::ZERO,
    };
    let pk =
        Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng).unwrap();
    let vk = pk.vk.clone();
    let mut pk_bytes = Vec::new();
    pk.serialize_uncompressed(&mut pk_bytes).unwrap();
    let mut vk_bytes = Vec::new();
    vk.serialize_uncompressed(&mut vk_bytes).unwrap();
    println!("  PK size: {} bytes", pk_bytes.len());
    println!("  VK size: {} bytes", vk_bytes.len());
    (pk_bytes, vk_bytes)
}
