//! End-to-end test: capture → extract → project → prove → verify.
//! Uses only the SDK; no network or contract mock needed.
//!
//! Full-circuit (128 v_obf) keygen is slow (~38K constraints).
//! These tests use a small circuit (2 v_obf) for fast keygen, then
//! prove/verify without the prover padding (which expects 128 elements).

use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_groth16::{prepare_verifying_key, Groth16, ProvingKey, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use hus_sdk::capture::{Capture, MockCapture};
use hus_sdk::circuit::poseidon::PoseidonConfig;
use hus_sdk::circuit::r1cs::HusCircuit;
use hus_sdk::config::Modality;
use hus_sdk::projection::derive_and_project;
use hus_sdk::prover::{prove_projected, verify_projected};

/// Generate a proving key + verifying key for a SMALL circuit (2-element v_obf).
/// Full 128-element keygen is too slow for CI testing.
fn gen_keys() -> (ProvingKey<Bn254>, VerifyingKey<Bn254>) {
    let mut rng = rand::rngs::OsRng;
    let alpha = Fr::rand(&mut rng);
    let beta = Fr::rand(&mut rng);
    let gamma = Fr::rand(&mut rng);
    let delta = Fr::rand(&mut rng);
    let g1 = G1Projective::rand(&mut rng);
    let g2 = G2Projective::rand(&mut rng);
    let pk = Groth16::<Bn254, LibsnarkReduction>::generate_parameters_with_qap(
        HusCircuit {
            v_obf: vec![Fr::ZERO; 2],
            nonce: Fr::ZERO,
            commitment: Fr::ZERO,
        },
        alpha,
        beta,
        gamma,
        delta,
        g1,
        g2,
        &mut rng,
    )
    .unwrap();
    (pk.clone(), pk.vk.clone())
}

fn seed_fn(m: Modality) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = m as u8;
    s
}

/// End-to-end test using a SMALL circuit (2-element v_obf).
/// Proves and verifies within the same circuit size.
#[test]
fn full_pipeline_small_circuit() {
    let mut rng = rand::rngs::OsRng;
    let (pk, vk) = gen_keys();

    let mut mock = MockCapture::new(Modality::Keystroke);
    let raw = mock.capture().unwrap();
    let extractor = hus_sdk::extract::get_extractor(Modality::Keystroke).unwrap();
    let embedding = extractor.extract(&raw).unwrap();

    let seed = seed_fn(Modality::Keystroke);
    let proj_dim = 2;
    let v_obf = derive_and_project(&seed, &embedding.vector, proj_dim).unwrap();
    assert_eq!(v_obf.len(), proj_dim);

    let v_obf_frs: Vec<Fr> = v_obf.iter().map(|v| Fr::from(v.to_bits() as u64)).collect();
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).unwrap();
    let nonce = Fr::from_be_bytes_mod_order(&buf);

    let config = PoseidonConfig::new();
    let commitment = config.hash_native(&[v_obf_frs.clone(), vec![nonce]].concat());

    let prover_circuit = HusCircuit {
        v_obf: v_obf_frs.clone(),
        nonce,
        commitment,
    };
    let proof = Groth16::<Bn254, LibsnarkReduction>::create_random_proof_with_reduction(
        prover_circuit,
        &pk,
        &mut rng,
    )
    .unwrap();

    let pvk = prepare_verifying_key(&vk);
    let pub_inputs = vec![commitment];
    let valid =
        Groth16::<Bn254, LibsnarkReduction>::verify_proof(&pvk, &proof, &pub_inputs).unwrap();
    assert!(valid, "proof must verify");
}

/// Test using the SDK's prove_projected / verify_projected with a
/// full 128-element padded circuit. Keygen is slow (~38K constraints)
/// so this test is ignored by default.
#[test]
#[ignore = "full-circuit keygen is slow (~5-20 min with 38K constraints)"]
fn full_pipeline_keystroke() {
    let mut mock = MockCapture::new(Modality::Keystroke);
    let raw = mock.capture().unwrap();
    let extractor = hus_sdk::extract::get_extractor(Modality::Keystroke).unwrap();
    let embedding = extractor.extract(&raw).unwrap();

    let seed = seed_fn(Modality::Keystroke);
    let proj_dim = 16;
    let v_obf = derive_and_project(&seed, &embedding.vector, proj_dim).unwrap();

    let (pk, vk) = generate_full_test_keys();
    let (proof_bytes, commitment) = prove_projected(&pk, &v_obf).unwrap();
    assert!(!proof_bytes.is_empty());

    let valid = verify_projected(&vk, &proof_bytes, &commitment, &v_obf).unwrap();
    assert!(valid, "proof must verify");

    // v_obf_to_contract uses fixed-point ×10⁶ (canonical on-chain encoding)
    let contract_v_obf = hus_sdk::v_obf_to_contract(&v_obf);
    assert_eq!(contract_v_obf.len(), v_obf.len());
    for (i, &val) in contract_v_obf.iter().enumerate() {
        let expected = (v_obf[i] as f64 * 1_000_000.0) as i64;
        assert_eq!(val, expected, "v_obf[{i}] mismatch");
    }
}

#[test]
#[ignore = "full-circuit keygen is slow (~5-20 min with 38K constraints)"]
fn full_pipeline_multimodal() {
    let (pk, vk) = generate_full_test_keys();

    for modality in &[Modality::Keystroke, Modality::TouchGesture] {
        let mut mock = MockCapture::new(*modality);
        let raw = mock.capture().unwrap();
        let extractor = hus_sdk::extract::get_extractor(*modality).unwrap();
        let embedding = extractor.extract(&raw).unwrap();

        let seed = seed_fn(*modality);
        let cfg = hus_sdk::config::ModalityConfig::for_modality(*modality);
        let v_obf = derive_and_project(&seed, &embedding.vector, cfg.proj_dim).unwrap();

        let (proof_bytes, commitment) = prove_projected(&pk, &v_obf).unwrap();
        let valid = verify_projected(&vk, &proof_bytes, &commitment, &v_obf).unwrap();
        assert!(valid, "proof must verify for {:?}", modality);
    }
}

#[test]
fn v_obf_contract_conversion_roundtrip() {
    let v = vec![0.5f32, -1.0f32, 3.14159f32, 0.0f32, 1.0f32];
    let contract = hus_sdk::v_obf_to_contract(&v);
    assert_eq!(contract.len(), v.len());
    for (i, &val) in contract.iter().enumerate() {
        let expected = (v[i] as f64 * 1_000_000.0) as i64;
        assert_eq!(val, expected, "v_obf[{i}] mismatch");
    }
}

fn generate_full_test_keys() -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::rngs::OsRng;
    let alpha = Fr::rand(&mut rng);
    let beta = Fr::rand(&mut rng);
    let gamma = Fr::rand(&mut rng);
    let delta = Fr::rand(&mut rng);
    let g1 = G1Projective::rand(&mut rng);
    let g2 = G2Projective::rand(&mut rng);
    let pk = Groth16::<Bn254, LibsnarkReduction>::generate_parameters_with_qap(
        HusCircuit {
            v_obf: vec![Fr::ZERO; 128],
            nonce: Fr::ZERO,
            commitment: Fr::ZERO,
        },
        alpha,
        beta,
        gamma,
        delta,
        g1,
        g2,
        &mut rng,
    )
    .unwrap();
    let vk = pk.vk.clone();
    let mut pk_bytes = Vec::new();
    pk.serialize_uncompressed(&mut pk_bytes).unwrap();
    let mut vk_bytes = Vec::new();
    vk.serialize_uncompressed(&mut vk_bytes).unwrap();
    (pk_bytes, vk_bytes)
}
