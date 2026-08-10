use alloc::vec::Vec;
use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::circuit::poseidon::PoseidonConfig;
use crate::circuit::r1cs::HusCircuit;
use crate::circuit::r1cs::MAX_PROJ_DIM;
use crate::error::SdkError;
use crate::metrics::HUS_METRICS;

type G16 = Groth16<Bn254>;

/// Generate a Groth16 proof: Poseidon(v_obf || nonce) == commitment
///
/// Returns (proof_bytes, commitment_hash).
pub fn prove_projected(pk: &[u8], v_obf: &[f32]) -> Result<(Vec<u8>, [u8; 32]), SdkError> {
    #[cfg(feature = "std")]
    let start = std::time::Instant::now();

    let pk =
        ProvingKey::<Bn254>::deserialize_uncompressed(pk).map_err(|_| SdkError::CryptoError {
            reason: "PK deserialize failed",
        })?;

    let mut padded = v_obf.to_vec();
    padded.resize(MAX_PROJ_DIM, 0.0f32);
    let v_obf_frs: Vec<Fr> = padded
        .iter()
        .map(|v| Fr::from(v.to_bits() as u64))
        .collect();

    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).map_err(|_| SdkError::CryptoError {
        reason: "nonce generation failed",
    })?;
    let nonce = Fr::from_be_bytes_mod_order(&buf);

    let mut preimage = v_obf_frs.clone();
    preimage.push(nonce);
    let config = PoseidonConfig::new();
    let commitment_fp = config.hash_native(&preimage);
    let commitment_bytes = serialize_fr(commitment_fp);

    let circuit = HusCircuit {
        v_obf: v_obf_frs,
        nonce,
        commitment: commitment_fp,
    };

    let mut rng = rand::rngs::OsRng;
    let proof = G16::create_random_proof_with_reduction(circuit, &pk, &mut rng).map_err(|_| {
        SdkError::CryptoError {
            reason: "Groth16 proof creation failed",
        }
    })?;

    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|_| SdkError::CryptoError {
            reason: "proof serialize failed",
        })?;

    HUS_METRICS
        .proofs_generated
        .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    #[cfg(feature = "std")]
    HUS_METRICS.last_proof_time_us.store(
        start.elapsed().as_micros() as u64,
        core::sync::atomic::Ordering::Relaxed,
    );

    Ok((proof_bytes, commitment_bytes))
}

/// Off-chain verification of a Groth16 proof.
///
/// Public input: commitment only (v_obf is private witness).
pub fn verify_projected(
    vk: &[u8],
    proof: &[u8],
    commitment: &[u8; 32],
    _v_obf: &[f32],
) -> Result<bool, SdkError> {
    HUS_METRICS
        .proofs_verified
        .fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    let vk =
        VerifyingKey::<Bn254>::deserialize_uncompressed(vk).map_err(|_| SdkError::CryptoError {
            reason: "VK deserialize failed",
        })?;
    let pvk = prepare_verifying_key(&vk);

    let proof =
        Proof::<Bn254>::deserialize_compressed(proof).map_err(|_| SdkError::CryptoError {
            reason: "proof deserialize failed",
        })?;

    let public_comm = Fr::deserialize_uncompressed(&commitment[..])
        .map_err(|_| SdkError::CryptoError {
            reason: "commitment deserialize failed",
        })?;

    // Only commitment is a public input
    let public_inputs = core::iter::once(public_comm).collect::<alloc::vec::Vec<_>>();

    let result =
        G16::verify_proof(&pvk, &proof, &public_inputs).map_err(|_| SdkError::CryptoError {
            reason: "proof verification failed",
        })?;

    if !result {
        HUS_METRICS
            .proofs_failed
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    Ok(result)
}

fn serialize_fr(fe: Fr) -> [u8; 32] {
    let mut buf = Vec::new();
    fe.serialize_uncompressed(&mut buf).ok();
    let mut arr = [0u8; 32];
    arr[..buf.len()].copy_from_slice(&buf);
    arr
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::poseidon::PoseidonConfig;
    use crate::circuit::r1cs::HusCircuit;
    use ark_bn254::{G1Projective, G2Projective};
    use ark_ff::{Field, UniformRand};
    use ark_groth16::r1cs_to_qap::LibsnarkReduction;

    fn gen_keys_direct(
        n: usize,
        rng: &mut impl rand::RngCore,
    ) -> (ProvingKey<Bn254>, VerifyingKey<Bn254>) {
        let alpha = Fr::rand(rng);
        let beta = Fr::rand(rng);
        let gamma = Fr::rand(rng);
        let delta = Fr::rand(rng);
        let g1 = G1Projective::rand(rng);
        let g2 = G2Projective::rand(rng);
        let pk = Groth16::<Bn254, LibsnarkReduction>::generate_parameters_with_qap(
            HusCircuit {
                v_obf: vec![Fr::ZERO; n],
                nonce: Fr::ZERO,
                commitment: Fr::ZERO,
            },
            alpha,
            beta,
            gamma,
            delta,
            g1,
            g2,
            rng,
        )
        .unwrap();
        let vk = pk.vk.clone();
        (pk, vk)
    }

    fn run_roundtrip(
        v_obf_input: &[f32],
        wrong_comm: Option<[u8; 32]>,
    ) -> bool {
        let mut rng = rand::rngs::OsRng;
        let n = v_obf_input.len();
        let (pk, vk) = gen_keys_direct(n, &mut rng);

        let v_obf_frs: Vec<Fr> = v_obf_input
            .iter()
            .map(|v| Fr::from(v.to_bits() as u64))
            .collect();
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf).unwrap();
        let nonce = Fr::from_be_bytes_mod_order(&buf);
        let commitment =
            PoseidonConfig::new().hash_native(&[v_obf_frs.clone(), vec![nonce]].concat());

        let proof = G16::create_random_proof_with_reduction(
            HusCircuit {
                v_obf: v_obf_frs.clone(),
                nonce,
                commitment,
            },
            &pk,
            &mut rng,
        )
        .unwrap();

        // Only commitment is public input (v_obf is now private witness)
        let verify_comm = wrong_comm
            .map(|c| Fr::from_be_bytes_mod_order(&c))
            .unwrap_or(commitment);

        let pvk = prepare_verifying_key(&vk);
        let pub_inputs = vec![verify_comm];
        G16::verify_proof(&pvk, &proof, &pub_inputs).unwrap_or(false)
    }

    #[test]
    fn groth16_satisfiable() {
        assert!(run_roundtrip(&[0.5f32; 2], None));
    }

    #[test]
    fn wrong_commitment_rejected() {
        assert!(!run_roundtrip(&[0.5f32; 2], Some([0x99u8; 32])));
    }

    #[test]
    fn different_nonces_produce_different_commitments() {
        let mut rng = rand::rngs::OsRng;
        let v_obf: Vec<f32> = vec![0.5f32; 2];
        let v_obf_frs: Vec<Fr> = v_obf.iter().map(|v| Fr::from(v.to_bits() as u64)).collect();
        let nonce1 = Fr::rand(&mut rng);
        let nonce2 = Fr::rand(&mut rng);
        assert_ne!(nonce1, nonce2, "nonces must differ");
        let config = PoseidonConfig::new();
        let c1 = config.hash_native(&[v_obf_frs.clone(), vec![nonce1]].concat());
        let c2 = config.hash_native(&[v_obf_frs, vec![nonce2]].concat());
        assert_ne!(
            serialize_fr(c1),
            serialize_fr(c2),
            "different nonces must produce different commitments"
        );
    }
}
