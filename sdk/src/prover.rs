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
use crate::v_obf_to_contract;

type G16 = Groth16<Bn254>;

/// The circuit is defined over the *on-chain* encoding of V_obf: the
/// fixed-point i64 values (`v_obf_to_contract`), zero-padded to
/// `MAX_PROJ_DIM`. Proving and verifying must derive fields identically,
/// so the proved vector is byte-for-byte the vector the contract stores.
fn v_obf_i64_to_frs(v_obf: &[i64]) -> Vec<Fr> {
    let mut padded = alloc::vec![0i64; MAX_PROJ_DIM];
    let n = v_obf.len().min(MAX_PROJ_DIM);
    padded[..n].copy_from_slice(&v_obf[..n]);
    padded.iter().map(|v| Fr::from(*v)).collect()
}

/// Who a proof is for. The verifier issues a fresh `challenge` and knows the
/// key the account will be controlled by; both go into the proof as one
/// public input, so the same proof can't be replayed with another challenge,
/// stolen for another key, or front-run.
///
/// `H = SHA-256("hus.binding.v1" ‖ len(owner_pubkey) as u32 LE ‖ owner_pubkey ‖ challenge)`,
/// reduced into the field. Returned as the field element's canonical
/// 32-byte encoding.
pub fn proof_binding(owner_pubkey: &[u8], challenge: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"hus.binding.v1");
    h.update((owner_pubkey.len() as u32).to_le_bytes());
    h.update(owner_pubkey);
    h.update(challenge);
    serialize_fr(Fr::from_le_bytes_mod_order(&h.finalize()))
}

fn binding_fr(binding: &[u8; 32]) -> Result<Fr, SdkError> {
    Fr::deserialize_uncompressed(&binding[..]).map_err(|_| SdkError::CryptoError {
        reason: "binding deserialize failed",
    })
}

/// Generate a Groth16 proof: Poseidon(v_obf_fixed || nonce) == commitment,
/// with every `v_obf` element and the `binding` (see [`proof_binding`])
/// exposed as public inputs.
///
/// Returns (proof_bytes, commitment_hash).
pub fn prove_projected(
    pk: &[u8],
    v_obf: &[f32],
    binding: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 32]), SdkError> {
    #[cfg(feature = "std")]
    let start = std::time::Instant::now();

    let pk =
        ProvingKey::<Bn254>::deserialize_uncompressed(pk).map_err(|_| SdkError::CryptoError {
            reason: "PK deserialize failed",
        })?;

    // Canonical on-chain encoding (fixed-point ×10⁶, padded to 128).
    let v_obf_contract = v_obf_to_contract(v_obf);
    let v_obf_frs = v_obf_i64_to_frs(&v_obf_contract);

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
        binding: binding_fr(binding)?,
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
/// Public inputs: commitment, every v_obf element (fixed-point i64,
/// `v_obf_to_contract` encoding), then the binding. The proof only verifies
/// if the supplied `v_obf` is byte-identical to the vector the proof was
/// generated over, and `binding` is the one it was made for: the verifier
/// computes it itself with [`proof_binding`] from the owner key and the
/// challenge it issued.
pub fn verify_projected(
    vk: &[u8],
    proof: &[u8],
    commitment: &[u8; 32],
    v_obf: &[i64],
    binding: &[u8; 32],
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

    // Public inputs: [commitment] ++ v_obf (128 fixed-point elements) ++ [binding].
    if v_obf.len() > MAX_PROJ_DIM {
        return Ok(false);
    }
    let mut public_inputs =
        core::iter::once(public_comm).collect::<alloc::vec::Vec<_>>();
    public_inputs.extend(v_obf_i64_to_frs(v_obf));
    public_inputs.push(binding_fr(binding)?);

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
                binding: Fr::ZERO,
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

    fn to_fixed(v: &[f32]) -> Vec<i64> {
        v.iter()
            .map(|x| (*x as f64 * 1_000_000.0) as i64)
            .collect()
    }

    fn run_roundtrip(
        v_obf_input: &[f32],
        wrong_comm: Option<[u8; 32]>,
    ) -> bool {
        run_roundtrip_bound(v_obf_input, wrong_comm, Fr::from(7u64), Fr::from(7u64))
    }

    fn run_roundtrip_bound(
        v_obf_input: &[f32],
        wrong_comm: Option<[u8; 32]>,
        proved_binding: Fr,
        checked_binding: Fr,
    ) -> bool {
        let mut rng = rand::rngs::OsRng;
        let n = v_obf_input.len();
        let (pk, vk) = gen_keys_direct(n, &mut rng);

        // Unpadded fixed-point conversion — the 128-padding is an API-level
        // normalization; the circuit itself accepts any length.
        let v_obf_frs = to_fixed(v_obf_input)
            .iter()
            .map(|v| Fr::from(*v))
            .collect::<alloc::vec::Vec<_>>();
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
                binding: proved_binding,
            },
            &pk,
            &mut rng,
        )
        .unwrap();

        // Public inputs: [commitment] ++ v_obf ++ [binding]
        let verify_comm = wrong_comm
            .map(|c| Fr::from_be_bytes_mod_order(&c))
            .unwrap_or(commitment);

        let pvk = prepare_verifying_key(&vk);
        let pub_inputs = core::iter::once(verify_comm)
            .chain(v_obf_frs.iter().copied())
            .chain(core::iter::once(checked_binding))
            .collect::<alloc::vec::Vec<_>>();
        match G16::verify_proof(&pvk, &proof, &pub_inputs) {
            Ok(b) => b,
            Err(_) => false,
        }
    }

    #[test]
    fn groth16_satisfiable() {
        assert!(run_roundtrip(&[0.5f32; 2], None));
    }

    #[test]
    fn wrong_commitment_rejected() {
        assert!(!run_roundtrip(&[0.5f32; 2], Some([0x99u8; 32])));
    }

    /// S3: a proof made for one owner/challenge must not verify for another.
    #[test]
    fn other_binding_rejected() {
        let a = binding_fr(&proof_binding(b"owner-A", b"challenge-1")).unwrap();
        let b = binding_fr(&proof_binding(b"owner-B", b"challenge-1")).unwrap();
        let a2 = binding_fr(&proof_binding(b"owner-A", b"challenge-2")).unwrap();
        assert!(run_roundtrip_bound(&[0.5f32; 2], None, a, a));
        assert!(!run_roundtrip_bound(&[0.5f32; 2], None, a, b), "another owner");
        assert!(!run_roundtrip_bound(&[0.5f32; 2], None, a, a2), "another challenge");
    }

    #[test]
    fn binding_is_domain_separated_and_length_prefixed() {
        assert_ne!(proof_binding(b"ab", b"c"), proof_binding(b"a", b"bc"));
        assert_eq!(proof_binding(b"k", b"n"), proof_binding(b"k", b"n"));
    }

    /// C1: the proof must bind v_obf itself — a proof made for one vector
    /// must NOT verify against a different (even single-element) vector.
    #[test]
    fn tampered_v_obf_rejected() {
        let mut rng = rand::rngs::OsRng;
        let (pk, vk) = gen_keys_direct(2, &mut rng);

        let v_obf: Vec<f32> = vec![0.5f32, -1.25f32];
        let v_obf_contract = to_fixed(&v_obf);
        let v_obf_frs = v_obf_contract
            .iter()
            .map(|v| Fr::from(*v))
            .collect::<alloc::vec::Vec<_>>();
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
                binding: Fr::ONE,
            },
            &pk,
            &mut rng,
        )
        .unwrap();

        let pvk = prepare_verifying_key(&vk);

        // Same vector → verifies.
        let pub_inputs = core::iter::once(commitment)
            .chain(v_obf_frs.iter().copied())
            .chain(core::iter::once(Fr::ONE))
            .collect::<alloc::vec::Vec<_>>();
        assert!(G16::verify_proof(&pvk, &proof, &pub_inputs).unwrap());

        // One element changed (0.5 → 0.500001) → must fail.
        let mut tampered = v_obf_contract.clone();
        tampered[0] += 1;
        let tampered_frs = tampered
            .iter()
            .map(|v| Fr::from(*v))
            .collect::<alloc::vec::Vec<_>>();
        let pub_inputs = core::iter::once(commitment)
            .chain(tampered_frs.iter().copied())
            .chain(core::iter::once(Fr::ONE))
            .collect::<alloc::vec::Vec<_>>();
        assert!(
            !G16::verify_proof(&pvk, &proof, &pub_inputs).unwrap(),
            "a proof must not verify against a swapped v_obf"
        );
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
