// Core Groth16 verification against the embedded HUS verifying key.
//
// This is a self-contained port of `hus_sdk::prover::verify_projected`
// so the WASM component does not need the full SDK dependency graph.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{prepare_verifying_key, VerifyingKey};
use ark_serialize::CanonicalDeserialize;

const VK_BYTES: &[u8] = include_bytes!("../assets/vk.bin");

const MAX_PROJ_DIM: usize = 128;
const V_OBF_BYTES: usize = MAX_PROJ_DIM * 8;

/// Validate a Groth16 proof produced by HUS.
///
/// Args layout (mirrors the wire format agreed for the node call):
///   [0..4]        proof length (u32 LE)
///   [4..4+plen]   proof bytes (arkworks compressed)
///   [4+plen ..4+plen+32]    commitment (32 bytes, Fr uncompressed LE)
///   [4+plen+32 ..]          v_obf (128 × i64 LE, canonical ×10⁶ encoding)
///
/// The proof's public inputs are `[commitment] ++ v_obf`, so a proof
/// generated for one vector cannot verify against a different `v_obf`.
pub fn verify(args: &[u8]) -> bool {
    if args.len() < 4 + 32 + V_OBF_BYTES {
        return false;
    }
    let plen = u32::from_le_bytes([args[0], args[1], args[2], args[3]]) as usize;
    if args.len() != 4 + plen + 32 + V_OBF_BYTES {
        return false;
    }

    let vk = match VerifyingKey::<Bn254>::deserialize_uncompressed(VK_BYTES) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    let pvk = prepare_verifying_key(&vk);

    let proof = match ark_groth16::Proof::<Bn254>::deserialize_compressed(
        &args[4..4 + plen],
    ) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let mut comm_bytes = [0u8; 32];
    comm_bytes.copy_from_slice(&args[4 + plen..4 + plen + 32]);
    let comm = match Fr::deserialize_uncompressed(&comm_bytes[..]) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Public inputs: [commitment] ++ v_obf (128 fixed-point i64 values).
    // Values are bounded by the encoding (|v| < 2³¹ in practice), so a
    // direct i64 → Fr conversion is exact and never wraps.
    let v_obf_start = 4 + plen + 32;
    let public_inputs = core::iter::once(comm)
        .chain(
            args[v_obf_start..v_obf_start + V_OBF_BYTES]
                .chunks_exact(8)
                .map(|c| {
                    let v = i64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
                    Fr::from(v)
                }),
        )
        .collect::<std::vec::Vec<_>>();
    if public_inputs.len() != 1 + MAX_PROJ_DIM {
        return false;
    }

    match ark_groth16::Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs) {
        Ok(true) => true,
        _ => false,
    }
}