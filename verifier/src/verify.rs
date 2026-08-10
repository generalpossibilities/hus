// Core Groth16 verification against the embedded HUS verifying key.
//
// This is a self-contained port of `hus_sdk::prover::verify_projected`
// so the WASM component does not need the full SDK dependency graph.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{prepare_verifying_key, VerifyingKey};
use ark_serialize::CanonicalDeserialize;

const VK_BYTES: &[u8] = include_bytes!("../assets/vk.bin");

/// Validate a Groth16 proof produced by HUS.
///
/// Args layout (mirrors our contract/gateway encoding):
///   [0..4]        proof length (u32 LE)
///   [4..4+plen]   proof bytes (arkworks compressed)
///   [4+plen ..]   commitment (32 bytes, Fr uncompressed LE)
pub fn verify(args: &[u8]) -> bool {
    if args.len() < 4 + 32 {
        return false;
    }
    let plen = u32::from_le_bytes([args[0], args[1], args[2], args[3]]) as usize;
    if args.len() != 4 + plen + 32 {
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

    match ark_groth16::Groth16::<Bn254>::verify_proof(&pvk, &proof, &[comm]) {
        Ok(true) => true,
        _ => false,
    }
}