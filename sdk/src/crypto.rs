use crate::circuit::poseidon::PoseidonConfig;
use crate::PROJ_DIM;
use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;

pub type Scalar = Fr;

pub fn hash_commitment(data: &[u8]) -> [u8; 32] {
    let elements = bytes_to_fes(data);
    let config = PoseidonConfig::new();
    let result = config.hash_native(&elements);
    fe_to_bytes(result)
}

pub fn commit_isolated_vector(vec: &[f32; PROJ_DIM]) -> [u8; 32] {
    let mut fe = [Fr::ZERO; PROJ_DIM];
    for (i, v) in vec.iter().enumerate() {
        fe[i] = Fr::from(v.to_bits() as u64);
    }
    let config = PoseidonConfig::new();
    let result = config.hash_native(&fe);
    fe_to_bytes(result)
}

fn bytes_to_fes(data: &[u8]) -> Vec<Fr> {
    let mut elements = Vec::with_capacity(data.len() / 31 + 1);
    for chunk in data.chunks(31) {
        let mut bytes = [0u8; 32];
        bytes[..chunk.len()].copy_from_slice(chunk);
        elements.push(Fr::from_be_bytes_mod_order(&bytes));
    }
    elements
}

fn fe_to_bytes(fe: Fr) -> [u8; 32] {
    let mut encoded = Vec::new();
    fe.serialize_uncompressed(&mut encoded).ok();
    let mut buf = [0u8; 32];
    buf[..encoded.len()].copy_from_slice(&encoded);
    buf
}

pub fn build_mock_proof(commitment: &[u8; 32]) -> Vec<u8> {
    let mut proof = Vec::new();
    proof.extend_from_slice(commitment);
    proof.push(0x01);
    proof
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_is_32_bytes() {
        let c = hash_commitment(b"hello");
        assert_eq!(c.len(), 32);
    }

    #[test]
    fn commitment_deterministic() {
        let a = hash_commitment(b"test");
        let b = hash_commitment(b"test");
        assert_eq!(a, b);
    }

    #[test]
    fn different_input_different_commitment() {
        let a = hash_commitment(b"alpha");
        let b = hash_commitment(b"beta");
        assert_ne!(a, b);
    }

    #[test]
    fn vector_commitment_is_32_bytes() {
        let v = [0.5f32; PROJ_DIM];
        let c = commit_isolated_vector(&v);
        assert_eq!(c.len(), 32);
    }

    #[test]
    fn mock_proof_contains_commitment() {
        let c = [0xabu8; 32];
        let p = build_mock_proof(&c);
        assert_eq!(&p[..32], &c[..]);
        assert_eq!(p[32], 0x01);
    }
}
