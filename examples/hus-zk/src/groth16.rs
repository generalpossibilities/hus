//! Groth16 verification over BN254 using only `g1_add`, `g1_mul` and
//! `pairing_check`, so it costs a handful of host calls on a runtime with the
//! native functions.
//!
//! Verifying key, raw big-endian (the format snarkjs/gnark/arkworks keys
//! convert to directly): `α G1 | β G2 | γ G2 | δ G2 | n u32 BE | IC[n] G1`,
//! where `n` = number of public inputs + 1.
//! Proof: `A G1 | B G2 | C G1` (256 bytes).
//! Public inputs: 32-byte big-endian scalars.
use crate::{g1_add, g1_mul, g1_neg, pairing_check, Error, Scalar};
use alloc::vec::Vec;

pub const PROOF_LEN: usize = 64 + 128 + 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The key is not in the raw format, or the input count does not match.
    BadKey,
    BadProof,
    Curve(Error),
}

impl From<Error> for VerifyError {
    fn from(e: Error) -> Self {
        VerifyError::Curve(e)
    }
}

/// A parsed view of a raw verifying key (no copying, no curve checks: the
/// pairing check validates every point it uses).
pub struct VerifyingKey<'a> {
    alpha: &'a [u8],
    beta: &'a [u8],
    gamma: &'a [u8],
    delta: &'a [u8],
    ic: &'a [u8],
}

impl<'a> VerifyingKey<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, VerifyError> {
        if raw.len() < 452 {
            return Err(VerifyError::BadKey);
        }
        let n = u32::from_be_bytes(raw[448..452].try_into().unwrap()) as usize;
        if n == 0 || raw.len() != 452 + 64 * n {
            return Err(VerifyError::BadKey);
        }
        Ok(VerifyingKey { alpha: &raw[0..64], beta: &raw[64..192], gamma: &raw[192..320], delta: &raw[320..448], ic: &raw[452..] })
    }

    pub fn public_inputs(&self) -> usize {
        self.ic.len() / 64 - 1
    }
}

/// `true` if the proof verifies; `Ok(false)` for a well-formed but wrong proof.
pub fn verify(vk: &VerifyingKey<'_>, public_inputs: &[Scalar], proof: &[u8]) -> Result<bool, VerifyError> {
    if public_inputs.len() != vk.public_inputs() {
        return Err(VerifyError::BadKey);
    }
    if proof.len() != PROOF_LEN {
        return Err(VerifyError::BadProof);
    }
    // L = IC[0] + Σ input_i · IC[i + 1]
    let ic = |i: usize| -> [u8; 64] { vk.ic[64 * i..64 * (i + 1)].try_into().unwrap() };
    let mut l = ic(0);
    for (i, s) in public_inputs.iter().enumerate() {
        if s.iter().any(|b| *b != 0) {
            l = g1_add(&l, &g1_mul(&ic(i + 1), s)?)?;
        }
    }
    // e(-A, B) · e(α, β) · e(L, γ) · e(C, δ) = 1
    let a: [u8; 64] = proof[0..64].try_into().unwrap();
    let mut input = Vec::with_capacity(4 * 192);
    input.extend_from_slice(&g1_neg(&a));
    input.extend_from_slice(&proof[64..192]);
    input.extend_from_slice(vk.alpha);
    input.extend_from_slice(vk.beta);
    input.extend_from_slice(&l);
    input.extend_from_slice(vk.gamma);
    input.extend_from_slice(&proof[192..256]);
    input.extend_from_slice(vk.delta);
    Ok(pairing_check(&input)?)
}
