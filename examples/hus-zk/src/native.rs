//! Backend over the proposed AVM host functions (import module `avm_crypto`).
//! Not provided by any AVM runtime yet; see HOST-FUNCTIONS.md for the
//! specification this follows.
//!
//! Every function takes input and output pointers into the contract's linear
//! memory and returns 0 on success or an error code: 1 invalid field element,
//! 2 invalid G1, 3 invalid G2, 4 invalid length. `bn254_pairing_check` writes
//! one byte, 1 or 0.
use crate::{Error, Scalar, G1};

#[link(wasm_import_module = "avm_crypto")]
extern "C" {
    fn bn254_g1_add(input_ptr: *const u8, output_ptr: *mut u8) -> u32;
    fn bn254_g1_mul(input_ptr: *const u8, output_ptr: *mut u8) -> u32;
    fn bn254_pairing_check(input_ptr: *const u8, input_len: u32, output_ptr: *mut u8) -> u32;
}

fn status(code: u32) -> Result<(), Error> {
    match code {
        0 => Ok(()),
        1 => Err(Error::InvalidFieldElement),
        2 => Err(Error::InvalidG1),
        3 => Err(Error::InvalidG2),
        _ => Err(Error::InvalidLength),
    }
}

pub fn g1_add(p: &G1, q: &G1) -> Result<G1, Error> {
    let mut input = [0u8; 128];
    input[..64].copy_from_slice(p);
    input[64..].copy_from_slice(q);
    let mut out = [0u8; 64];
    // SAFETY: the host reads 128 bytes from `input` and writes 64 to `out`.
    status(unsafe { bn254_g1_add(input.as_ptr(), out.as_mut_ptr()) })?;
    Ok(out)
}

pub fn g1_mul(p: &G1, s: &Scalar) -> Result<G1, Error> {
    let mut input = [0u8; 96];
    input[..64].copy_from_slice(p);
    input[64..].copy_from_slice(s);
    let mut out = [0u8; 64];
    // SAFETY: the host reads 96 bytes from `input` and writes 64 to `out`.
    status(unsafe { bn254_g1_mul(input.as_ptr(), out.as_mut_ptr()) })?;
    Ok(out)
}

pub fn pairing_check(pairs: &[u8]) -> Result<bool, Error> {
    let mut out = [0u8; 1];
    // SAFETY: the host reads `pairs.len()` bytes and writes 1 byte to `out`.
    status(unsafe { bn254_pairing_check(pairs.as_ptr(), pairs.len() as u32, out.as_mut_ptr()) })?;
    Ok(out[0] == 1)
}
