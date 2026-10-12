//! BN254 (alt_bn128) operations with Ethereum's EIP-196/197 encoding, and
//! Groth16 verification built only from them, for AVM contracts.
//!
//! Encoding (all big-endian, as in Ethereum's precompiles):
//! - field element / scalar: 32 bytes;
//! - G1 point: `x | y` (64 bytes), `0…0` is the point at infinity;
//! - G2 point: `x.c1 | x.c0 | y.c1 | y.c0` (128 bytes), `0…0` is infinity;
//! - pairing input: `n × (G1 | G2)` (192 bytes per pair).
//!
//! Two backends with the same API:
//! - default: pure WASM (`substrate-bn`). Correct everywhere, but on AVM
//!   today only `g1_add` fits a message: `g1_mul` costs about 8M FUEL and a
//!   pairing check hundreds of millions (see the README);
//! - `native` feature: calls the proposed AVM host functions in import module
//!   `avm_crypto` (`bn254_g1_add`, `bn254_g1_mul`, `bn254_pairing_check`).
//!   A contract built against this crate needs no source change to switch.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

#[cfg(not(feature = "native"))]
mod soft;
#[cfg(feature = "native")]
mod native;
#[cfg(not(feature = "native"))]
use soft as backend;
#[cfg(feature = "native")]
use native as backend;

pub mod groth16;

pub type G1 = [u8; 64];
pub type G2 = [u8; 128];
pub type Scalar = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A coordinate is not below the field modulus.
    InvalidFieldElement,
    /// A G1 point is not on the curve.
    InvalidG1,
    /// A G2 point is not on the curve or not in the prime-order subgroup.
    InvalidG2,
    /// The pairing input is not a multiple of 192 bytes.
    InvalidLength,
}

/// EIP-196 ECADD: `p + q`.
pub fn g1_add(p: &G1, q: &G1) -> Result<G1, Error> {
    backend::g1_add(p, q)
}

/// EIP-196 ECMUL: `s · p`. The scalar is any 256-bit value (reduced mod r).
pub fn g1_mul(p: &G1, s: &Scalar) -> Result<G1, Error> {
    backend::g1_mul(p, s)
}

/// EIP-197 ECPAIRING: whether `∏ e(G1_i, G2_i) = 1`. Empty input is `true`.
pub fn pairing_check(pairs: &[u8]) -> Result<bool, Error> {
    if pairs.len() % 192 != 0 {
        return Err(Error::InvalidLength);
    }
    backend::pairing_check(pairs)
}

/// The BN254 base-field modulus p, big-endian.
pub const FIELD_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

/// `-p` for a G1 point: `(x, p - y)`, infinity stays infinity. Needs no curve
/// arithmetic, so it is the same for both backends.
pub fn g1_neg(p: &G1) -> G1 {
    if p.iter().all(|b| *b == 0) {
        return *p;
    }
    let mut out = *p;
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = FIELD_MODULUS[i] as i16 - p[32 + i] as i16 - borrow;
        out[32 + i] = d.rem_euclid(256) as u8;
        borrow = (d < 0) as i16;
    }
    out
}
