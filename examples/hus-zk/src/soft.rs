//! Pure-WASM backend on substrate-bn (the library behind Parity's and other
//! EVMs' alt_bn128 precompiles), with EIP-196/197 semantics.
use crate::{Error, Scalar, G1, G2};
use substrate_bn::{pairing_batch, AffineG1, AffineG2, Fq, Fq2, Fr, Group, Gt};

fn fq(b: &[u8]) -> Result<Fq, Error> {
    Fq::from_slice(b).map_err(|_| Error::InvalidFieldElement)
}

pub(crate) fn read_g1(b: &[u8]) -> Result<substrate_bn::G1, Error> {
    let (x, y) = (fq(&b[0..32])?, fq(&b[32..64])?);
    if x.is_zero() && y.is_zero() {
        return Ok(substrate_bn::G1::zero());
    }
    AffineG1::new(x, y).map(Into::into).map_err(|_| Error::InvalidG1)
}

pub(crate) fn read_g2(b: &[u8]) -> Result<substrate_bn::G2, Error> {
    let (xc1, xc0, yc1, yc0) = (fq(&b[0..32])?, fq(&b[32..64])?, fq(&b[64..96])?, fq(&b[96..128])?);
    let (x, y) = (Fq2::new(xc0, xc1), Fq2::new(yc0, yc1));
    if x.is_zero() && y.is_zero() {
        return Ok(substrate_bn::G2::zero());
    }
    // AffineG2::new checks the curve equation and the subgroup.
    AffineG2::new(x, y).map(Into::into).map_err(|_| Error::InvalidG2)
}

fn write_g1(p: substrate_bn::G1) -> G1 {
    let mut out = [0u8; 64];
    if let Some(a) = AffineG1::from_jacobian(p) {
        a.x().to_big_endian(&mut out[0..32]).unwrap();
        a.y().to_big_endian(&mut out[32..64]).unwrap();
    }
    out
}

pub fn g1_add(p: &G1, q: &G1) -> Result<G1, Error> {
    Ok(write_g1(read_g1(p)? + read_g1(q)?))
}

pub fn g1_mul(p: &G1, s: &Scalar) -> Result<G1, Error> {
    // EIP-196 takes any 256-bit scalar; reduce it mod r.
    let mut wide = [0u8; 64];
    wide[32..].copy_from_slice(s);
    let s = Fr::interpret(&wide);
    Ok(write_g1(read_g1(p)? * s))
}

pub fn pairing_check(pairs: &[u8]) -> Result<bool, Error> {
    let mut v = alloc::vec::Vec::with_capacity(pairs.len() / 192);
    for c in pairs.chunks_exact(192) {
        let g2: &G2 = c[64..192].try_into().unwrap();
        v.push((read_g1(&c[0..64])?, read_g2(g2)?));
    }
    Ok(v.is_empty() || pairing_batch(&v) == Gt::one())
}
