// Groth16 (BN254) verification on raw big-endian coordinates with substrate-bn.
// VK  : alpha G1 | beta G2 | gamma G2 | delta G2 | n u32 BE | IC[n] G1
// args: A G1 | B G2 | C G1 | commitment Fr | v_obf 128 x i64 LE
// G1 = x|y (64 B), G2 = x.c1|x.c0|y.c1|y.c0 (128 B, Ethereum precompile order).
use substrate_bn::{pairing_batch, AffineG1, AffineG2, Fq, Fq2, Fr, Group, Gt, G1, G2};

fn fq(b: &[u8]) -> Option<Fq> { Fq::from_slice(b).ok() }
fn g1(b: &[u8]) -> Option<G1> {
    let (x, y) = (fq(&b[0..32])?, fq(&b[32..64])?);
    if x.is_zero() && y.is_zero() { return Some(G1::zero()); }
    AffineG1::new(x, y).ok().map(Into::into)
}
fn g2(b: &[u8]) -> Option<G2> {
    let x = Fq2::new(fq(&b[32..64])?, fq(&b[0..32])?);
    let y = Fq2::new(fq(&b[96..128])?, fq(&b[64..96])?);
    AffineG2::new(x, y).ok().map(Into::into)
}
fn fr_i64(v: i64) -> Fr {
    let mut be = [0u8; 32];
    be[24..].copy_from_slice(&v.unsigned_abs().to_be_bytes());
    let f = Fr::from_slice(&be).unwrap_or_else(|_| Fr::zero());
    if v < 0 { -f } else { f }
}

pub const V_OBF_LEN: usize = 128;

pub fn verify_raw(vk: &[u8], args: &[u8]) -> bool { verify_stage(vk, args, 4) }

/// 1 parse, 2 parse+MSM, 3 parse+pairing (no MSM), 4 full.
pub fn verify_stage(vk: &[u8], args: &[u8], stage: u8) -> bool {
    const PROOF: usize = 64 + 128 + 64;
    if args.len() != PROOF + 32 + V_OBF_LEN * 8 || vk.len() < 64 + 3 * 128 + 4 { return false; }
    if stage == 0 { return true; }
    if stage >= 0x10 {
        // Calibration: 2^(stage-0x10) x 1000 xorshift rounds.
        let n: u64 = 1000u64 << (stage - 0x10);
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..n { x ^= x << 13; x ^= x >> 7; x ^= x << 17; }
        return core::hint::black_box(x) != 0;
    }
    if stage == 5 { return g1(&vk[0..64]).is_some() && g1(&args[0..64]).is_some() && g1(&args[192..256]).is_some() && g1(&vk[452..516]).is_some(); }
    if stage == 6 { return g2(&vk[64..192]).is_some(); }
    let n = u32::from_be_bytes([vk[448], vk[449], vk[450], vk[451]]) as usize;
    if n != 1 + 1 + V_OBF_LEN || vk.len() != 452 + n * 64 { return false; }
    let (Some(alpha), Some(beta), Some(gamma), Some(delta)) =
        (g1(&vk[0..64]), g2(&vk[64..192]), g2(&vk[192..320]), g2(&vk[320..448])) else { return false };
    let (Some(a), Some(b), Some(c)) = (g1(&args[0..64]), g2(&args[64..192]), g1(&args[192..256])) else { return false };
    let Ok(comm) = Fr::from_slice(&args[256..288]) else { return false };
    // L = IC0 + commitment·IC1 + Σ v_obf[i]·IC[i+2]
    let ic = |i: usize| g1(&vk[452 + i * 64..452 + (i + 1) * 64]);
    let Some(mut l) = ic(0) else { return false };
    if stage == 1 { return true; }
    let Some(ic1) = ic(1) else { return false };
    if stage != 3 { l = l + ic1 * comm; }
    for i in 0..(if stage == 3 { 0 } else { V_OBF_LEN }) {
        let o = 288 + i * 8;
        let v = i64::from_le_bytes([args[o], args[o+1], args[o+2], args[o+3], args[o+4], args[o+5], args[o+6], args[o+7]]);
        let Some(p) = ic(2 + i) else { return false };
        l = l + p * fr_i64(v);
    }
    if stage == 2 { return true; }
    pairing_batch(&[(-a, b), (alpha, beta), (l, gamma), (c, delta)]) == Gt::one()
}
