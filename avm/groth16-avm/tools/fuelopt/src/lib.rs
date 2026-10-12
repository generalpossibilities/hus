//! Cost breakdown of an optimised Groth16 verifier: the verifying key is
//! trusted (embedded), so its points are built without curve/subgroup checks.
//! The proof's B (a G2 point from the user) still needs the subgroup check.
use substrate_bn::{miller_loop_batch, pairing_batch, AffineG1, AffineG2, Fq, Fq2, Fr, Group, Gt, G1, G2};

const VK: &[u8] = include_bytes!("../../../vectors/vk_raw.bin");
const GOOD: &[u8] = include_bytes!("../../../vectors/good_raw.bin");

fn fq(b: &[u8]) -> Fq { Fq::from_slice(b).unwrap() }
fn g1u(b: &[u8]) -> G1 { G1::new(fq(&b[0..32]), fq(&b[32..64]), Fq::one()) }
fn g2u(b: &[u8]) -> G2 {
    G2::new(Fq2::new(fq(&b[32..64]), fq(&b[0..32])), Fq2::new(fq(&b[96..128]), fq(&b[64..96])), Fq2::one())
}
fn g2checked(b: &[u8]) -> Option<G2> {
    AffineG2::new(Fq2::new(fq(&b[32..64]), fq(&b[0..32])), Fq2::new(fq(&b[96..128]), fq(&b[64..96]))).ok().map(Into::into)
}
fn g1checked(b: &[u8]) -> Option<G1> { AffineG1::new(fq(&b[0..32]), fq(&b[32..64])).ok().map(Into::into) }
fn fr_i64(v: i64) -> Fr {
    let mut be = [0u8; 32];
    be[24..].copy_from_slice(&v.unsigned_abs().to_be_bytes());
    let f = Fr::from_slice(&be).unwrap();
    if v < 0 { -f } else { f }
}
fn ic(i: usize) -> G1 { g1u(&VK[452 + i * 64..452 + (i + 1) * 64]) }
fn l_full() -> G1 {
    let mut l = ic(0) + ic(1) * Fr::from_slice(&GOOD[256..288]).unwrap();
    for i in 0..128 {
        let o = 288 + i * 8;
        let v = i64::from_le_bytes(GOOD[o..o + 8].try_into().unwrap());
        l = l + ic(2 + i) * fr_i64(v);
    }
    l
}

/// Full check with the existing 129-input proof: 4-pair pairing, unchecked VK,
/// checked proof points. Returns true for good_raw.
pub fn verify_full_unchecked_vk() -> bool {
    let (alpha, beta, gamma, delta) = (g1u(&VK[0..64]), g2u(&VK[64..192]), g2u(&VK[192..320]), g2u(&VK[320..448]));
    let (Some(a), Some(b), Some(c)) = (g1checked(&GOOD[0..64]), g2checked(&GOOD[64..192]), g1checked(&GOOD[192..256])) else { return false };
    pairing_batch(&[(-a, b), (alpha, beta), (l_full(), gamma), (c, delta)]) == Gt::one()
}

#[no_mangle]
pub extern "C" fn run(stage: u32) -> u32 {
    let (alpha, beta, gamma, delta) = (g1u(&VK[0..64]), g2u(&VK[64..192]), g2u(&VK[192..320]), g2u(&VK[320..448]));
    let (a, b, c) = (g1u(&GOOD[0..64]), g2u(&GOOD[64..192]), g1u(&GOOD[192..256]));
    let r = match stage {
        0 => true, // build all points unchecked
        1 => g2checked(&GOOD[64..192]).is_some(),                         // proof B subgroup check
        2 => g1checked(&GOOD[0..64]).is_some() && g1checked(&GOOD[192..256]).is_some(), // proof A, C on-curve
        3 => { let l = ic(0) + ic(1) * Fr::from_slice(&GOOD[256..288]).unwrap() + ic(2) * fr_i64(7); !l.is_zero() } // MSM, 2 inputs
        4 => { let l = l_full(); !l.is_zero() }                            // MSM, 129 inputs
        5 => miller_loop_batch(&[(b, -a)]).is_ok(),                        // 1 Miller loop
        6 => miller_loop_batch(&[(b, -a), (gamma, c), (delta, c)]).is_ok(), // 3 Miller loops
        7 => miller_loop_batch(&[(b, -a), (beta, alpha), (gamma, c), (delta, c)]).is_ok(), // 4 Miller loops
        8 => miller_loop_batch(&[(b, -a)]).ok().and_then(|g| g.final_exponentiation()).is_some(), // 1 ML + final exp
        9 => pairing_batch(&[(-a, b), (alpha, beta), (ic(0), gamma), (c, delta)]) != Gt::one(), // 4-pair pairing (as today)
        10 => verify_full_unchecked_vk(),
        // Duplicate check: squared L2 distance between two 128-dim i64 vectors.
        11 => l2_scan(1) > 0,
        12 => l2_scan(1000) > 0,
        _ => false,
    };
    r as u32
}

fn vec_at(k: u64) -> [i64; 128] {
    let mut v = [0i64; 128];
    let mut x = 0x9e37_79b9_7f4a_7c15u64 ^ k;
    for e in v.iter_mut() { x ^= x << 13; x ^= x >> 7; x ^= x << 17; *e = (x % 2_000_001) as i64 - 1_000_000; }
    v
}
/// Minimum squared distance from a query to n stored vectors (vectors are
/// generated, so the cost includes making them: a small, fixed overhead).
fn l2_scan(n: u64) -> i128 {
    let q = core::hint::black_box(vec_at(u64::MAX));
    let mut best = i128::MAX;
    for k in 0..n {
        let v = core::hint::black_box(vec_at(k));
        let d: i128 = q.iter().zip(v.iter()).map(|(a, b)| { let t = (*a - *b) as i128; t * t }).sum();
        if d < best { best = d; }
    }
    best
}
