//! Conformance: every operation is cross-checked against arkworks (an
//! independent BN254 implementation), and Groth16 against real HUS vectors.
use ark_bn254::{Fq, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use hus_zk::groth16::{verify, VerifyingKey};
use hus_zk::{g1_add, g1_mul, g1_neg, pairing_check, Error};

fn fq_be(x: &Fq) -> [u8; 32] { x.into_bigint().to_bytes_be().try_into().unwrap() }
fn g1(p: &G1Affine) -> [u8; 64] {
    let mut o = [0u8; 64];
    if !p.is_zero() { o[..32].copy_from_slice(&fq_be(&p.x)); o[32..].copy_from_slice(&fq_be(&p.y)); }
    o
}
fn g2(p: &G2Affine) -> [u8; 128] {
    let mut o = [0u8; 128];
    if !p.is_zero() {
        o[0..32].copy_from_slice(&fq_be(&p.x.c1)); o[32..64].copy_from_slice(&fq_be(&p.x.c0));
        o[64..96].copy_from_slice(&fq_be(&p.y.c1)); o[96..128].copy_from_slice(&fq_be(&p.y.c0));
    }
    o
}
fn fr_be(s: &Fr) -> [u8; 32] { s.into_bigint().to_bytes_be().try_into().unwrap() }

#[test]
fn g1_add_and_mul_match_arkworks() {
    let mut rng = ark_std::test_rng();
    for _ in 0..20 {
        let (p, q) = (G1Projective::rand(&mut rng).into_affine(), G1Projective::rand(&mut rng).into_affine());
        let s = Fr::rand(&mut rng);
        assert_eq!(g1_add(&g1(&p), &g1(&q)).unwrap(), g1(&(p + q).into_affine()));
        assert_eq!(g1_mul(&g1(&p), &fr_be(&s)).unwrap(), g1(&(p * s).into_affine()));
        assert_eq!(g1_add(&g1(&p), &g1_neg(&g1(&p))).unwrap(), [0u8; 64], "p + (-p) = infinity");
    }
}

#[test]
fn infinity_and_invalid_points() {
    let gen = g1(&G1Affine::generator());
    let zero = [0u8; 64];
    assert_eq!(g1_add(&zero, &gen).unwrap(), gen);
    assert_eq!(g1_mul(&gen, &[0u8; 32]).unwrap(), zero);
    let mut off_curve = gen;
    off_curve[63] ^= 1;
    assert_eq!(g1_add(&off_curve, &gen), Err(Error::InvalidG1));
    assert_eq!(g1_add(&[0xff; 64], &gen), Err(Error::InvalidFieldElement));
    assert_eq!(pairing_check(&[0u8; 100]), Err(Error::InvalidLength));
    assert_eq!(pairing_check(&[]), Ok(true));
    // A G2 point on the twist but outside the prime-order subgroup is rejected.
    let mut bad_g2 = g2(&G2Affine::generator());
    bad_g2[127] ^= 1;
    let mut input = gen.to_vec();
    input.extend_from_slice(&bad_g2);
    assert!(matches!(pairing_check(&input), Err(Error::InvalidG2)));
}

#[test]
fn pairing_is_bilinear() {
    let mut rng = ark_std::test_rng();
    let (a, b) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
    let p = G1Affine::generator();
    let q = G2Affine::generator();
    // e(aP, bQ) · e(-abP, Q) = 1
    let mut input = g1(&(p * a).into_affine()).to_vec();
    input.extend_from_slice(&g2(&(G2Projective::generator() * b).into_affine()));
    input.extend_from_slice(&g1(&(-(p * (a * b))).into_affine()));
    input.extend_from_slice(&g2(&q));
    assert_eq!(pairing_check(&input), Ok(true));
    // and with a wrong scalar it is not 1
    let mut wrong = input.clone();
    wrong[..64].copy_from_slice(&g1(&(p * (a + Fr::from(1u64))).into_affine()));
    assert_eq!(pairing_check(&wrong), Ok(false));
}

/// HUS public inputs from the raw proof file: commitment, then v_obf as field elements.
fn hus_inputs(raw: &[u8]) -> Vec<[u8; 32]> {
    let mut v = vec![raw[256..288].try_into().unwrap()];
    for i in 0..128 {
        let x = i64::from_le_bytes(raw[288 + 8 * i..296 + 8 * i].try_into().unwrap());
        let f = if x < 0 { -Fr::from(x.unsigned_abs()) } else { Fr::from(x as u64) };
        v.push(fr_be(&f));
    }
    v
}

#[test]
fn groth16_hus_vectors() {
    let vk_raw = include_bytes!("../vectors/vk_raw.bin");
    let vk = VerifyingKey::parse(vk_raw).unwrap();
    assert_eq!(vk.public_inputs(), 129);
    let good = include_bytes!("../vectors/good_raw.bin");
    let bad = include_bytes!("../vectors/bad_raw.bin");
    assert_eq!(verify(&vk, &hus_inputs(good), &good[..256]), Ok(true));
    assert_eq!(verify(&vk, &hus_inputs(bad), &bad[..256]), Ok(false));
    // A tampered proof point fails too.
    let mut p = good[..256].to_vec();
    p[255] ^= 1;
    assert!(verify(&vk, &hus_inputs(good), &p) != Ok(true));
}
