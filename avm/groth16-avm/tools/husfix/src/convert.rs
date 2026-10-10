// Convert the arkworks VK and the good/bad fixtures to raw coordinates, then
// check the substrate-bn verifier natively against them.
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
#[path = "rawverify.rs"] mod rawverify;

fn be<F: PrimeField>(f: &F) -> Vec<u8> { f.into_bigint().to_bytes_be() }
fn g1(p: &G1Affine) -> Vec<u8> { let mut v = be(&p.x); v.extend(be(&p.y)); v }
fn g2(p: &G2Affine) -> Vec<u8> { let mut v = be(&p.x.c1); v.extend(be(&p.x.c0)); v.extend(be(&p.y.c1)); v.extend(be(&p.y.c0)); v }

fn main() {
    let vk = VerifyingKey::<Bn254>::deserialize_uncompressed(&std::fs::read("../../../../keep/vk.bin").unwrap()[..]).unwrap();
    let mut raw = g1(&vk.alpha_g1);
    raw.extend(g2(&vk.beta_g2)); raw.extend(g2(&vk.gamma_g2)); raw.extend(g2(&vk.delta_g2));
    raw.extend((vk.gamma_abc_g1.len() as u32).to_be_bytes());
    for p in &vk.gamma_abc_g1 { raw.extend(g1(p)); }
    std::fs::write("vk_raw.bin", &raw).unwrap();
    println!("vk_raw {} B, IC points {}", raw.len(), vk.gamma_abc_g1.len());
    for name in ["good", "bad"] {
        let a = std::fs::read(format!("{name}.bin")).unwrap();
        let plen = u32::from_le_bytes([a[0], a[1], a[2], a[3]]) as usize;
        let proof = Proof::<Bn254>::deserialize_compressed(&a[4..4 + plen]).unwrap();
        let comm = Fr::deserialize_uncompressed(&a[4 + plen..4 + plen + 32]).unwrap();
        let mut r = g1(&proof.a); r.extend(g2(&proof.b)); r.extend(g1(&proof.c));
        r.extend(be(&comm));
        r.extend(&a[4 + plen + 32..]);
        std::fs::write(format!("{name}_raw.bin"), &r).unwrap();
        println!("{name}_raw {} B -> substrate-bn native verify: {}", r.len(), rawverify::verify_raw(&raw, &r));
    }
}
