//! How long proving takes: loading the proving key, then one proof.
//!   cargo run --release -p hus-sdk --example prove_timing -- keep/pk.bin
use std::time::Instant;

use ark_bn254::Bn254;
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "keep/pk.bin".into());
    let pk = std::fs::read(&path).expect("proving key");
    let t = Instant::now();
    ProvingKey::<Bn254>::deserialize_uncompressed(&pk[..]).unwrap();
    println!("load (checked):   {:?}", t.elapsed());
    let t = Instant::now();
    ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(&pk[..]).unwrap();
    println!("load (unchecked): {:?}", t.elapsed());
    let v = vec![0.01f32; 128];
    let t = Instant::now();
    hus_sdk::prove_projected(&pk, &v, &[0u8; 32]).unwrap();
    println!("prove (with checked load): {:?}", t.elapsed());
}
