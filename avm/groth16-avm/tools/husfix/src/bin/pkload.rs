// Time just the proving-key deserialisation that prove_projected does each call.
use ark_bn254::Bn254;
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use std::time::Instant;
fn main() {
    let pk = std::fs::read("../../../../keep/pk.bin").unwrap();
    let t = Instant::now();
    let _k = ProvingKey::<Bn254>::deserialize_uncompressed(&pk[..]).unwrap();
    println!("PK load (validated):   {:.0} ms", t.elapsed().as_secs_f64() * 1000.0);
    let t = Instant::now();
    let _k = ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(&pk[..]).unwrap();
    println!("PK load (unchecked):   {:.0} ms", t.elapsed().as_secs_f64() * 1000.0);
}
