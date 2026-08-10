//! Generate a real proof fixture (args + raw bytes) for wasmtime CLI testing.
//!
//! Run: cargo run --example gen_fixture -p hus-wasm-verifier
//! Writes assets/fixture_args.bin and assets/fixture_args.wave

use hus_sdk::circuit::r1cs::MAX_PROJ_DIM;
use hus_sdk::prover::prove_projected;

fn main() {
    let pk_bytes = std::fs::read("../keep/pk.bin").expect("keep/pk.bin");
    let v_obf: Vec<f32> = (0..MAX_PROJ_DIM).map(|i| (i as f32) / 100.0).collect();
    let (proof, commitment) = prove_projected(&pk_bytes, &v_obf).expect("prove failed");

    let mut args = Vec::with_capacity(4 + proof.len() + 32);
    args.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    args.extend_from_slice(&proof);
    args.extend_from_slice(&commitment);

    std::fs::write("assets/fixtures.bin", &args).expect("write bin fixture");

    let wave = format!("verify([{}])", args.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(","));
    std::fs::write("assets/fixtures.wave", wave).expect("write wave fixture");

    println!("proof={} commitment=32 args={} wrote assets/fixtures.bin + .wave", proof.len(), args.len());
}