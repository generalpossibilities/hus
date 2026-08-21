/// Generate real Groth16 PK/VK on BN254 for Shellnet deployment.
///
/// Outputs PK and VK as hex strings for use with HusRegistry.
/// Run: cargo run --example keygen -p hus-sdk --release
use ark_bn254::{Bn254, Fr};
use ark_ff::Field;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use hus_sdk::circuit::r1cs::HusCircuit;

fn main() {
    let mut rng = rand::rngs::OsRng;
    let circuit = HusCircuit {
        v_obf: vec![Fr::ZERO; 128],
        nonce: Fr::ZERO,
        commitment: Fr::ZERO,
    };
    let start = std::time::Instant::now();
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng).unwrap();
    let vk = pk.vk.clone();
    let keygen_time = start.elapsed();

    let mut pk_bytes = Vec::new();
    pk.serialize_uncompressed(&mut pk_bytes).unwrap();
    let mut vk_bytes = Vec::new();
    vk.serialize_uncompressed(&mut vk_bytes).unwrap();

    std::fs::create_dir_all("keep").unwrap();
    std::fs::write("keep/pk.bin", &pk_bytes).unwrap();
    std::fs::write("keep/vk.bin", &vk_bytes).unwrap();
    std::fs::write("verifier/assets/vk.bin", &vk_bytes).unwrap();
    let pk_hex = hex::encode(&pk_bytes);
    let vk_hex = hex::encode(&vk_bytes);
    std::fs::write("keep/pk.hex", &pk_hex).unwrap();
    std::fs::write("keep/vk.hex", &vk_hex).unwrap();
    println!("PK hex written to keep/pk.hex ({} bytes)", pk_bytes.len());
    println!("VK hex written to keep/vk.hex ({} bytes)", vk_bytes.len());
    println!(
        "VK binary also written to verifier/assets/vk.bin (embedded in the WASM verifier)"
    );
    println!("PK size: {} bytes", pk_bytes.len());
    println!("VK size: {} bytes", vk_bytes.len());
    println!("Keygen time: {:?}", keygen_time);
}
