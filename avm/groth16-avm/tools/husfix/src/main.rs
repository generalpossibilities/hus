// Writes a real HUS proof in the current wire format, plus a tampered copy.
//   [plen u32 LE][proof][commitment 32B][v_obf 128 x i64 LE]
use hus_sdk::{prove_projected, v_obf_to_contract, verify_projected};

fn main() {
    let pk = std::fs::read("../../../../keep/pk.bin").expect("pk.bin");
    let vk = std::fs::read("../../../../keep/vk.bin").expect("vk.bin");
    let v: Vec<f32> = (0..128).map(|i| (i as f32) / 100.0).collect();
    let (proof, commitment) = prove_projected(&pk, &v).expect("prove");
    let v_obf = v_obf_to_contract(&v);
    let mut bad_v = v_obf.clone();
    bad_v[0] += 1;
    let enc = |vv: &[i64]| {
        let mut a = Vec::new();
        a.extend_from_slice(&(proof.len() as u32).to_le_bytes());
        a.extend_from_slice(&proof);
        a.extend_from_slice(&commitment);
        for x in vv { a.extend_from_slice(&x.to_le_bytes()); }
        a
    };
    std::fs::write("good.bin", enc(&v_obf)).unwrap();
    std::fs::write("bad.bin", enc(&bad_v)).unwrap();
    println!("proof {} B, args {} B", proof.len(), enc(&v_obf).len());
    println!("native verify good: {:?}", verify_projected(&vk, &proof, &commitment, &v_obf));
    println!("native verify bad:  {:?}", verify_projected(&vk, &proof, &commitment, &bad_v));
}
