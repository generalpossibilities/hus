// Time HUS proof generation and verification natively (production keys).
use hus_sdk::{prove_projected, v_obf_to_contract, verify_projected};
use std::time::Instant;

fn main() {
    let pk = std::fs::read("../../../../keep/pk.bin").unwrap();
    let vk = std::fs::read("../../../../keep/vk.bin").unwrap();
    let v: Vec<f32> = (0..128).map(|i| (i as f32) / 100.0).collect();
    let v_obf = v_obf_to_contract(&v);
    let mut prove_ms = Vec::new();
    let mut verify_ms = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        let (proof, comm) = prove_projected(&pk, &v).unwrap();
        prove_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        let t = Instant::now();
        assert!(verify_projected(&vk, &proof, &comm, &v_obf).unwrap());
        verify_ms.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    let s = |x: &Vec<f64>| { let mut y = x.clone(); y.sort_by(|a, b| a.partial_cmp(b).unwrap()); (y[0], y[y.len() / 2], y[y.len() - 1]) };
    let (a, b, c) = s(&prove_ms); println!("prove  (incl. 17 MB PK load): min {a:.0} ms, median {b:.0} ms, max {c:.0} ms");
    let (a, b, c) = s(&verify_ms); println!("verify (incl. VK load):       min {a:.1} ms, median {b:.1} ms, max {c:.1} ms");
}
