//! Test-data generator for the stand scripts (prints hex, no 0x prefix).
//!   gen config [attestor_hex...]        registry config (HUS-like defaults)
//!   gen person <seed> [noise] [commit]  registration: commitment | v_obf | proof
use hus_registry::registry::{Config, VerifyMode};

struct Rng(u64);
impl Rng {
    fn u(&mut self) -> f64 { self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17; (self.0 >> 11) as f64 / (1u64 << 53) as f64 }
    fn gauss(&mut self) -> f64 { let (a, b) = (self.u().max(1e-300), self.u()); (-2.0 * a.ln()).sqrt() * (6.283185307179586 * b).cos() }
}
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        Some("config") => {
            let attestors = a[1..].iter().map(|h| {
                let v: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap()).collect();
                v.try_into().unwrap()
            }).collect();
            let c = Config { dim: 128, lsh_bits: 8, probe_margin: 3_000_000, dup_dist_sq: 25_000_000_000_000,
                             seed: [7; 32], mode: VerifyMode::Attestor, attestors };
            println!("{}", hex(&c.encode()));
        }
        Some("person") => {
            let seed: u64 = a[1].parse().unwrap();
            let noise: f64 = a.get(2).map_or(0.0, |s| s.parse().unwrap());
            let commit: u64 = a.get(3).map_or(seed, |s| s.parse().unwrap());
            let mut p = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
            let mut n = Rng(commit.wrapping_mul(0xd1b5_4a32_d192_ed03) | 1);
            let mut b = [0u8; 32].to_vec();
            b[..8].copy_from_slice(&commit.to_le_bytes());
            b[31] = 1;
            for _ in 0..128 {
                let x = p.gauss() + noise * n.gauss();
                b.extend_from_slice(&((x * 1e6).round() as i64).to_le_bytes());
            }
            b.extend_from_slice(b"proof");
            println!("{}", hex(&b));
        }
        _ => eprintln!("usage: gen config [attestor_hex...] | gen person <seed> [noise] [commit]"),
    }
}
