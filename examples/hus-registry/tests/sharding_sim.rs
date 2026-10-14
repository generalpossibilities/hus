//! Native simulation of a sharded registry, before any contract code.
//!
//! Scheme ("write-side fan-out, local read"): buckets are spread over S shard
//! accounts. An accepted record is stored at its home bucket's shard and copied
//! to every other shard that owns one of its probe buckets. A new registration
//! is checked only at its own home shard, against the records that shard holds
//! in the registration's probe buckets.
//!
//! Measures, per shard count: recall on rescans, copies per record, worst-case
//! comparisons per check (must stay well under ~400, the ~10M FUEL message cap
//! at ~25k FUEL per comparison), and records per shard including copies.
//!
//! Run: cargo test --release --test sharding_sim -- --ignored --nocapture
use hus_registry::registry::*;
use std::collections::HashMap;

const DIM: usize = 128;
const SCALE: f64 = 1e6;
const DUP: f64 = 5.0;

struct Rng(u64);
impl Rng {
    fn u(&mut self) -> f64 { self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17; (self.0 >> 11) as f64 / (1u64 << 53) as f64 }
    fn gauss(&mut self) -> f64 { let (a, b) = (self.u().max(1e-300), self.u()); (-2.0 * a.ln()).sqrt() * (6.283185307179586 * b).cos() }
    fn person(&mut self) -> Vec<f64> { (0..DIM).map(|_| self.gauss()).collect() }
}

fn config(lsh_bits: u8) -> Config {
    Config { dim: DIM as u16, lsh_bits, cell: 1, quant_step: 62_500, probe_margin: 3_000_000,
             dup_dist_sq: 25_000_000_000_000, seed: [7; 32], mode: VerifyMode::Attestor, attestors: vec![] }
}
fn fixed(v: &[f64]) -> Vec<i32> { v.iter().map(|x| (x * SCALE).round() as i32).collect() }
fn dist(a: &[f64], b: &[f64]) -> f64 { a.iter().zip(b).map(|(x, y)| (x - y) * (x - y)).sum::<f64>().sqrt() }

struct Report { shards: usize, recall: f64, copies: f64, avg_cmp: f64, max_cmp: usize, max_shard: usize, false_dup: usize }

fn simulate(home_only: bool, lsh_bits: u8, shards: usize, people: &[Vec<f64>], rescans: &[(usize, Vec<f64>)], fresh: &[Vec<f64>]) -> Report {
    let c = config(lsh_bits);
    let shard_of = |b: u16| (b as usize) % shards;
    // shard -> bucket -> person indices
    let mut store: Vec<HashMap<u16, Vec<usize>>> = (0..shards).map(|_| HashMap::new()).collect();
    let mut copies = 0usize;
    for (i, p) in people.iter().enumerate() {
        let (_, probes) = lsh_probes(&c, &fixed(p));
        // a copy per shard; within a shard the record is filed under each probe bucket it owns
        let mut shards_hit = std::collections::HashSet::new();
        for b in &probes {
            store[shard_of(*b)].entry(*b).or_default().push(i);
            shards_hit.insert(shard_of(*b));
        }
        copies += shards_hit.len();
    }
    // Check one vector at its home shard: compare with records filed under its probe buckets that shard owns.
    let check = |v: &[f64]| -> (bool, usize) {
        let (home, probes) = lsh_probes(&c, &fixed(v));
        let s = shard_of(home);
        let mut seen = std::collections::HashSet::new();
        let mut hit = false;
        let look: Vec<u16> = if home_only { vec![home] } else { probes.iter().copied().filter(|b| shard_of(*b) == s).collect() };
        for b in look.iter() {
            if let Some(list) = store[s].get(b) {
                for &i in list {
                    if seen.insert(i) && dist(v, &people[i]) < DUP { hit = true; }
                }
            }
        }
        (hit, seen.len())
    };
    let mut caught = 0; let mut max_cmp = 0; let mut sum_cmp = 0;
    for (_, r) in rescans { let (hit, n) = check(r); if hit { caught += 1 } max_cmp = max_cmp.max(n); sum_cmp += n; }
    let mut false_dup = 0;
    for f in fresh { let (hit, n) = check(f); if hit { false_dup += 1 } max_cmp = max_cmp.max(n); sum_cmp += n; }
    // records per shard (distinct people, i.e. stored copies)
    let max_shard = store.iter().map(|m| { let mut s = std::collections::HashSet::new(); for l in m.values() { s.extend(l.iter().copied()); } s.len() }).max().unwrap_or(0);
    Report { shards, recall: caught as f64 / rescans.len() as f64, copies: copies as f64 / people.len() as f64,
             avg_cmp: sum_cmp as f64 / (rescans.len() + fresh.len()) as f64, max_cmp, max_shard, false_dup }
}

#[test]
#[ignore]
fn sharded_fanout_recall_and_load() {
    for &(n, lsh_bits) in &[(20_000usize, 8u8), (20_000, 10), (20_000, 12)] {
        let mut rng = Rng(42);
        let people: Vec<Vec<f64>> = (0..n).map(|_| rng.person()).collect();
        let rescans: Vec<(usize, Vec<f64>)> = (0..3_000).map(|t| { let i = (t * 7919) % n; (i, people[i].iter().map(|x| x + 0.1 * rng.gauss()).collect()) }).collect();
        let fresh: Vec<Vec<f64>> = (0..300).map(|_| rng.person()).collect();
        println!("\n{n} people, {} buckets (lsh_bits {lsh_bits}); 3,000 rescans (σ 0.1), 300 new people", 1u32 << lsh_bits);
        println!("{:>10} {:>7} {:>9} {:>14} {:>11} {:>11} {:>16} {:>10}", "check", "shards", "recall", "copies/record", "avg cmp", "max cmp", "max recs/shard", "false dup");
        for &home_only in &[false, true] {
            for &s in &[1usize, 16, 64, 256] {
                if s > (1 << lsh_bits) { continue; }
                let r = simulate(home_only, lsh_bits, s, &people, &rescans, &fresh);
                println!("{:>10} {:>7} {:>8.2}% {:>14.2} {:>11.1} {:>11} {:>16} {:>10}", if home_only { "home" } else { "probes" }, r.shards, 100.0 * r.recall, r.copies, r.avg_cmp, r.max_cmp, r.max_shard, r.false_dup);
            }
        }
    }
}

/// Recall of the home-bucket check as buckets grow (needed so comparisons stay
/// flat while the population grows), and what a wider probe margin buys back.
#[test]
#[ignore]
fn recall_vs_buckets_and_margin() {
    let mut rng = Rng(7);
    let n = 20_000;
    let people: Vec<Vec<f64>> = (0..n).map(|_| rng.person()).collect();
    let rescans: Vec<Vec<f64>> = (0..3_000).map(|t| people[(t * 7919) % n].iter().map(|x| x + 0.1 * rng.gauss()).collect()).collect();
    println!("\nhome-bucket check, 1 shard; {n} people, 3,000 rescans (σ 0.1)");
    println!("{:>8} {:>8} {:>13} {:>9} {:>14}", "buckets", "margin", "copies (S=∞)", "recall", "probes/record");
    for &bits in &[10u8, 12, 14, 16] {
        for &margin in &[3_000_000u64, 5_000_000, 8_000_000] {
            let mut c = config(bits); c.probe_margin = margin;
            let mut by_bucket: HashMap<u16, Vec<usize>> = HashMap::new();
            let mut probes_total = 0usize;
            for (i, p) in people.iter().enumerate() {
                let (_, probes) = lsh_probes(&c, &fixed(p));
                probes_total += probes.len();
                for b in probes { by_bucket.entry(b).or_default().push(i); }
            }
            let caught = rescans.iter().enumerate().filter(|(t, r)| {
                let (home, _) = lsh_probes(&c, &fixed(r));
                by_bucket.get(&home).map_or(false, |l| l.contains(&((t * 7919) % n)))
            }).count();
            println!("{:>8} {:>7.0}M {:>13.2} {:>8.2}% {:>14.2}", 1u32 << bits, margin as f64 / 1e6,
                     probes_total as f64 / n as f64, 100.0 * caught as f64 / rescans.len() as f64, probes_total as f64 / n as f64);
        }
    }
}
