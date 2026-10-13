use hus_registry::registry::*;

const DIM: usize = 128;
const SCALE: f64 = 1e6;

struct Rng(u64);
impl Rng {
    fn u(&mut self) -> f64 { self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17; (self.0 >> 11) as f64 / (1u64 << 53) as f64 }
    fn gauss(&mut self) -> f64 { let (a, b) = (self.u().max(1e-300), self.u()); (-2.0 * a.ln()).sqrt() * (6.283185307179586 * b).cos() }
    fn person(&mut self) -> Vec<f64> { (0..DIM).map(|_| self.gauss()).collect() }
}

/// HUS-like config: duplicate when L2 < 5.0 (×10⁶ fixed point), 256 buckets.
fn config(attestors: Vec<[u8; 32]>) -> Config {
    Config { dim: DIM as u16, lsh_bits: 8, cell: 1, quant_step: 62_500, probe_margin: 3_000_000, dup_dist_sq: 25_000_000_000_000,
             seed: [7; 32], mode: VerifyMode::Attestor, attestors }
}

fn args(commitment: [u8; 32], v: &[f64]) -> Vec<u8> {
    let mut b = commitment.to_vec();
    for x in v { b.extend_from_slice(&((x * SCALE).round() as i64).to_le_bytes()); }
    b.extend_from_slice(b"proof");
    b
}

fn commit(i: u64) -> [u8; 32] { let mut c = [0u8; 32]; c[..8].copy_from_slice(&i.to_le_bytes()); c[31] = 1; c }

fn try_register(state: &mut Vec<u8>, c: [u8; 32], v: &[f64]) -> Result<Accepted, Error> {
    let a = args(c, v);
    let reg = Registry::parse(state).unwrap();
    let r = reg.parse_registration(&a)?;
    let (next, acc) = reg.register(&r)?;
    *state = next;
    Ok(acc)
}

#[test]
fn config_round_trips() {
    let c = config(vec![[1; 32], [2; 32]]);
    assert_eq!(Config::decode(&c.encode()).unwrap(), c);
    assert!(Config::decode(&c.encode()[..60]).is_err());
}

#[test]
fn one_person_one_registration() {
    let mut rng = Rng(42);
    let mut state = initial_state(&config(vec![]));
    let people: Vec<Vec<f64>> = (0..1_500).map(|_| rng.person()).collect();
    for (i, p) in people.iter().enumerate() {
        try_register(&mut state, commit(i as u64), p).unwrap_or_else(|e| panic!("person {i} rejected: {e:?}"));
    }
    // Rescans of registered people (sensor noise σ = 0.1 per coordinate) must be caught,
    // with a fresh commitment each time.
    let (mut caught, trials) = (0, 3_000);
    for t in 0..trials {
        let p = &people[t % people.len()];
        let rescan: Vec<f64> = p.iter().map(|x| x + 0.1 * rng.gauss()).collect();
        match try_register(&mut state.clone(), commit(10_000 + t as u64), &rescan) {
            Err(Error::Duplicate) => caught += 1,
            Ok(_) => {}
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    assert_eq!(Registry::parse(&state).unwrap().count, 1_500);
    // Cost for a genuinely new person: how many stored vectors it is compared with.
    let (mut total, mut worst) = (0u32, 0u32);
    for t in 0..200 {
        let a = try_register(&mut state.clone(), commit(50_000 + t), &rng.person()).unwrap();
        total += a.compared;
        worst = worst.max(a.compared);
    }
    println!("rescans caught: {caught}/{trials}; new person compared with avg {} / worst {worst} of 1500", total / 200);
    assert!(caught as f64 >= 0.99 * trials as f64, "recall too low: {caught}/{trials}");
}

#[test]
fn replay_and_attestor_and_range() {
    let mut rng = Rng(7);
    let mut state = initial_state(&config(vec![]));
    let p = rng.person();
    try_register(&mut state, commit(1), &p).unwrap();
    let q = rng.person();
    assert_eq!(try_register(&mut state, commit(1), &q), Err(Error::Replay));
    let mut big = q.clone();
    big[0] = 1e9; // ×10⁶ overflows i32
    assert_eq!(try_register(&mut state, commit(2), &big), Err(Error::OutOfRange));
    assert_eq!(Registry::parse(&state).unwrap().parse_registration(&[0u8; 40]).err(), Some(Error::BadArgs));
}

#[test]
fn probes_flip_only_weak_bits() {
    let c = config(vec![]);
    let v: Vec<i32> = (0..DIM as i32).map(|i| (i - 64) * 100_000).collect();
    let (home, probes) = lsh_probes(&c, &v);
    assert_eq!(probes[0], home);
    assert!(probes.len() <= 1 << MAX_FLIPS);
    let mut sorted = probes.clone(); sorted.sort(); sorted.dedup();
    assert_eq!(sorted.len(), probes.len());
}

/// The NativeGroth16 path with the real HUS vectors (pure-WASM backend here).
#[cfg(feature = "groth16")]
#[test]
fn groth16_registration_with_real_proof() {
    let good = include_bytes!("../../hus-zk/vectors/good_raw.bin");
    let bad = include_bytes!("../../hus-zk/vectors/bad_raw.bin");
    let mut c = config(vec![]);
    c.mode = VerifyMode::NativeGroth16;
    let state = initial_state(&c);
    let reg = Registry::parse(&state).unwrap();
    // good_raw: proof 256 | commitment 32 | v_obf 128 × i64 → registration bytes.
    let args = |raw: &[u8]| { let mut a = raw[256..288].to_vec(); a.extend_from_slice(&raw[288..]); a.extend_from_slice(&raw[..256]); a };
    let (ga, ba) = (args(good), args(bad));
    assert_eq!(verify_proof(&reg.parse_registration(&ga).unwrap()), Ok(()));
    assert_eq!(verify_proof(&reg.parse_registration(&ba).unwrap()), Err(Error::BadProof));
}

#[test]
fn compact_records() {
    let mut rng = Rng(11);
    let c = config(vec![]);
    assert_eq!(c.record_len(), 146);
    let mut state = initial_state(&c);
    let p = rng.person();
    try_register(&mut state, commit(1), &p).unwrap();
    assert_eq!(state.len(), c.len() + 4 + 146);
    // An exact rescan is a duplicate despite the rounding of the stored copy.
    assert_eq!(try_register(&mut state.clone(), commit(2), &p), Err(Error::Duplicate));
    // Values beyond the 1-byte range (±8.0 at 1/16) are clamped, not rejected.
    let mut far = rng.person();
    far[0] = 1_000.0;
    try_register(&mut state, commit(3), &far).unwrap();
}

#[test]
fn exact_cells_keep_old_behaviour() {
    let mut rng = Rng(5);
    let mut c = config(vec![]);
    (c.cell, c.quant_step) = (4, 1);
    assert_eq!(c.record_len(), 16 + 2 + 512);
    let mut state = initial_state(&c);
    let people: Vec<Vec<f64>> = (0..300).map(|_| rng.person()).collect();
    for (i, p) in people.iter().enumerate() {
        try_register(&mut state, commit(i as u64), p).unwrap();
    }
    let caught = (0..300).filter(|&t| {
        let rescan: Vec<f64> = people[t].iter().map(|x| x + 0.1 * rng.gauss()).collect();
        try_register(&mut state.clone(), commit(1_000 + t as u64), &rescan) == Err(Error::Duplicate)
    }).count();
    assert!(caught >= 297, "{caught}/300");
}

#[test]
fn full_shard_still_rejects_duplicates() {
    let mut rng = Rng(3);
    let mut state = initial_state(&config(vec![]));
    let people: Vec<Vec<f64>> = (0..MAX_RECORDS).map(|_| rng.person()).collect();
    for (i, p) in people.iter().enumerate() {
        try_register(&mut state, commit(i as u64), p).unwrap();
    }
    assert_eq!(try_register(&mut state.clone(), commit(1), &rng.person()), Err(Error::Replay));
    assert_eq!(try_register(&mut state.clone(), commit(9_999), &people[7]), Err(Error::Duplicate));
    assert_eq!(try_register(&mut state.clone(), commit(9_998), &rng.person()), Err(Error::Full));
}
