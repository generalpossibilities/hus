//! Registry logic, independent of the AVM glue so it can be tested natively.
//!
//! A registration is a commitment plus the obfuscated vector `v_obf` that a
//! HUS proof binds to it. The registry rejects a replayed commitment, and a
//! vector closer than `dup_dist_sq` (squared L2) to any stored vector of the
//! same app: that is how one person gets one registration.
//!
//! Comparing against every stored vector does not fit AVM's per-message FUEL
//! cap past a few hundred users, so vectors are bucketed by a sign random
//! projection (LSH): `lsh_bits` ±1 hyperplanes derived from `seed`. A new
//! vector is compared only against its own bucket, plus each bucket reached by
//! flipping a bit whose projection margin is below `probe_margin` (at most
//! MAX_FLIPS of them), so a noisy rescan of the same person near a hyperplane
//! is still found.

use alloc::vec::Vec;

pub const MAGIC: &[u8; 4] = b"HUSR";
pub const VERSION: u8 = 1;
pub const MAX_ATTESTORS: usize = 8;
pub const MAX_LSH_BITS: u8 = 12;
pub const MAX_FLIPS: usize = 4;
/// Records per registry shard. Bounds state size and the exact-replay scan.
pub const MAX_RECORDS: u32 = 2_000;

/// How registrations are authorised until AVM can verify Groth16 natively.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VerifyMode {
    /// Only configured attestors (external signers that checked the proof
    /// off-chain) may register. Every proof stays in the message journal, so
    /// anyone can re-verify it and expose a dishonest attestor.
    Attestor = 0,
    /// Verify the Groth16 proof in the contract, through `hus-zk`. Needs the
    /// native BN254 host functions; without them registration fails (3007).
    NativeGroth16 = 1,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Config {
    pub dim: u16,
    pub lsh_bits: u8,
    pub probe_margin: u64,
    pub dup_dist_sq: u128,
    pub seed: [u8; 32],
    pub mode: VerifyMode,
    pub attestors: Vec<[u8; 32]>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    BadState = 3000,
    BadArgs = 3001,
    NotAttestor = 3002,
    Duplicate = 3003,
    Replay = 3004,
    Full = 3005,
    OutOfRange = 3006,
    NoVerifier = 3007,
    BadProof = 3008,
}

impl Config {
    /// MAGIC | VERSION | dim u16 | lsh_bits u8 | mode u8 | probe_margin u64 |
    /// dup_dist_sq u128 | seed [32] | n u8 | attestors [n × 32]   (all LE)
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(self.len());
        b.extend_from_slice(MAGIC);
        b.push(VERSION);
        b.extend_from_slice(&self.dim.to_le_bytes());
        b.push(self.lsh_bits);
        b.push(self.mode as u8);
        b.extend_from_slice(&self.probe_margin.to_le_bytes());
        b.extend_from_slice(&self.dup_dist_sq.to_le_bytes());
        b.extend_from_slice(&self.seed);
        b.push(self.attestors.len() as u8);
        for a in &self.attestors {
            b.extend_from_slice(a);
        }
        b
    }

    pub fn len(&self) -> usize {
        4 + 1 + 2 + 1 + 1 + 8 + 16 + 32 + 1 + 32 * self.attestors.len()
    }

    pub fn decode(b: &[u8]) -> Result<Config, Error> {
        let e = Error::BadState;
        if b.len() < 66 || &b[0..4] != MAGIC || b[4] != VERSION {
            return Err(e);
        }
        let dim = u16::from_le_bytes([b[5], b[6]]);
        let lsh_bits = b[7];
        let mode = match b[8] {
            0 => VerifyMode::Attestor,
            1 => VerifyMode::NativeGroth16,
            _ => return Err(e),
        };
        let probe_margin = u64::from_le_bytes(b[9..17].try_into().map_err(|_| e)?);
        let dup_dist_sq = u128::from_le_bytes(b[17..33].try_into().map_err(|_| e)?);
        let seed: [u8; 32] = b[33..65].try_into().map_err(|_| e)?;
        let n = b[65] as usize;
        if dim == 0 || lsh_bits > MAX_LSH_BITS || n > MAX_ATTESTORS || b.len() < 66 + 32 * n {
            return Err(e);
        }
        let attestors = (0..n).map(|i| b[66 + 32 * i..98 + 32 * i].try_into().unwrap()).collect();
        Ok(Config { dim, lsh_bits, probe_margin, dup_dist_sq, seed, mode, attestors })
    }

    fn record_len(&self) -> usize {
        32 + 2 + 4 * self.dim as usize
    }
}

/// Parsed state: config, then count u32 LE, then `count` records of
/// commitment [32] | bucket u16 LE | v_obf [dim × i32 LE].
pub struct Registry<'a> {
    pub config: Config,
    pub count: u32,
    records: &'a [u8],
}

pub struct Registration<'a> {
    pub commitment: [u8; 32],
    pub v_obf: Vec<i32>,
    pub proof: &'a [u8],
}

/// The outcome of a successful registration, for the caller and for tests.
#[derive(Debug, PartialEq, Eq)]
pub struct Accepted {
    pub bucket: u16,
    pub probed: usize,
    pub compared: u32,
    pub min_dist_sq: Option<u128>,
}

pub fn initial_state(config: &Config) -> Vec<u8> {
    let mut s = config.encode();
    s.extend_from_slice(&0u32.to_le_bytes());
    s
}

impl<'a> Registry<'a> {
    pub fn parse(state: &'a [u8]) -> Result<Registry<'a>, Error> {
        let config = Config::decode(state)?;
        let at = config.len();
        let count = u32::from_le_bytes(state.get(at..at + 4).ok_or(Error::BadState)?.try_into().unwrap());
        let records = &state[at + 4..];
        if records.len() != count as usize * config.record_len() {
            return Err(Error::BadState);
        }
        Ok(Registry { config, count, records })
    }

    pub fn parse_registration<'m>(&self, args: &'m [u8]) -> Result<Registration<'m>, Error> {
        let dim = self.config.dim as usize;
        if args.len() < 32 + 8 * dim {
            return Err(Error::BadArgs);
        }
        let commitment = args[..32].try_into().unwrap();
        let mut v_obf = Vec::with_capacity(dim);
        for i in 0..dim {
            let o = 32 + 8 * i;
            let v = i64::from_le_bytes(args[o..o + 8].try_into().unwrap());
            v_obf.push(i32::try_from(v).map_err(|_| Error::OutOfRange)?);
        }
        Ok(Registration { commitment, v_obf, proof: &args[32 + 8 * dim..] })
    }

    fn record(&self, i: usize) -> &'a [u8] {
        let n = self.config.record_len();
        &self.records[i * n..(i + 1) * n]
    }

    /// Checks a registration and returns the new state on success.
    pub fn register(&self, reg: &Registration<'_>) -> Result<(Vec<u8>, Accepted), Error> {
        let (record, acc) = self.check(reg)?;
        let mut next = Vec::with_capacity(self.config.len() + 4 + self.records.len() + record.len());
        next.extend_from_slice(&self.config.encode());
        next.extend_from_slice(&(self.count + 1).to_le_bytes());
        next.extend_from_slice(self.records);
        next.extend_from_slice(&record);
        Ok((next, acc))
    }

    /// Byte offset of the record count within the state.
    pub fn count_offset(&self) -> usize {
        self.config.len()
    }

    /// Checks a registration and returns the record to append on success.
    pub fn check(&self, reg: &Registration<'_>) -> Result<(Vec<u8>, Accepted), Error> {
        if self.count >= MAX_RECORDS {
            return Err(Error::Full);
        }
        // A replayed commitment (the same proof sent twice).
        for i in 0..self.count as usize {
            if self.record(i)[..32] == reg.commitment {
                return Err(Error::Replay);
            }
        }
        let (bucket, probes) = lsh_probes(&self.config, &reg.v_obf);
        let mut compared = 0u32;
        let mut min_dist_sq: Option<u128> = None;
        for i in 0..self.count as usize {
            let r = self.record(i);
            let b = u16::from_le_bytes([r[32], r[33]]);
            if !probes.contains(&b) {
                continue;
            }
            compared += 1;
            let d = dist_sq(&reg.v_obf, &r[34..]);
            if d < self.config.dup_dist_sq {
                return Err(Error::Duplicate);
            }
            min_dist_sq = Some(min_dist_sq.map_or(d, |m| m.min(d)));
        }
        let mut record = Vec::with_capacity(self.config.record_len());
        record.extend_from_slice(&reg.commitment);
        record.extend_from_slice(&bucket.to_le_bytes());
        for v in &reg.v_obf {
            record.extend_from_slice(&v.to_le_bytes());
        }
        Ok((record, Accepted { bucket, probed: probes.len(), compared, min_dist_sq }))
    }
}

/// Squared L2 distance between a vector and a stored record (i32 LE).
fn dist_sq(a: &[i32], stored: &[u8]) -> u128 {
    let mut s: u128 = 0;
    for (i, x) in a.iter().enumerate() {
        let y = i32::from_le_bytes(stored[4 * i..4 * i + 4].try_into().unwrap());
        let d = (*x as i64 - y as i64).unsigned_abs() as u128;
        s += d * d;
    }
    s
}

/// The HUS verifying key (production circuit: 129 public inputs, the
/// commitment then `v_obf`), raw format, see hus_zk::groth16.
#[cfg(feature = "groth16")]
pub const HUS_VK: &[u8] = include_bytes!("../../hus-zk/vectors/vk_raw.bin");

/// Checks the registration's Groth16 proof (`proof` = A | B | C, 256 bytes)
/// against the HUS key, with the commitment and `v_obf` as public inputs.
#[cfg(feature = "groth16")]
pub fn verify_proof(reg: &Registration<'_>) -> Result<(), Error> {
    use hus_zk::groth16::{verify, VerifyingKey};
    let vk = VerifyingKey::parse(HUS_VK).map_err(|_| Error::BadState)?;
    let mut inputs = Vec::with_capacity(1 + reg.v_obf.len());
    inputs.push(reg.commitment);
    inputs.extend(reg.v_obf.iter().map(|v| hus_zk::scalar_from_i64(*v as i64)));
    match verify(&vk, &inputs, reg.proof) {
        Ok(true) => Ok(()),
        Ok(false) => Err(Error::BadProof),
        Err(_) => Err(Error::BadArgs),
    }
}

/// SplitMix64: the deterministic stream the hyperplanes are drawn from.
struct SplitMix(u64);
impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// Home bucket of `v`, and the buckets to probe: the home bucket and every
/// combination of flips of the (at most MAX_FLIPS) least-certain bits whose
/// margin is below `probe_margin`.
pub fn lsh_probes(c: &Config, v: &[i32]) -> (u16, Vec<u16>) {
    let mut rng = SplitMix(u64::from_le_bytes(c.seed[..8].try_into().unwrap())
        ^ u64::from_le_bytes(c.seed[8..16].try_into().unwrap()).rotate_left(17)
        ^ u64::from_le_bytes(c.seed[16..24].try_into().unwrap()).rotate_left(34)
        ^ u64::from_le_bytes(c.seed[24..32].try_into().unwrap()).rotate_left(51));
    let mut home: u16 = 0;
    let mut weak: Vec<(u64, u8)> = Vec::new(); // (|margin|, bit)
    for bit in 0..c.lsh_bits {
        let mut acc: i64 = 0;
        let mut word = 0u64;
        for (i, x) in v.iter().enumerate() {
            if i % 64 == 0 {
                word = rng.next();
            }
            if (word >> (i % 64)) & 1 == 1 { acc += *x as i64 } else { acc -= *x as i64 }
        }
        if acc >= 0 {
            home |= 1 << bit;
        }
        let m = acc.unsigned_abs();
        if m < c.probe_margin {
            weak.push((m, bit));
        }
    }
    weak.sort_unstable();
    weak.truncate(MAX_FLIPS);
    let mut probes = alloc::vec![home];
    for mask in 1u32..(1 << weak.len()) {
        let mut b = home;
        for (k, (_, bit)) in weak.iter().enumerate() {
            if mask & (1 << k) != 0 {
                b ^= 1 << bit;
            }
        }
        probes.push(b);
    }
    (home, probes)
}
