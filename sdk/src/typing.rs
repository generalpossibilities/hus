//! Typing enrolment: the person types a code derived from the verifier's
//! single-use challenge on the app's own keypad, and their key timing
//! (how long each key is held, the gaps between keys) is the biometric.
//!
//! The app must draw the keypad itself and report each key's press and
//! release from touch events. A system keyboard can't be used: it reports no
//! press/release times and allows paste.
//!
//! Liveness here means a person typed it just now: the exact code (unknown
//! before the challenge), within time limits, with human timing. Uniform
//! gaps, superhuman speed and identical hold times are refused. Typing
//! rhythm tells people apart only weakly; it adds to the face, it doesn't
//! replace it.

use alloc::vec::Vec;

use crate::config::Modality;
use crate::enroll::{seal, EnrollError, Enrollment};
use crate::prover::ProverKey;
use crate::extract::{Extractor, KeystrokeExtractor};

#[derive(Debug, Clone, Copy)]
pub struct TypingConfig {
    pub digits: usize,
    pub min_hold_ms: u64,
    pub max_hold_ms: u64,
    /// Shortest gap between two presses.
    pub min_gap_ms: u64,
    /// Longest gap between two presses.
    pub max_gap_ms: u64,
    pub max_total_ms: u64,
    /// Lowest coefficient of variation of the press-to-press gaps.
    pub min_gap_cv: f32,
    /// Lowest standard deviation of the hold times.
    pub min_hold_std_ms: f32,
    /// Wrong keys allowed before the session fails (each one restarts the code).
    pub max_restarts: u32,
}

impl Default for TypingConfig {
    fn default() -> Self {
        TypingConfig {
            digits: 12,
            min_hold_ms: 20,
            max_hold_ms: 800,
            min_gap_ms: 50,
            max_gap_ms: 5_000,
            max_total_ms: 120_000,
            min_gap_cv: 0.12,
            min_hold_std_ms: 4.0,
            max_restarts: 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypingFailure {
    TooManyMistakes,
    BadTiming,
    TooSlow,
    Robotic,
}

impl TypingFailure {
    pub fn id(self) -> u32 {
        match self {
            TypingFailure::TooManyMistakes => 1,
            TypingFailure::BadTiming => 2,
            TypingFailure::TooSlow => 3,
            TypingFailure::Robotic => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypingPhase {
    Typing,
    Done,
    Failed(TypingFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypingStatus {
    pub phase: TypingPhase,
    /// Correct keys typed in the current attempt.
    pub typed: usize,
    pub total: usize,
    /// The last key was wrong and the code starts again.
    pub restarted: bool,
}

/// The code for one challenge: `SHA-256("hus.typing.v1" ‖ challenge)`,
/// one decimal digit per byte (`byte % 10`).
pub fn code_for(challenge: &[u8], digits: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"hus.typing.v1");
    h.update(challenge);
    let d = h.finalize();
    d.iter().take(digits.clamp(4, 32)).map(|b| b'0' + b % 10).collect()
}

#[derive(Debug, Clone, Copy)]
struct Key {
    press: u64,
    release: u64,
}

pub struct TypingEnrollment {
    cfg: TypingConfig,
    challenge: Vec<u8>,
    code: Vec<u8>,
    keys: Vec<Key>,
    first_press: Option<u64>,
    last_press: Option<u64>,
    restarts: u32,
    restarted: bool,
    phase: TypingPhase,
}

impl TypingEnrollment {
    pub fn new(challenge: &[u8], cfg: TypingConfig) -> Result<Self, EnrollError> {
        if challenge.len() < 16 {
            return Err(EnrollError::BadChallenge);
        }
        Ok(TypingEnrollment {
            code: code_for(challenge, cfg.digits),
            cfg,
            challenge: challenge.to_vec(),
            keys: Vec::new(),
            first_press: None,
            last_press: None,
            restarts: 0,
            restarted: false,
            phase: TypingPhase::Typing,
        })
    }

    /// The digits to type, as ASCII.
    pub fn code(&self) -> &[u8] {
        &self.code
    }

    pub fn status(&self) -> TypingStatus {
        TypingStatus { phase: self.phase, typed: self.keys.len(), total: self.code.len(), restarted: self.restarted }
    }

    fn fail(&mut self, f: TypingFailure) -> TypingStatus {
        self.phase = TypingPhase::Failed(f);
        self.keys.clear();
        self.status()
    }

    /// One key from the app's keypad: the ASCII character and when it was
    /// pressed and released (milliseconds, one clock).
    pub fn push(&mut self, key: u8, press_ms: u64, release_ms: u64) -> TypingStatus {
        if self.phase != TypingPhase::Typing {
            return self.status();
        }
        self.restarted = false;
        let c = self.cfg;
        if release_ms < press_ms + c.min_hold_ms || release_ms > press_ms + c.max_hold_ms {
            return self.fail(TypingFailure::BadTiming);
        }
        if let Some(last) = self.last_press {
            if press_ms < last + c.min_gap_ms {
                return self.fail(TypingFailure::BadTiming);
            }
            if press_ms > last + c.max_gap_ms {
                return self.fail(TypingFailure::TooSlow);
            }
        }
        let first = *self.first_press.get_or_insert(press_ms);
        if press_ms - first > c.max_total_ms {
            return self.fail(TypingFailure::TooSlow);
        }
        self.last_press = Some(press_ms);
        if key != self.code[self.keys.len()] {
            self.restarts += 1;
            if self.restarts > c.max_restarts {
                return self.fail(TypingFailure::TooManyMistakes);
            }
            self.keys.clear();
            self.restarted = true;
            return self.status();
        }
        self.keys.push(Key { press: press_ms, release: release_ms });
        if self.keys.len() == self.code.len() {
            if !self.human() {
                return self.fail(TypingFailure::Robotic);
            }
            self.phase = TypingPhase::Done;
        }
        self.status()
    }

    fn human(&self) -> bool {
        let gaps: Vec<f32> = self.keys.windows(2).map(|w| (w[1].press - w[0].press) as f32).collect();
        let holds: Vec<f32> = self.keys.iter().map(|k| (k.release - k.press) as f32).collect();
        let (gm, gs) = mean_std(&gaps);
        let (_, hs) = mean_std(&holds);
        gm > 0.0 && gs / gm >= self.cfg.min_gap_cv && hs >= self.cfg.min_hold_std_ms
    }

    /// Extract the timing features of the typed code, project, prove and
    /// compute the attestation challenge. Only after the code was typed.
    pub fn finish(
        &self,
        pk: &ProverKey,
        projection_seed: &[u8; 32],
        owner_pubkey: &[u8],
        app_address: &str,
    ) -> Result<Enrollment, EnrollError> {
        if self.phase != TypingPhase::Done {
            return Err(EnrollError::NotLive);
        }
        let mut data = Vec::with_capacity(self.keys.len() * 20);
        for (k, code) in self.keys.iter().zip(&self.code) {
            data.extend_from_slice(&(*code as u32).to_le_bytes());
            data.extend_from_slice(&k.press.to_le_bytes());
            data.extend_from_slice(&k.release.to_le_bytes());
        }
        let first = self.keys[0].press;
        let last = self.keys[self.keys.len() - 1].release;
        let capture = crate::capture::RawCapture {
            meta: crate::capture::CaptureMeta {
                modality: Modality::Keystroke,
                width: 0,
                height: 0,
                sample_rate: 0,
                timestamp_ms: first,
                duration_ms: (last - first) as u32,
            },
            data,
        };
        let embedding = KeystrokeExtractor
            .extract(&capture)
            .map_err(|e| EnrollError::Model(alloc::format!("{e:?}")))?;
        seal(&self.challenge, &embedding.vector, Modality::Keystroke, pk, projection_seed, owner_pubkey, app_address)
    }
}

fn mean_std(v: &[f32]) -> (f32, f32) {
    if v.is_empty() {
        return (0.0, 0.0);
    }
    let m = v.iter().sum::<f32>() / v.len() as f32;
    let var = v.iter().map(|x| (x - m) * (x - m)).sum::<f32>() / v.len() as f32;
    (m, libm::sqrtf(var))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHALLENGE: [u8; 16] = [5u8; 16];

    // A person: gaps and holds wander.
    fn type_code(t: &mut TypingEnrollment, start: u64) -> TypingStatus {
        let code = t.code().to_vec();
        let mut now = start;
        let mut s = t.status();
        for (i, c) in code.iter().enumerate() {
            now += 180 + (i as u64 * 37 % 140);
            s = t.push(*c, now, now + 70 + (i as u64 * 13 % 50));
        }
        s
    }

    #[test]
    fn the_code_depends_on_the_challenge() {
        let a = code_for(&CHALLENGE, 12);
        assert_eq!(a.len(), 12);
        assert!(a.iter().all(|c| c.is_ascii_digit()));
        assert_ne!(a, code_for(&[6u8; 16], 12));
        assert!(TypingEnrollment::new(&[1; 4], TypingConfig::default()).is_err());
    }

    #[test]
    fn a_person_typing_the_code_passes() {
        let mut t = TypingEnrollment::new(&CHALLENGE, TypingConfig::default()).unwrap();
        assert_eq!(type_code(&mut t, 1_000).phase, TypingPhase::Done);
    }

    #[test]
    fn a_wrong_key_restarts_and_too_many_fail() {
        let mut t = TypingEnrollment::new(&CHALLENGE, TypingConfig::default()).unwrap();
        let wrong = if t.code()[0] == b'0' { b'1' } else { b'0' };
        let s = t.push(wrong, 1_000, 1_080);
        assert!(s.restarted && s.typed == 0 && s.phase == TypingPhase::Typing);
        assert_eq!(type_code(&mut t, 1_500).phase, TypingPhase::Done);

        let mut t = TypingEnrollment::new(&CHALLENGE, TypingConfig::default()).unwrap();
        let mut now = 1_000;
        for _ in 0..4 {
            now += 300;
            t.push(wrong, now, now + 80);
        }
        assert_eq!(t.status().phase, TypingPhase::Failed(TypingFailure::TooManyMistakes));
    }

    #[test]
    fn a_metronome_is_refused() {
        let mut t = TypingEnrollment::new(&CHALLENGE, TypingConfig::default()).unwrap();
        let code = t.code().to_vec();
        for (i, c) in code.iter().enumerate() {
            let p = 1_000 + i as u64 * 200;
            t.push(*c, p, p + 80);
        }
        assert_eq!(t.status().phase, TypingPhase::Failed(TypingFailure::Robotic));
    }

    #[test]
    fn impossible_timing_is_refused() {
        let mut t = TypingEnrollment::new(&CHALLENGE, TypingConfig::default()).unwrap();
        let c = t.code().to_vec();
        t.push(c[0], 1_000, 1_005);
        assert_eq!(t.status().phase, TypingPhase::Failed(TypingFailure::BadTiming));

        let mut t = TypingEnrollment::new(&CHALLENGE, TypingConfig::default()).unwrap();
        t.push(c[0], 1_000, 1_080);
        t.push(c[1], 1_010, 1_090);
        assert_eq!(t.status().phase, TypingPhase::Failed(TypingFailure::BadTiming));

        let mut t = TypingEnrollment::new(&CHALLENGE, TypingConfig::default()).unwrap();
        t.push(c[0], 1_000, 1_080);
        t.push(c[1], 9_000, 9_080);
        assert_eq!(t.status().phase, TypingPhase::Failed(TypingFailure::TooSlow));
    }

    #[test]
    fn finish_needs_the_whole_code_and_gives_a_request_the_verifier_accepts() {
        let mut t = TypingEnrollment::new(&CHALLENGE, TypingConfig::default()).unwrap();
        let pk = crate::enroll::tests::pk();
        assert_eq!(t.finish(&pk, &[1; 32], &[2; 32], "0:ab").unwrap_err(), EnrollError::NotLive);
        type_code(&mut t, 1_000);
        let vk = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../keep/vk.bin")).unwrap();
        let r = t.finish(&pk, &[3; 32], &[9; 32], "0:ab").unwrap();
        assert_eq!(r.modality_id, Modality::Keystroke.id());
        assert!(crate::verify_projected(&vk, &r.proof, &r.commitment, &r.v_obf, &r.binding).unwrap());
    }
}
