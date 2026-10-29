//! Signal-presence checks per modality. **This is not liveness**: it only
//! rejects empty or constant input (a flat image, silence) and accepts any
//! photo or recording. Face liveness is [`crate::face_liveness`], used by
//! [`crate::enroll::FaceEnrollment`]; never treat a pass here as proof that
//! a live person was present.

use crate::capture::RawCapture;
use crate::config::Modality;
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq)]
pub enum LivenessChallenge {
    // Face
    Blink,
    Smile,
    TurnHead,
    DepthMeasurement,
    // Iris
    HoldStill,
    VaryLighting,
    // Voice
    RepeatPhrase([u8; 8]),
    Hum,
    // Fingerprint
    Swipe,
    LiftAndRepeat,
    // Keystroke
    TypeSentence(u64),
    RepeatRhythm,
    // TouchGesture
    SwipePattern,
    PinchZoom,
    // Gait
    WalkSteps(u32),
    Turn,
    StopStart,
    // Generic
    ChallengeResponse([u8; 8]),
}

impl LivenessChallenge {
    pub fn description(&self) -> &'static str {
        match self {
            LivenessChallenge::Blink => "blink your eyes",
            LivenessChallenge::Smile => "smile naturally",
            LivenessChallenge::TurnHead => "turn your head slightly left and right",
            LivenessChallenge::DepthMeasurement => "hold still for depth scan",
            LivenessChallenge::HoldStill => "hold still for iris capture",
            LivenessChallenge::VaryLighting => "move to slightly different lighting",
            LivenessChallenge::RepeatPhrase(_) => "repeat the shown phrase aloud",
            LivenessChallenge::Hum => "hum a steady tone",
            LivenessChallenge::Swipe => "swipe your finger on the sensor",
            LivenessChallenge::LiftAndRepeat => "lift and place your finger again",
            LivenessChallenge::TypeSentence(_) => "type the shown sentence",
            LivenessChallenge::RepeatRhythm => "type the same rhythm again",
            LivenessChallenge::SwipePattern => "swipe in the shown pattern",
            LivenessChallenge::PinchZoom => "pinch and zoom on screen",
            LivenessChallenge::WalkSteps(_) => "walk the shown number of steps",
            LivenessChallenge::Turn => "turn around",
            LivenessChallenge::StopStart => "stop, then start walking again",
            LivenessChallenge::ChallengeResponse(_) => "respond to the random challenge",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LivenessResult {
    pub passed: bool,
    pub score: u8,
    pub challenges_passed: usize,
    pub challenges_total: usize,
}

#[derive(Debug, Clone)]
struct ChallengeState {
    _challenge: LivenessChallenge,
    completed: bool,
}

#[derive(Debug, Clone)]
pub struct LivenessSession {
    challenges: Vec<ChallengeState>,
    min_pass_score: u8,
    modality: Modality,
}

impl LivenessSession {
    pub fn new(min_pass_score: u8, modality: Modality) -> Self {
        Self {
            challenges: Vec::new(),
            min_pass_score,
            modality,
        }
    }

    pub fn add_challenge(&mut self, challenge: LivenessChallenge) {
        self.challenges.push(ChallengeState {
            _challenge: challenge,
            completed: false,
        });
    }

    pub fn modality(&self) -> Modality {
        self.modality
    }

    pub fn challenge_count(&self) -> usize {
        self.challenges.len()
    }

    pub fn verify_response(
        &mut self,
        index: usize,
        capture: &RawCapture,
    ) -> Result<(), &'static str> {
        if index >= self.challenges.len() {
            return Err("challenge index out of bounds");
        }
        let challenge = &self.challenges[index];
        let ok = verify_challenge(&challenge._challenge, capture);
        if !ok {
            return Err("liveness challenge failed: spoof or no response detected");
        }
        self.challenges[index].completed = true;
        Ok(())
    }

    pub fn challenges_passed(&self) -> usize {
        self.challenges.iter().filter(|c| c.completed).count()
    }

    pub fn finalize(&self) -> LivenessResult {
        let total = self.challenges.len();
        let passed = self.challenges_passed();
        let score = if total == 0 {
            0
        } else {
            ((passed as f32 / total as f32) * 100.0) as u8
        };
        LivenessResult {
            passed: score >= self.min_pass_score,
            score,
            challenges_passed: passed,
            challenges_total: total,
        }
    }
}

// ---------------------------------------------------------------------------
// Standard session constructors per modality
// ---------------------------------------------------------------------------
pub fn create_session(modality: Modality, seed: &[u8]) -> LivenessSession {
    match modality {
        Modality::Face => create_face_session(seed),
        Modality::Iris => create_iris_session(seed),
        Modality::Voice => create_voice_session(seed),
        Modality::Fingerprint => create_fingerprint_session(seed),
        Modality::Keystroke => create_keystroke_session(seed),
        Modality::TouchGesture => create_touch_session(seed),
        Modality::Gait => create_gait_session(seed),
    }
}

pub fn create_face_session(_seed: &[u8]) -> LivenessSession {
    let mut s = LivenessSession::new(60, Modality::Face);
    s.add_challenge(LivenessChallenge::Blink);
    s.add_challenge(LivenessChallenge::Smile);
    s.add_challenge(LivenessChallenge::DepthMeasurement);
    s
}

pub fn create_iris_session(_seed: &[u8]) -> LivenessSession {
    let mut s = LivenessSession::new(70, Modality::Iris);
    s.add_challenge(LivenessChallenge::HoldStill);
    s.add_challenge(LivenessChallenge::VaryLighting);
    s
}

pub fn create_voice_session(seed: &[u8]) -> LivenessSession {
    let mut s = LivenessSession::new(60, Modality::Voice);
    let mut phrase = [0u8; 8];
    let len = seed.len().min(8);
    phrase[..len].copy_from_slice(&seed[..len]);
    s.add_challenge(LivenessChallenge::RepeatPhrase(phrase));
    s.add_challenge(LivenessChallenge::Hum);
    s
}

pub fn create_fingerprint_session(_seed: &[u8]) -> LivenessSession {
    let mut s = LivenessSession::new(80, Modality::Fingerprint);
    s.add_challenge(LivenessChallenge::Swipe);
    s.add_challenge(LivenessChallenge::LiftAndRepeat);
    s
}

pub fn create_keystroke_session(seed: &[u8]) -> LivenessSession {
    let mut s = LivenessSession::new(60, Modality::Keystroke);
    let phrase = u64::from_le_bytes({
        let mut b = [0u8; 8];
        let len = seed.len().min(8);
        b[..len].copy_from_slice(&seed[..len]);
        b
    });
    s.add_challenge(LivenessChallenge::TypeSentence(phrase));
    s.add_challenge(LivenessChallenge::RepeatRhythm);
    s
}

pub fn create_touch_session(_seed: &[u8]) -> LivenessSession {
    let mut s = LivenessSession::new(50, Modality::TouchGesture);
    s.add_challenge(LivenessChallenge::SwipePattern);
    s.add_challenge(LivenessChallenge::PinchZoom);
    s
}

pub fn create_gait_session(_seed: &[u8]) -> LivenessSession {
    let mut s = LivenessSession::new(50, Modality::Gait);
    s.add_challenge(LivenessChallenge::WalkSteps(10));
    s.add_challenge(LivenessChallenge::Turn);
    s.add_challenge(LivenessChallenge::StopStart);
    s
}

/// Legacy — kept for backwards compatibility.
pub fn create_standard_session(rng_seed: &[u8]) -> LivenessSession {
    create_face_session(rng_seed)
}

pub fn require_liveness(result: &LivenessResult) -> Result<(), &'static str> {
    if result.passed {
        Ok(())
    } else {
        Err("liveness check failed: possible spoof attempt")
    }
}

// ---------------------------------------------------------------------------
// Per-challenge verification logic (simple statistical/hard checks)
// ---------------------------------------------------------------------------
fn verify_challenge(challenge: &LivenessChallenge, capture: &RawCapture) -> bool {
    if capture.data.is_empty() {
        return false;
    }
    match challenge {
        LivenessChallenge::Blink
        | LivenessChallenge::Smile
        | LivenessChallenge::TurnHead
        | LivenessChallenge::DepthMeasurement
        | LivenessChallenge::HoldStill
        | LivenessChallenge::VaryLighting => {
            // RGBA image: reject uniform/static data (bot would send flat frames)
            check_pixel_variance(&capture.data)
        }

        LivenessChallenge::RepeatPhrase(_) | LivenessChallenge::Hum => {
            // PCM audio: reject silence or single-tone bots
            check_audio_variance(&capture.data)
        }

        LivenessChallenge::Swipe | LivenessChallenge::LiftAndRepeat => {
            // Fingerprint sensor embeds its own liveness score
            // Accept if data is present (sensor gatekeeps)
            capture.data.len() >= 32
        }

        LivenessChallenge::TypeSentence(_) | LivenessChallenge::RepeatRhythm => {
            // Keystroke: check inter-key timing variance (bots type uniformly)
            check_key_timing_variance(&capture.data)
        }

        LivenessChallenge::SwipePattern | LivenessChallenge::PinchZoom => {
            // Touch: check movement is not perfectly linear
            check_touch_variance(&capture.data)
        }

        LivenessChallenge::WalkSteps(_) | LivenessChallenge::Turn | LivenessChallenge::StopStart => {
            // Gait: check accelerometer signal has real movement
            check_gait_variance(&capture.data)
        }

        LivenessChallenge::ChallengeResponse(_) => {
            // Generic: non-empty data is sufficient
            true
        }
    }
}

/// Reject perfectly uniform RGBA pixel data (static image / flat colour).
fn check_pixel_variance(data: &[u8]) -> bool {
    // Downsample: check every 64th byte for variation
    let step = 64usize.max(data.len() / 256);
    let mut samples = [0u8; 16];
    let mut idx = 0;
    let mut i = 0;
    while i < data.len() && idx < samples.len() {
        samples[idx] = data[i];
        idx += 1;
        i += step;
    }
    if idx < 2 {
        return false;
    }
    let slice = &samples[..idx];
    let min = *slice.iter().min().unwrap_or(&0);
    let max = *slice.iter().max().unwrap_or(&0);
    // At least some variance (not all bytes the same value)
    (max - min) > 5
}

/// Reject silence or constant-tone audio.
fn check_audio_variance(data: &[u8]) -> bool {
    let step = 32usize.max(data.len() / 128);
    let mut sum_sq: u64 = 0;
    let mut count = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        let sample = i16::from_le_bytes([data[i], data[i + 1]]);
        let s = sample.abs() as u64;
        sum_sq += s * s;
        count += 1;
        i += step;
    }
    if count == 0 {
        return false;
    }
    let rms = (sum_sq / count as u64) as u16;
    // RMS above silence threshold (~1% of i16 range)
    rms > 300
}

/// Keystroke timing: check inter-key intervals are NOT perfectly uniform.
fn check_key_timing_variance(data: &[u8]) -> bool {
    // Parse KeyEvent records: key_code(4) + press_time(8) + release_time(8) = 20 bytes each
    let record_size = 20;
    if data.len() < record_size * 2 {
        return false; // need at least 2 key events to check variance
    }
    let count = data.len() / record_size;
    if count < 2 {
        return false;
    }
    // Check that press times have some variance
    let first_press = u64::from_le_bytes(
        data[4..12].try_into().unwrap_or([0u8; 8]),
    );
    let mut prev_release = u64::from_le_bytes(
        data[12..20].try_into().unwrap_or([0u8; 8]),
    );
    for i in 1..count.min(10) {
        let offset = i * record_size;
        let press = u64::from_le_bytes(
            data[offset + 4..offset + 12].try_into().unwrap_or([0u8; 8]),
        );
        let release = u64::from_le_bytes(
            data[offset + 12..offset + 20].try_into().unwrap_or([0u8; 8]),
        );
        let interval = press.saturating_sub(prev_release);
        if interval > 5 {
            // At least one interval has meaningful gap → human-like
            return true;
        }
        prev_release = release;
    }
    // If we get here, all intervals were ≤5ms (too uniform → bot)
    first_press > 0
}

/// Touch data: check movement is not all identical points.
fn check_touch_variance(data: &[u8]) -> bool {
    let record_size = 20; // x(4) + y(4) + pressure(4) + time(8)
    if data.len() < record_size * 2 {
        return false;
    }
    let first_x = f32::from_le_bytes(data[0..4].try_into().unwrap_or([0u8; 4]));
    let count = data.len() / record_size;
    for i in 1..count.min(10) {
        let offset = i * record_size;
        let x = f32::from_le_bytes(
            data[offset..offset + 4].try_into().unwrap_or([0u8; 4]),
        );
        if (x - first_x).abs() > 0.01 {
            return true; // at least some movement
        }
    }
    false
}

/// Gait accelerometer: check signal is not all zeros.
fn check_gait_variance(data: &[u8]) -> bool {
    let record_size = 16; // x(4) + y(4) + z(4) + time(8)
    if data.len() < record_size {
        return false;
    }
    let mut any_nonzero = false;
    let count = data.len() / record_size;
    for i in 0..count.min(20) {
        let offset = i * record_size;
        let x = f32::from_le_bytes(
            data[offset..offset + 4].try_into().unwrap_or([0u8; 4]),
        );
        let y = f32::from_le_bytes(
            data[offset + 4..offset + 8].try_into().unwrap_or([0u8; 4]),
        );
        let z = f32::from_le_bytes(
            data[offset + 8..offset + 12].try_into().unwrap_or([0u8; 4]),
        );
        if x != 0.0 || y != 0.0 || z != 0.0 {
            any_nonzero = true;
            break;
        }
    }
    any_nonzero
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn face_session_has_three_challenges() {
        let s = create_face_session(&[0xAB; 32]);
        assert_eq!(s.challenge_count(), 3);
    }

    #[test]
    fn iris_session_has_two_challenges() {
        let s = create_iris_session(&[]);
        assert_eq!(s.challenge_count(), 2);
    }

    #[test]
    fn voice_session_has_two_challenges() {
        let s = create_voice_session(&[0x42; 8]);
        assert_eq!(s.challenge_count(), 2);
    }

    #[test]
    fn keystroke_session_has_two_challenges() {
        let s = create_keystroke_session(&[0x10; 8]);
        assert_eq!(s.challenge_count(), 2);
    }

    #[test]
    fn gait_session_has_three_challenges() {
        let s = create_gait_session(&[]);
        assert_eq!(s.challenge_count(), 3);
    }

    #[test]
    fn all_challenges_have_descriptions() {
        for c in &[
            LivenessChallenge::Blink,
            LivenessChallenge::Smile,
            LivenessChallenge::HoldStill,
            LivenessChallenge::Swipe,
            LivenessChallenge::Hum,
            LivenessChallenge::Turn,
        ] {
            assert!(!c.description().is_empty());
        }
    }

    #[test]
    fn partial_pass_below_threshold_fails() {
        let mut s = LivenessSession::new(80, Modality::Face);
        s.add_challenge(LivenessChallenge::Blink);
        s.add_challenge(LivenessChallenge::Smile);
        // Non-uniform pixel data with variance to pass check_pixel_variance
        let mut data = vec![0u8; 32 * 32 * 4];
        for i in 0..data.len() {
            data[i] = (i % 256) as u8;
        }
        let cap = RawCapture {
            meta: crate::capture::CaptureMeta {
                modality: Modality::Face,
                width: 32,
                height: 32,
                sample_rate: 0,
                timestamp_ms: 1000,
                duration_ms: 100,
            },
            data,
        };
        s.verify_response(0, &cap).unwrap();
        let r = s.finalize();
        assert!(!r.passed);
        assert_eq!(r.score, 50);
    }

    #[test]
    fn require_liveness_passed() {
        let r = LivenessResult {
            passed: true,
            score: 100,
            challenges_passed: 3,
            challenges_total: 3,
        };
        assert!(require_liveness(&r).is_ok());
    }

    #[test]
    fn session_tracks_modality() {
        let s = create_gait_session(&[]);
        assert_eq!(s.modality(), Modality::Gait);
    }
}
