//! Active face liveness: the person performs a short sequence of actions
//! (blink, smile, turn left, turn right) in an order derived from the
//! verifier's single-use challenge, while one face is tracked without a
//! break. A printed photo can't blink or smile; a recording can't follow an
//! order nobody knew before the challenge was issued.
//!
//! The platform's face detector (ML Kit, Vision, ...) supplies per-frame
//! [`FaceSignals`]; this module decides. It also keeps an aligned crop of the
//! face each time the person is back at rest (before the first action and
//! after each one), so the identity used for the proof comes from the same
//! tracked face that did the actions (see `enroll`).
//!
//! What it does not stop: a screen showing a face that an attacker controls
//! live (a puppeted deepfake). Hardware attestation means it has to be shown
//! to a real phone's camera.

use alloc::vec::Vec;

use crate::face::{align_face, mean_luma, Frame};

/// One action the person is asked to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Blink,
    Smile,
    /// The person turns their head to their own left.
    TurnLeft,
    /// The person turns their head to their own right.
    TurnRight,
}

impl Action {
    pub fn id(self) -> u32 {
        match self {
            Action::Blink => 1,
            Action::Smile => 2,
            Action::TurnLeft => 3,
            Action::TurnRight => 4,
        }
    }
}

/// What the face detector saw in one frame, in upright image coordinates.
///
/// Angles are degrees. `yaw` is positive when the person has turned to their
/// own left, `pitch` positive when looking up. Probabilities are 0–1, or
/// negative when the detector couldn't tell.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FaceSignals {
    /// Camera timestamp, milliseconds, strictly increasing.
    pub t_ms: u64,
    /// Number of faces in the frame.
    pub faces: u32,
    /// The detector's tracking id for the face, if it tracks.
    pub track_id: Option<i64>,
    pub image_w: f32,
    pub image_h: f32,
    /// Face box: x, y, width, height.
    pub bbox: [f32; 4],
    pub yaw: f32,
    pub pitch: f32,
    pub roll: f32,
    pub left_eye_open: f32,
    pub right_eye_open: f32,
    pub smile: f32,
    /// Left eye, right eye, nose tip, left mouth corner, right mouth corner
    /// ("left" = smaller x in the image).
    pub landmarks: Option<[[f32; 2]; 5]>,
}

/// Thresholds. The defaults suit ML Kit and Apple Vision.
#[derive(Debug, Clone, Copy)]
pub struct LivenessConfig {
    pub actions: usize,
    pub max_frame_gap_ms: u64,
    pub max_absent_ms: u64,
    pub max_total_ms: u64,
    pub settle_timeout_ms: u64,
    pub action_timeout_ms: u64,
    pub return_timeout_ms: u64,
    pub neutral_hold_ms: u64,
    pub neutral_yaw: f32,
    pub neutral_pitch: f32,
    pub neutral_roll: f32,
    pub eye_open: f32,
    pub eye_closed: f32,
    pub max_blink_ms: u64,
    pub smile_on: f32,
    pub smile_off: f32,
    pub smile_hold_ms: u64,
    pub turn_yaw: f32,
    pub turn_hold_ms: u64,
    pub action_max_yaw: f32,
    /// Face width as a share of the shorter image side.
    pub min_face: f32,
    /// Largest move of the face centre between frames, in face widths.
    pub max_jump: f32,
    /// Largest change of face width between frames (ratio).
    pub max_resize: f32,
    pub min_luma: f32,
    pub max_luma: f32,
}

impl Default for LivenessConfig {
    fn default() -> Self {
        LivenessConfig {
            actions: 3,
            max_frame_gap_ms: 1_000,
            max_absent_ms: 700,
            max_total_ms: 90_000,
            settle_timeout_ms: 30_000,
            action_timeout_ms: 7_000,
            return_timeout_ms: 6_000,
            neutral_hold_ms: 400,
            neutral_yaw: 12.0,
            neutral_pitch: 15.0,
            neutral_roll: 20.0,
            eye_open: 0.6,
            eye_closed: 0.25,
            max_blink_ms: 1_000,
            smile_on: 0.8,
            smile_off: 0.35,
            smile_hold_ms: 250,
            turn_yaw: 25.0,
            turn_hold_ms: 150,
            action_max_yaw: 20.0,
            min_face: 0.2,
            max_jump: 0.5,
            max_resize: 1.6,
            min_luma: 40.0,
            max_luma: 225.0,
        }
    }
}

/// Why a session failed. Final: start a new session (with a new challenge).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    ClockWentBack,
    FramesStopped,
    TimedOut,
    FaceLost,
    MultipleFaces,
    FaceChanged,
    FaceJumped,
    TooSlow,
    WrongAction,
}

impl Failure {
    pub fn id(self) -> u32 {
        match self {
            Failure::ClockWentBack => 1,
            Failure::FramesStopped => 2,
            Failure::TimedOut => 3,
            Failure::FaceLost => 4,
            Failure::MultipleFaces => 5,
            Failure::FaceChanged => 6,
            Failure::FaceJumped => 7,
            Failure::TooSlow => 8,
            Failure::WrongAction => 9,
        }
    }
}

/// Guidance for the person while the session waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hint {
    None,
    NoFace,
    MoveCloser,
    CenterFace,
    LookStraight,
    OpenEyes,
    StopSmiling,
    TooDark,
    TooBright,
    HoldStill,
}

impl Hint {
    pub fn id(self) -> u32 {
        match self {
            Hint::None => 0,
            Hint::NoFace => 1,
            Hint::MoveCloser => 2,
            Hint::CenterFace => 3,
            Hint::LookStraight => 4,
            Hint::OpenEyes => 5,
            Hint::StopSmiling => 6,
            Hint::TooDark => 7,
            Hint::TooBright => 8,
            Hint::HoldStill => 9,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Look at the camera, still, until the first crop is taken.
    Settle,
    /// Perform action `i`.
    Act(usize),
    /// Back to rest after action `i`; a crop is taken.
    Return(usize),
    Done,
    Failed(Failure),
}

/// Where the session is, for the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    pub phase: Phase,
    /// The action to perform now (in `Act`), else the next one.
    pub action: Option<Action>,
    /// Actions completed so far.
    pub completed: usize,
    pub total: usize,
    pub hint: Hint,
}

/// The order of actions for one challenge: `SHA-256("hus.face-liveness.v1" ‖ challenge)`
/// shuffles the four actions; the first `n` are used.
pub fn actions_for(challenge: &[u8], n: usize) -> Vec<Action> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"hus.face-liveness.v1");
    h.update(challenge);
    let d = h.finalize();
    let mut pool = [Action::Blink, Action::Smile, Action::TurnLeft, Action::TurnRight];
    for i in (1..pool.len()).rev() {
        let j = d[i] as usize % (i + 1);
        pool.swap(i, j);
    }
    pool[..n.clamp(1, pool.len())].to_vec()
}

/// One live session. Feed every analysed frame to [`push`](Self::push).
#[derive(Debug, Clone)]
pub struct FaceLiveness {
    cfg: LivenessConfig,
    actions: Vec<Action>,
    phase: Phase,
    phase_start: u64,
    start: Option<u64>,
    last_t: Option<u64>,
    last_box: Option<[f32; 4]>,
    track: Option<i64>,
    absent_since: Option<u64>,
    neutral_since: Option<u64>,
    hold_since: Option<u64>,
    eyes_seen_open: bool,
    eyes_closed_at: Option<u64>,
    hint: Hint,
    crops: Vec<Vec<u8>>,
}

impl FaceLiveness {
    /// `challenge` is the verifier's single-use challenge (at least 16 bytes).
    pub fn new(challenge: &[u8], cfg: LivenessConfig) -> Option<Self> {
        if challenge.len() < 16 {
            return None;
        }
        Some(FaceLiveness {
            actions: actions_for(challenge, cfg.actions),
            cfg,
            phase: Phase::Settle,
            phase_start: 0,
            start: None,
            last_t: None,
            last_box: None,
            track: None,
            absent_since: None,
            neutral_since: None,
            hold_since: None,
            eyes_seen_open: false,
            eyes_closed_at: None,
            hint: Hint::None,
            crops: Vec::new(),
        })
    }

    pub fn actions(&self) -> &[Action] {
        &self.actions
    }

    pub fn status(&self) -> Status {
        let completed = match self.phase {
            Phase::Settle | Phase::Failed(_) => self.crops.len().saturating_sub(1),
            Phase::Act(i) => i,
            Phase::Return(i) => i + 1,
            Phase::Done => self.actions.len(),
        };
        let action = match self.phase {
            Phase::Settle => self.actions.first().copied(),
            Phase::Act(i) => Some(self.actions[i]),
            Phase::Return(i) => self.actions.get(i + 1).copied(),
            _ => None,
        };
        Status { phase: self.phase, action, completed, total: self.actions.len(), hint: self.hint }
    }

    /// Aligned 112×112 RGBA crops of the tracked face, one per rest point
    /// (`actions + 1`). Only once the session is done.
    pub fn crops(&self) -> Option<&[Vec<u8>]> {
        (self.phase == Phase::Done).then_some(&self.crops[..])
    }

    fn fail(&mut self, f: Failure) -> Status {
        self.phase = Phase::Failed(f);
        self.crops.clear();
        self.status()
    }

    fn enter(&mut self, phase: Phase, t: u64) {
        self.phase = phase;
        self.phase_start = t;
        self.neutral_since = None;
        self.hold_since = None;
        self.eyes_seen_open = false;
        self.eyes_closed_at = None;
    }

    /// Process one frame. `frame` is the camera buffer the signals came from;
    /// pass it whenever available (crops are taken from it at rest points).
    pub fn push(&mut self, s: &FaceSignals, frame: Option<&Frame>) -> Status {
        if matches!(self.phase, Phase::Done | Phase::Failed(_)) {
            return self.status();
        }
        let t = s.t_ms;
        let c = self.cfg;
        match self.last_t {
            Some(last) if t <= last => return self.fail(Failure::ClockWentBack),
            Some(last) if t - last > c.max_frame_gap_ms => {
                return self.fail(Failure::FramesStopped)
            }
            None => {
                self.start = Some(t);
                self.phase_start = t;
            }
            _ => {}
        }
        self.last_t = Some(t);
        if t - self.start.unwrap_or(t) > c.max_total_ms {
            return self.fail(Failure::TimedOut);
        }
        let deadline = match self.phase {
            Phase::Settle => c.settle_timeout_ms,
            Phase::Act(_) => c.action_timeout_ms,
            _ => c.return_timeout_ms,
        };
        if t - self.phase_start > deadline {
            return self.fail(Failure::TooSlow);
        }

        if s.faces > 1 {
            return self.fail(Failure::MultipleFaces);
        }
        if s.faces == 0 {
            let since = *self.absent_since.get_or_insert(t);
            if t - since > c.max_absent_ms {
                return self.fail(Failure::FaceLost);
            }
            self.neutral_since = None;
            self.hold_since = None;
            self.hint = Hint::NoFace;
            return self.status();
        }
        self.absent_since = None;

        if let Some(id) = s.track_id {
            match self.track {
                Some(prev) if prev != id => return self.fail(Failure::FaceChanged),
                _ => self.track = Some(id),
            }
        }
        let b = s.bbox;
        if !(b.iter().all(|v| v.is_finite()) && b[2] > 0.0 && b[3] > 0.0) {
            return self.fail(Failure::FaceLost);
        }
        if let Some(p) = self.last_box {
            let (pcx, pcy) = (p[0] + p[2] / 2.0, p[1] + p[3] / 2.0);
            let (cx, cy) = (b[0] + b[2] / 2.0, b[1] + b[3] / 2.0);
            let dist = libm::sqrtf((cx - pcx) * (cx - pcx) + (cy - pcy) * (cy - pcy));
            let ratio = if b[2] > p[2] { b[2] / p[2] } else { p[2] / b[2] };
            if dist > c.max_jump * b[2].max(p[2]) || ratio > c.max_resize {
                return self.fail(Failure::FaceJumped);
            }
        }
        self.last_box = Some(b);

        let short = s.image_w.min(s.image_h);
        let framed = if b[2] < c.min_face * short {
            Err(Hint::MoveCloser)
        } else if b[0] < 0.0 || b[1] < 0.0 || b[0] + b[2] > s.image_w || b[1] + b[3] > s.image_h {
            Err(Hint::CenterFace)
        } else {
            Ok(())
        };

        match self.phase {
            Phase::Settle | Phase::Return(_) => self.rest(s, framed, frame, t),
            Phase::Act(i) => self.act(i, s, framed, t),
            _ => {}
        }
        self.status()
    }

    fn rest(&mut self, s: &FaceSignals, framed: Result<(), Hint>, frame: Option<&Frame>, t: u64) {
        let c = self.cfg;
        let neutral = framed.and_then(|_| {
            // Written so that a NaN (detector unsure) never counts as at rest.
            if !(s.yaw.abs() <= c.neutral_yaw && s.pitch.abs() <= c.neutral_pitch && s.roll.abs() <= c.neutral_roll) {
                Err(Hint::LookStraight)
            } else if !(s.left_eye_open >= c.eye_open && s.right_eye_open >= c.eye_open) {
                Err(Hint::OpenEyes)
            } else if !(0.0..=c.smile_off).contains(&s.smile) {
                Err(Hint::StopSmiling)
            } else {
                Ok(())
            }
        });
        if let Err(h) = neutral {
            self.neutral_since = None;
            self.hint = h;
            return;
        }
        let since = *self.neutral_since.get_or_insert(t);
        if t - since < c.neutral_hold_ms {
            self.hint = Hint::HoldStill;
            return;
        }
        let (Some(frame), Some(lm)) = (frame, s.landmarks) else {
            self.hint = Hint::HoldStill;
            return;
        };
        let Some(crop) = align_face(frame, &lm) else {
            self.hint = Hint::LookStraight;
            return;
        };
        let luma = mean_luma(&crop);
        if luma < c.min_luma {
            self.hint = Hint::TooDark;
            return;
        }
        if luma > c.max_luma {
            self.hint = Hint::TooBright;
            return;
        }
        self.crops.push(crop);
        self.hint = Hint::None;
        let next = match self.phase {
            Phase::Settle => Phase::Act(0),
            Phase::Return(i) if i + 1 < self.actions.len() => Phase::Act(i + 1),
            _ => Phase::Done,
        };
        self.enter(next, t);
    }

    fn act(&mut self, i: usize, s: &FaceSignals, framed: Result<(), Hint>, t: u64) {
        let c = self.cfg;
        let want = self.actions[i];
        // Doing a different action than the one asked for ends the session:
        // a recording that runs through every action can't wait for its cue.
        // A blink is natural at any time and never counts as wrong.
        let wrong = (want != Action::TurnLeft && s.yaw >= c.turn_yaw)
            || (want != Action::TurnRight && s.yaw <= -c.turn_yaw)
            || (want != Action::Smile && s.smile >= c.smile_on);
        if wrong {
            self.fail(Failure::WrongAction);
            return;
        }
        if let Err(h) = framed {
            self.hint = h;
            self.hold_since = None;
            return;
        }
        self.hint = Hint::None;
        let done = match want {
            Action::Blink => {
                let open = s.left_eye_open >= c.eye_open && s.right_eye_open >= c.eye_open;
                let closed = (0.0..=c.eye_closed).contains(&s.left_eye_open)
                    && (0.0..=c.eye_closed).contains(&s.right_eye_open);
                if !(s.yaw.abs() <= c.action_max_yaw) {
                    self.eyes_seen_open = false;
                    self.eyes_closed_at = None;
                    self.hint = Hint::LookStraight;
                    false
                } else if open {
                    let blinked = matches!(self.eyes_closed_at, Some(at) if t - at <= c.max_blink_ms);
                    self.eyes_closed_at = None;
                    self.eyes_seen_open = true;
                    blinked
                } else {
                    if closed && self.eyes_seen_open {
                        self.eyes_closed_at.get_or_insert(t);
                    }
                    false
                }
            }
            Action::Smile => self.held(s.smile >= c.smile_on && s.yaw.abs() <= c.action_max_yaw, c.smile_hold_ms, t),
            Action::TurnLeft => self.held(s.yaw >= c.turn_yaw, c.turn_hold_ms, t),
            Action::TurnRight => self.held(s.yaw <= -c.turn_yaw, c.turn_hold_ms, t),
        };
        if done {
            self.enter(Phase::Return(i), t);
        }
    }

    fn held(&mut self, on: bool, hold_ms: u64, t: u64) -> bool {
        if !on {
            self.hold_since = None;
            return false;
        }
        t - *self.hold_since.get_or_insert(t) >= hold_ms
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::face::{PixelFormat, ARCFACE_TEMPLATE};

    pub(crate) const CHALLENGE: [u8; 16] = [7u8; 16];

    pub(crate) fn image() -> Vec<u8> {
        let (w, h) = (320usize, 240usize);
        let mut d = Vec::with_capacity(w * h * 4);
        for y in 0..h {
            for x in 0..w {
                d.extend_from_slice(&[(60 + x % 120) as u8, (60 + y % 120) as u8, 120, 255]);
            }
        }
        d
    }

    pub(crate) fn frame(d: &[u8]) -> Frame<'_> {
        Frame::new(PixelFormat::Rgba, 320, 240, 320 * 4, 0, d).unwrap()
    }

    pub(crate) fn rest(t: u64) -> FaceSignals {
        let mut lm = ARCFACE_TEMPLATE;
        for p in lm.iter_mut() {
            p[0] += 100.0;
            p[1] += 60.0;
        }
        FaceSignals {
            t_ms: t,
            faces: 1,
            track_id: Some(4),
            image_w: 320.0,
            image_h: 240.0,
            bbox: [110.0, 70.0, 90.0, 110.0],
            yaw: 0.0,
            pitch: 0.0,
            roll: 0.0,
            left_eye_open: 0.95,
            right_eye_open: 0.95,
            smile: 0.05,
            landmarks: Some(lm),
        }
    }

    /// Frames every 100 ms performing `action` from rest and back.
    pub(crate) fn perform(action: Action, t: &mut u64, out: &mut Vec<FaceSignals>) {
        let mut push = |f: &dyn Fn(&mut FaceSignals), n: usize, out: &mut Vec<FaceSignals>| {
            for _ in 0..n {
                *t += 100;
                let mut s = rest(*t);
                f(&mut s);
                out.push(s);
            }
        };
        match action {
            Action::Blink => {
                push(&|_| {}, 2, out);
                push(&|s| { s.left_eye_open = 0.05; s.right_eye_open = 0.1 }, 2, out);
                push(&|_| {}, 1, out);
            }
            Action::Smile => push(&|s| s.smile = 0.95, 4, out),
            Action::TurnLeft => push(&|s| { s.yaw = 32.0; s.bbox[0] += 12.0 }, 3, out),
            Action::TurnRight => push(&|s| { s.yaw = -32.0; s.bbox[0] -= 12.0 }, 3, out),
        }
        push(&|_| {}, 6, out);
    }

    /// A complete passing trace for `CHALLENGE`.
    pub(crate) fn passing_trace() -> Vec<FaceSignals> {
        let mut t = 1_000;
        let mut out = Vec::new();
        for _ in 0..10 {
            t += 100;
            out.push(rest(t));
        }
        for a in actions_for(&CHALLENGE, 3) {
            perform(a, &mut t, &mut out);
        }
        out
    }

    fn run(trace: &[FaceSignals]) -> FaceLiveness {
        let img = image();
        let f = frame(&img);
        let mut l = FaceLiveness::new(&CHALLENGE, LivenessConfig::default()).unwrap();
        for s in trace {
            l.push(s, Some(&f));
        }
        l
    }

    #[test]
    fn a_live_person_passes_and_leaves_one_crop_per_rest_point() {
        let l = run(&passing_trace());
        assert_eq!(l.status().phase, Phase::Done, "{:?}", l.status());
        assert_eq!(l.crops().unwrap().len(), 4);
        assert!(l.crops().unwrap().iter().all(|c| c.len() == 112 * 112 * 4));
    }

    #[test]
    fn order_depends_on_the_challenge() {
        let mut seen = std::collections::BTreeSet::new();
        for i in 0..64u8 {
            let a = actions_for(&[i; 16], 3);
            assert_eq!(a.len(), 3);
            let mut d = a.clone();
            d.dedup();
            assert_eq!(d.len(), 3);
            seen.insert(a.iter().map(|x| x.id()).collect::<Vec<_>>());
        }
        assert!(seen.len() > 12, "only {} orders", seen.len());
        assert!(FaceLiveness::new(&[0u8; 8], LivenessConfig::default()).is_none());
    }

    #[test]
    fn a_still_photo_never_gets_past_the_first_action() {
        let mut t = 1_000;
        let trace: Vec<_> = (0..200).map(|_| { t += 100; rest(t) }).collect();
        let l = run(&trace);
        assert_eq!(l.status().phase, Phase::Failed(Failure::TooSlow));
        assert!(l.crops().is_none());
    }

    #[test]
    fn a_recording_in_another_order_fails() {
        let mut t = 1_000;
        let mut trace = Vec::new();
        for _ in 0..6 {
            t += 100;
            trace.push(rest(t));
        }
        let want = actions_for(&CHALLENGE, 3);
        // Perform the actions in reverse; the first wrong one that is a
        // turn or smile ends the session.
        let mut order = want.clone();
        order.reverse();
        if order[0] == Action::Blink {
            order.swap(0, 1);
        }
        for a in order {
            perform(a, &mut t, &mut trace);
        }
        let l = run(&trace);
        assert_eq!(l.status().phase, Phase::Failed(Failure::WrongAction));
    }

    #[test]
    fn two_faces_fail() {
        let mut trace = passing_trace();
        trace[10].faces = 2;
        assert_eq!(run(&trace).status().phase, Phase::Failed(Failure::MultipleFaces));
    }

    #[test]
    fn a_different_tracked_face_fails() {
        let mut trace = passing_trace();
        for s in trace.iter_mut().skip(15) {
            s.track_id = Some(9);
        }
        assert_eq!(run(&trace).status().phase, Phase::Failed(Failure::FaceChanged));
    }

    #[test]
    fn a_face_that_jumps_fails() {
        let mut trace = passing_trace();
        for s in trace.iter_mut().skip(12) {
            s.bbox[0] -= 80.0;
            if let Some(lm) = s.landmarks.as_mut() {
                for p in lm.iter_mut() {
                    p[0] -= 80.0;
                }
            }
        }
        assert_eq!(run(&trace).status().phase, Phase::Failed(Failure::FaceJumped));
    }

    #[test]
    fn losing_the_face_too_long_fails_but_a_flicker_does_not() {
        let mut trace = passing_trace();
        trace[2].faces = 0;
        assert_eq!(run(&trace).status().phase, Phase::Done);
        for s in trace.iter_mut().skip(8).take(9) {
            s.faces = 0;
        }
        assert_eq!(run(&trace).status().phase, Phase::Failed(Failure::FaceLost));
    }

    #[test]
    fn stalled_or_backwards_frames_fail() {
        let mut trace = passing_trace();
        for s in trace.iter_mut().skip(9) {
            s.t_ms += 5_000;
        }
        assert_eq!(run(&trace).status().phase, Phase::Failed(Failure::FramesStopped));
        let mut trace = passing_trace();
        trace[9].t_ms = trace[8].t_ms;
        assert_eq!(run(&trace).status().phase, Phase::Failed(Failure::ClockWentBack));
    }

    #[test]
    fn a_blink_needs_open_closed_open_quickly() {
        // Eyes shut for 2 s is not a blink.
        let mut l = FaceLiveness::new(&CHALLENGE, LivenessConfig::default()).unwrap();
        l.actions = vec![Action::Blink, Action::Smile, Action::TurnLeft];
        let img = image();
        let f = frame(&img);
        let mut t = 1_000;
        for _ in 0..6 {
            t += 100;
            l.push(&rest(t), Some(&f));
        }
        assert_eq!(l.status().phase, Phase::Act(0));
        for i in 0..25 {
            t += 100;
            let mut s = rest(t);
            if i >= 2 && i < 22 {
                s.left_eye_open = 0.0;
                s.right_eye_open = 0.0;
            }
            l.push(&s, Some(&f));
        }
        assert_eq!(l.status().phase, Phase::Act(0));
        // One eye closed is a wink, not a blink.
        for i in 0..5 {
            t += 100;
            let mut s = rest(t);
            if i == 2 {
                s.left_eye_open = 0.0;
            }
            l.push(&s, Some(&f));
        }
        assert_eq!(l.status().phase, Phase::Act(0));
        let mut trace = Vec::new();
        perform(Action::Blink, &mut t, &mut trace);
        for s in &trace {
            l.push(s, Some(&f));
        }
        assert_eq!(l.status().phase, Phase::Act(1));
    }

    #[test]
    fn no_crop_without_a_frame_or_landmarks() {
        let mut l = FaceLiveness::new(&CHALLENGE, LivenessConfig::default()).unwrap();
        let mut t = 1_000;
        for _ in 0..10 {
            t += 100;
            l.push(&rest(t), None);
        }
        assert_eq!(l.status().phase, Phase::Settle);
        assert_eq!(l.status().hint, Hint::HoldStill);
        let img = image();
        let f = frame(&img);
        for _ in 0..3 {
            t += 100;
            let mut s = rest(t);
            s.landmarks = None;
            l.push(&s, Some(&f));
        }
        assert_eq!(l.status().phase, Phase::Settle);
        t += 100;
        l.push(&rest(t), Some(&f));
        assert_eq!(l.status().phase, Phase::Act(0));
    }

    #[test]
    fn a_dark_face_is_not_cropped() {
        let dark = vec![5u8; 320 * 240 * 4];
        let f = frame(&dark);
        let mut l = FaceLiveness::new(&CHALLENGE, LivenessConfig::default()).unwrap();
        let mut t = 1_000;
        for _ in 0..10 {
            t += 100;
            l.push(&rest(t), Some(&f));
        }
        assert_eq!(l.status().phase, Phase::Settle);
        assert_eq!(l.status().hint, Hint::TooDark);
    }

    #[test]
    fn hints_guide_the_person() {
        let img = image();
        let f = frame(&img);
        let mut l = FaceLiveness::new(&CHALLENGE, LivenessConfig::default()).unwrap();
        let mut s = rest(1_000);
        s.bbox = [140.0, 100.0, 40.0, 44.0];
        assert_eq!(l.push(&s, Some(&f)).hint, Hint::MoveCloser);
        let mut s = rest(1_100);
        s.bbox = [130.0, 95.0, 50.0, 56.0];
        s.yaw = 30.0;
        assert_eq!(l.push(&s, Some(&f)).hint, Hint::LookStraight);
    }

    #[test]
    fn unknown_angles_or_eyes_never_count_as_at_rest() {
        let img = image();
        let f = frame(&img);
        let mut l = FaceLiveness::new(&CHALLENGE, LivenessConfig::default()).unwrap();
        let mut t = 1_000;
        for i in 0..20 {
            t += 100;
            let mut s = rest(t);
            if i % 2 == 0 {
                s.yaw = f32::NAN;
            } else {
                s.left_eye_open = f32::NAN;
            }
            l.push(&s, Some(&f));
        }
        assert_eq!(l.status().phase, Phase::Settle);
    }

    #[test]
    fn the_whole_session_has_a_time_limit() {
        let cfg = LivenessConfig { max_total_ms: 2_000, ..LivenessConfig::default() };
        let img = image();
        let f = frame(&img);
        let mut l = FaceLiveness::new(&CHALLENGE, cfg).unwrap();
        let trace = passing_trace();
        for s in &trace {
            l.push(s, Some(&f));
        }
        assert_eq!(l.status().phase, Phase::Failed(Failure::TimedOut));
    }
}
