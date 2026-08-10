use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Modality enum — every biometric HUS can capture and verify
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Modality {
    /// Face — front camera, 128–512 dim embedding via FaceNet / ArcFace
    Face,
    /// Iris — front camera with zoom, 256–2048 bit iris code
    Iris,
    /// Voice / speaker — microphone, 192–512 dim x-vector embedding
    Voice,
    /// Fingerprint — capacitive sensor, minutiae feature vector
    Fingerprint,
    /// Keystroke dynamics — keyboard timing features (passive)
    Keystroke,
    /// Touch / swipe gesture — touchscreen motion features (passive)
    TouchGesture,
    /// Gait — accelerometer + gyroscope stride features (passive)
    Gait,
}

impl Modality {
    /// Numeric id matching on-chain encoding (0 = Face, … 6 = Gait).
    pub const fn id(&self) -> u8 {
        match self {
            Modality::Face => 0,
            Modality::Iris => 1,
            Modality::Voice => 2,
            Modality::Fingerprint => 3,
            Modality::Keystroke => 4,
            Modality::TouchGesture => 5,
            Modality::Gait => 6,
        }
    }

    pub fn from_id(id: u8) -> Result<Self, &'static str> {
        match id {
            0 => Ok(Modality::Face),
            1 => Ok(Modality::Iris),
            2 => Ok(Modality::Voice),
            3 => Ok(Modality::Fingerprint),
            4 => Ok(Modality::Keystroke),
            5 => Ok(Modality::TouchGesture),
            6 => Ok(Modality::Gait),
            _ => Err("invalid modality id"),
        }
    }

    /// All modalities HUS supports.
    pub const fn all() -> &'static [Modality] {
        &[
            Modality::Face,
            Modality::Iris,
            Modality::Voice,
            Modality::Fingerprint,
            Modality::Keystroke,
            Modality::TouchGesture,
            Modality::Gait,
        ]
    }

    /// Modalities that work without special hardware — suitable for any
    /// consumer mobile phone.
    pub const fn mobile_friendly() -> &'static [Modality] {
        &[
            Modality::Face,
            Modality::Iris,
            Modality::Voice,
            Modality::Keystroke,
            Modality::TouchGesture,
            Modality::Gait,
        ]
    }

    /// High-assurance modalities for government / bank / election use-cases
    /// where the deployer provides supporting hardware.
    pub const fn government_grade() -> &'static [Modality] {
        &[
            Modality::Iris,
            Modality::Fingerprint,
            Modality::Face,
            Modality::Voice,
        ]
    }

    /// Human-readable name.
    pub const fn name(&self) -> &'static str {
        match self {
            Modality::Face => "face",
            Modality::Iris => "iris",
            Modality::Voice => "voice",
            Modality::Fingerprint => "fingerprint",
            Modality::Keystroke => "keystroke",
            Modality::TouchGesture => "touch_gesture",
            Modality::Gait => "gait",
        }
    }

    /// Whether the raw capture requires a hardware sensor beyond the
    /// standard front/rear camera, microphone, and touchscreen.
    pub const fn requires_hardware(&self) -> bool {
        match self {
            Modality::Face => false,
            Modality::Iris => false, // needs only high-res front camera
            Modality::Voice => false,
            Modality::Fingerprint => true, // needs capacitive / ultrasonic sensor
            Modality::Keystroke => false,
            Modality::TouchGesture => false,
            Modality::Gait => false,
        }
    }

    /// Template stability over many years (0–100).
    ///
    /// Iris is the most stable (little change over decades), followed by
    /// fingerprint and face. Behavioral modalities drift more.
    pub const fn template_stability(&self) -> u8 {
        match self {
            Modality::Iris => 98,
            Modality::Fingerprint => 95,
            Modality::Face => 85,
            Modality::Voice => 75,
            Modality::Gait => 60,
            Modality::Keystroke => 55,
            Modality::TouchGesture => 50,
        }
    }

    /// Whether extraction uses a machine-learning model (ONNX).
    pub const fn needs_ml_model(&self) -> bool {
        match self {
            Modality::Face => true,
            Modality::Iris => true,
            Modality::Voice => true,
            Modality::Fingerprint => true,
            Modality::Keystroke => false,
            Modality::TouchGesture => false,
            Modality::Gait => false,
        }
    }

    /// Liveness challenge type best suited for this modality.
    pub const fn liveness_type(&self) -> &'static [&'static str] {
        match self {
            Modality::Face => &["blink", "smile", "turn_head", "depth"],
            Modality::Iris => &["hold_still", "depth", "vary_light"],
            Modality::Voice => &["repeat_phrase", "random_challenge", "hum"],
            Modality::Fingerprint => &["swipe", "lift_repeat"],
            Modality::Keystroke => &["type_sentence", "repeat_rhythm"],
            Modality::TouchGesture => &["swipe_pattern", "pinch_zoom"],
            Modality::Gait => &["walk_steps", "turn", "stop_start"],
        }
    }
}

// ---------------------------------------------------------------------------
// Per-modality configuration
// ---------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct ModalityConfig {
    pub modality: Modality,
    /// Dimension of the raw embedding produced by the extractor.
    pub raw_dim: usize,
    /// Dimension after matrix projection (obfuscated).
    pub proj_dim: usize,
    /// Max allowable L2 distance for a match.
    pub threshold: f32,
    /// Minimum uniqueness score (0–100) to accept.
    pub min_score: u8,
    /// Number of times to capture for template enrollment.
    pub enrollment_captures: usize,
}

impl ModalityConfig {
    /// Build a config from on-chain values, filling in SDK defaults for
    /// `raw_dim`, `threshold`, and `enrollment_captures`.
    pub fn from_chain(modality: Modality, proj_dim: usize, min_score: u8) -> Self {
        let defaults = Self::for_modality(modality);
        Self {
            modality,
            raw_dim: defaults.raw_dim,
            proj_dim,
            threshold: defaults.threshold,
            min_score,
            enrollment_captures: defaults.enrollment_captures,
        }
    }

    pub const fn for_modality(m: Modality) -> Self {
        match m {
            Modality::Face => Self {
                modality: m,
                raw_dim: 512,
                proj_dim: 128,
                threshold: 1.0,
                min_score: 80,
                enrollment_captures: 3,
            },
            Modality::Iris => Self {
                modality: m,
                raw_dim: 256,
                proj_dim: 64,
                threshold: 0.6,
                min_score: 90,
                enrollment_captures: 2,
            },
            Modality::Voice => Self {
                modality: m,
                raw_dim: 192,
                proj_dim: 64,
                threshold: 1.2,
                min_score: 75,
                enrollment_captures: 3,
            },
            Modality::Fingerprint => Self {
                modality: m,
                raw_dim: 128,
                proj_dim: 48,
                threshold: 0.5,
                min_score: 90,
                enrollment_captures: 4,
            },
            Modality::Keystroke => Self {
                modality: m,
                raw_dim: 40,
                proj_dim: 16,
                threshold: 2.0,
                min_score: 70,
                enrollment_captures: 5,
            },
            Modality::TouchGesture => Self {
                modality: m,
                raw_dim: 30,
                proj_dim: 12,
                threshold: 2.0,
                min_score: 65,
                enrollment_captures: 5,
            },
            Modality::Gait => Self {
                modality: m,
                raw_dim: 60,
                proj_dim: 24,
                threshold: 1.5,
                min_score: 70,
                enrollment_captures: 4,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Modality selection — what an app signs up for
// ---------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct ModalitySelection {
    /// The modalities required (app picks at least 2).
    modalities: Vec<Modality>,
    /// Per-modality configs (from chain or defaults).
    configs: Vec<ModalityConfig>,
    /// Whether to use passive-only modalities (keystroke, touch, gait) that
    /// don't require explicit user action beyond normal usage.
    pub prefer_passive: bool,
}

impl ModalitySelection {
    pub fn new(modalities: Vec<Modality>) -> Result<Self, &'static str> {
        if modalities.len() < 2 {
            return Err("at least 2 modalities are required");
        }
        for i in 0..modalities.len() {
            for j in (i + 1)..modalities.len() {
                if modalities[i] == modalities[j] {
                    return Err("duplicate modality in selection");
                }
            }
        }
        let configs: Vec<ModalityConfig> =
            modalities.iter().map(|m| ModalityConfig::for_modality(*m)).collect();
        Ok(Self { modalities, configs, prefer_passive: false })
    }

    /// Build from a list of `ModalityConfig` objects returned by the chain.
    /// Validates >= 2 entries with unique modalities.
    pub fn from_chain_configs(configs: Vec<ModalityConfig>) -> Result<Self, &'static str> {
        if configs.len() < 2 {
            return Err("at least 2 modalities are required");
        }
        for i in 0..configs.len() {
            for j in (i + 1)..configs.len() {
                if configs[i].modality == configs[j].modality {
                    return Err("duplicate modality in chain config");
                }
            }
        }
        let modalities: Vec<Modality> = configs.iter().map(|c| c.modality).collect();
        Ok(Self { modalities, configs, prefer_passive: false })
    }

    pub fn modalities(&self) -> &[Modality] {
        &self.modalities
    }

    /// Minimum number of modalities that must pass for the overall
    /// registration to be accepted.
    pub fn required_passing(&self) -> usize {
        if self.modalities.len() <= 3 {
            self.modalities.len()
        } else {
            (self.modalities.len() * 3).div_ceil(4)
        }
    }

    pub fn configs(&self) -> &[ModalityConfig] {
        &self.configs
    }
}

// ---------------------------------------------------------------------------
// Legacy compatibility constants
// ---------------------------------------------------------------------------
pub const DEFAULT_RAW_DIM: usize = 512;
pub const DEFAULT_PROJ_DIM: usize = 128;
pub const DEFAULT_THRESHOLD: f32 = 1.0;
pub const UNIQUENESS_MIN_SCORE: u8 = 80;

#[derive(Debug, Clone)]
pub struct HusConfig {
    pub raw_dim: usize,
    pub proj_dim: usize,
    pub threshold: f32,
    pub uniqueness_min_score: u8,
}

impl HusConfig {
    pub const fn default() -> Self {
        Self {
            raw_dim: DEFAULT_RAW_DIM,
            proj_dim: DEFAULT_PROJ_DIM,
            threshold: DEFAULT_THRESHOLD,
            uniqueness_min_score: UNIQUENESS_MIN_SCORE,
        }
    }

    pub const fn custom(raw_dim: usize, proj_dim: usize, threshold: f32, min_score: u8) -> Self {
        Self {
            raw_dim,
            proj_dim,
            threshold,
            uniqueness_min_score: min_score,
        }
    }
}

impl Default for HusConfig {
    fn default() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_least_two_modalities_required() {
        assert!(ModalitySelection::new(vec![Modality::Face]).is_err());
        assert!(ModalitySelection::new(vec![Modality::Face, Modality::Iris]).is_ok());
    }

    #[test]
    fn duplicates_rejected() {
        assert!(ModalitySelection::new(vec![Modality::Face, Modality::Face]).is_err());
    }

    #[test]
    fn all_modalities_have_config() {
        for m in Modality::all() {
            let cfg = ModalityConfig::for_modality(*m);
            assert!(cfg.raw_dim > 0);
            assert!(cfg.proj_dim > 0);
            assert!(cfg.proj_dim < cfg.raw_dim);
        }
    }

    #[test]
    fn mobile_friendly_subset() {
        for m in Modality::mobile_friendly() {
            assert!(
                !m.requires_hardware(),
                "{:?} should not require hardware",
                m
            );
        }
    }

    #[test]
    fn required_passing_logic() {
        let sel = ModalitySelection::new(vec![Modality::Face, Modality::Iris]).unwrap();
        assert_eq!(sel.required_passing(), 2);

        let sel = ModalitySelection::new(vec![
            Modality::Face,
            Modality::Iris,
            Modality::Voice,
            Modality::Keystroke,
        ])
        .unwrap();
        assert_eq!(sel.required_passing(), 3); // 75 %
    }

    #[test]
    fn seven_modalities_accepted() {
        let all = Modality::all().to_vec();
        assert!(ModalitySelection::new(all).is_ok());
    }

    #[test]
    fn modality_name_is_non_empty() {
        for m in Modality::all() {
            assert!(!m.name().is_empty());
        }
    }

    #[test]
    fn modalselection_empty_rejected() {
        assert!(ModalitySelection::new(vec![]).is_err());
    }
}
