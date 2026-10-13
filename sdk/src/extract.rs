//! Biometric feature extraction — raw sensor data → fixed-dim embedding.
//!
//! Each modality has its own extraction strategy. Modalities that require a
//! machine-learning model (Face, Iris, Voice, Fingerprint) use tract-onnx
//! when the `ml` feature is enabled. Modalities that rely purely on signal
//! processing (Keystroke, TouchGesture, Gait) are implemented in full.

use crate::capture::RawCapture;
use crate::config::Modality;
use crate::error::ExtractionError;
use alloc::boxed::Box;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Result of extraction
// ---------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct Embedding {
    pub modality: Modality,
    /// Fixed-dimension float vector fed into the projection matrix.
    pub vector: Vec<f32>,
}

// ---------------------------------------------------------------------------
// Extraction trait
// ---------------------------------------------------------------------------
pub trait Extractor {
    fn modality(&self) -> Modality;
    fn extract(&self, capture: &RawCapture) -> Result<Embedding, ExtractionError>;
}

// ---------------------------------------------------------------------------
// ML-based extractors — delegate to tract-onnx when feature is enabled
// ---------------------------------------------------------------------------
#[cfg(feature = "ml")]
mod ml {
    use super::*;
    use crate::onnx::TractOnnxExtractor;

    pub struct MlExtractor(TractOnnxExtractor);

    impl MlExtractor {
        pub fn face(model: &[u8]) -> Result<Self, ExtractionError> {
            TractOnnxExtractor::new(Modality::Face, model).map(MlExtractor)
        }
        pub fn iris(model: &[u8]) -> Result<Self, ExtractionError> {
            TractOnnxExtractor::new(Modality::Iris, model).map(MlExtractor)
        }
        pub fn voice(model: &[u8]) -> Result<Self, ExtractionError> {
            TractOnnxExtractor::new(Modality::Voice, model).map(MlExtractor)
        }
        pub fn fingerprint(model: &[u8]) -> Result<Self, ExtractionError> {
            TractOnnxExtractor::new(Modality::Fingerprint, model).map(MlExtractor)
        }
    }

    impl Extractor for MlExtractor {
        fn modality(&self) -> Modality {
            self.0.modality()
        }
        fn extract(&self, capture: &RawCapture) -> Result<Embedding, ExtractionError> {
            self.0.extract(capture)
        }
    }
}

#[cfg(not(feature = "ml"))]
mod ml {
    // No-op module. ML extractors are unavailable.
    // `get_ml_extractor` returns Err and `get_extractor` uses `MlStubExtractor`.
}

// ---------------------------------------------------------------------------
// Keystroke extraction — timing features from key events
// ---------------------------------------------------------------------------
pub struct KeystrokeExtractor;

impl Extractor for KeystrokeExtractor {
    fn modality(&self) -> Modality {
        Modality::Keystroke
    }

    fn extract(&self, capture: &RawCapture) -> Result<Embedding, ExtractionError> {
        const KEY_EVENT_BYTES: usize = 20; // u32(4) + u64(8) + u64(8)
        if capture.data.len() < KEY_EVENT_BYTES {
            return Err(ExtractionError::InsufficientData);
        }
        let event_count = capture.data.len() / KEY_EVENT_BYTES;
        let events: Vec<[u8; 20]> = capture
            .data
            .chunks(KEY_EVENT_BYTES)
            .map(|c| {
                let mut arr = [0u8; 20];
                let n = c.len().min(20);
                arr[..n].copy_from_slice(&c[..n]);
                arr
            })
            .collect();

        // Each chunk: key_code(u32) | press_time(u64) | release_time(u64)
        let mut hold_times = Vec::with_capacity(event_count);
        let mut inter_key_times = Vec::with_capacity(event_count.saturating_sub(1));
        let mut prev_release: Option<u64> = None;
        for chunk in &events {
            if chunk.len() < 20 {
                return Err(crate::error::ExtractionError::InvalidFormat);
            }
            let press = u64::from_le_bytes(
                chunk[4..12]
                    .try_into()
                    .map_err(|_| crate::error::ExtractionError::InvalidFormat)?,
            );
            let release = u64::from_le_bytes(
                chunk[12..20]
                    .try_into()
                    .map_err(|_| crate::error::ExtractionError::InvalidFormat)?,
            );
            hold_times.push((release.saturating_sub(press)) as f32);
            if let Some(prev) = prev_release {
                inter_key_times.push((press.saturating_sub(prev)) as f32);
            }
            prev_release = Some(release);
        }

        // Build feature vector: [mean_hold, std_hold, mean_ikt, std_ikt,
        //                         min_hold, max_hold, min_ikt, max_ikt, ...]
        let mean_hold = mean(&hold_times);
        let std_hold = std_dev(&hold_times, mean_hold);
        let mean_ikt = if inter_key_times.is_empty() {
            0.0
        } else {
            mean(&inter_key_times)
        };
        let std_ikt = if inter_key_times.is_empty() {
            0.0
        } else {
            std_dev(&inter_key_times, mean_ikt)
        };

        let mut vec = Vec::with_capacity(40);
        vec.push(normalize_mean(mean_hold));
        vec.push(normalize_std(std_hold));
        vec.push(normalize_mean(mean_ikt));
        vec.push(normalize_std(std_ikt));
        vec.push(normalize_mean(min_or_zero(&hold_times)));
        vec.push(normalize_std(max_or_zero(&hold_times)));
        vec.push(normalize_mean(min_or_zero(&inter_key_times)));
        vec.push(normalize_std(max_or_zero(&inter_key_times)));
        // Pad to 40 with additional n-gram features
        for i in 0..16 {
            let idx = (i * event_count / 16).min(event_count.saturating_sub(1));
            vec.push(normalize_mean(hold_times.get(idx).copied().unwrap_or(0.0)));
        }
        for i in 0..16 {
            let idx = (i * inter_key_times.len().max(1) / 16)
                .min(inter_key_times.len().saturating_sub(1));
            vec.push(normalize_mean(
                inter_key_times.get(idx).copied().unwrap_or(0.0),
            ));
        }
        // Trim/pad to exactly 40
        vec.truncate(40);
        while vec.len() < 40 {
            vec.push(0.0);
        }

        Ok(Embedding {
            modality: Modality::Keystroke,
            vector: vec,
        })
    }
}

// ---------------------------------------------------------------------------
// Touch gesture extraction — motion features from touch events
// ---------------------------------------------------------------------------
pub struct TouchExtractor;

impl Extractor for TouchExtractor {
    fn modality(&self) -> Modality {
        Modality::TouchGesture
    }

    fn extract(&self, capture: &RawCapture) -> Result<Embedding, ExtractionError> {
        if capture.data.len() < 20 || !capture.data.len().is_multiple_of(20) {
            return Err(ExtractionError::InvalidFormat);
        }
        let event_count = capture.data.len() / 20;
        let mut xs = Vec::with_capacity(event_count);
        let mut ys = Vec::with_capacity(event_count);
        let mut ps = Vec::with_capacity(event_count);
        let mut times = Vec::with_capacity(event_count);

        for chunk in capture.data.chunks(20) {
            let arr: [u8; 20] = chunk
                .try_into()
                .map_err(|_| ExtractionError::InvalidFormat)?;
            xs.push(f32::from_le_bytes(
                arr[0..4]
                    .try_into()
                    .map_err(|_| ExtractionError::InvalidFormat)?,
            ));
            ys.push(f32::from_le_bytes(
                arr[4..8]
                    .try_into()
                    .map_err(|_| ExtractionError::InvalidFormat)?,
            ));
            ps.push(f32::from_le_bytes(
                arr[8..12]
                    .try_into()
                    .map_err(|_| ExtractionError::InvalidFormat)?,
            ));
            times.push(u64::from_le_bytes(
                arr[12..20]
                    .try_into()
                    .map_err(|_| ExtractionError::InvalidFormat)?,
            ));
        }

        // Compute velocities and accelerations
        let mut vx = Vec::with_capacity(event_count.saturating_sub(1));
        let mut vy = Vec::with_capacity(event_count.saturating_sub(1));
        for i in 1..event_count {
            let dt = (times[i] - times[i - 1]).max(1) as f32 / 1000.0;
            vx.push((xs[i] - xs[i - 1]) / dt);
            vy.push((ys[i] - ys[i - 1]) / dt);
        }

        let mut vec = Vec::with_capacity(30);
        vec.push(normalize_mean(mean(&xs)));
        vec.push(normalize_mean(mean(&ys)));
        vec.push(normalize_mean(mean(&ps)));
        vec.push(normalize_mean(mean(&vx)));
        vec.push(normalize_mean(mean(&vy)));
        vec.push(normalize_std(std_dev(&vx, mean(&vx))));
        vec.push(normalize_std(std_dev(&vy, mean(&vy))));
        // Total distance
        let total_dist: f32 = xs
            .windows(2)
            .map(|w| ((w[1] - w[0]).powi(2) + (ys[1] - ys[0]).powi(2)).sqrt())
            .sum();
        vec.push(normalize_mean(total_dist));
        vec.push(normalize_mean(total_dist / event_count.max(1) as f32));
        // Path curvature
        if event_count >= 3 {
            let mut curvature = 0.0f32;
            for i in 1..event_count - 1 {
                let dx1 = xs[i] - xs[i - 1];
                let dy1 = ys[i] - ys[i - 1];
                let dx2 = xs[i + 1] - xs[i];
                let dy2 = ys[i + 1] - ys[i];
                let cross = (dx1 * dy2 - dy1 * dx2).abs();
                curvature += cross;
            }
            vec.push(normalize_mean(curvature / event_count.max(1) as f32));
        } else {
            vec.push(0.0);
        }
        // Pad to 30
        while vec.len() < 30 {
            vec.push(0.0);
        }
        vec.truncate(30);

        Ok(Embedding {
            modality: Modality::TouchGesture,
            vector: vec,
        })
    }
}

// ---------------------------------------------------------------------------
// Gait extraction — accelerometer FFT features
// ---------------------------------------------------------------------------
pub struct GaitExtractor;

impl Extractor for GaitExtractor {
    fn modality(&self) -> Modality {
        Modality::Gait
    }

    fn extract(&self, capture: &RawCapture) -> Result<Embedding, ExtractionError> {
        if capture.data.len() < 16 || !capture.data.len().is_multiple_of(16) {
            return Err(ExtractionError::InvalidFormat);
        }
        let frame_count = capture.data.len() / 16;
        let mut xs = Vec::with_capacity(frame_count);
        let mut ys = Vec::with_capacity(frame_count);
        let mut zs = Vec::with_capacity(frame_count);

        for chunk in capture.data.chunks(16) {
            let arr: [u8; 16] = chunk
                .try_into()
                .map_err(|_| ExtractionError::InvalidFormat)?;
            xs.push(f32::from_le_bytes(
                arr[0..4]
                    .try_into()
                    .map_err(|_| ExtractionError::InvalidFormat)?,
            ));
            ys.push(f32::from_le_bytes(
                arr[4..8]
                    .try_into()
                    .map_err(|_| ExtractionError::InvalidFormat)?,
            ));
            zs.push(f32::from_le_bytes(
                arr[8..12]
                    .try_into()
                    .map_err(|_| ExtractionError::InvalidFormat)?,
            ));
        }

        // Compute magnitude vector
        let mut mag: Vec<f32> = xs
            .iter()
            .zip(ys.iter())
            .zip(zs.iter())
            .map(|((x, y), z)| (x * x + y * y + z * z).sqrt())
            .collect();

        // Normalize by removing gravity (DC component)
        let mean_mag = mean(&mag);
        for m in mag.iter_mut() {
            *m -= mean_mag;
        }

        // Simple frequency-domain features without FFT crate:
        // count zero-crossings (stride rate), energy, variance
        let mut zero_crossings = 0u32;
        for w in mag.windows(2) {
            if w[0] * w[1] < 0.0 {
                zero_crossings += 1;
            }
        }
        let energy: f32 = mag.iter().map(|m| m * m).sum();
        let variance = std_dev(&mag, mean(&mag));

        let mut vec = Vec::with_capacity(60);
        vec.push(normalize_mean(zero_crossings as f32));
        vec.push(normalize_mean(energy / frame_count.max(1) as f32));
        vec.push(normalize_std(variance));
        vec.push(normalize_mean(mean(&mag)));
        vec.push(normalize_mean(max_or_zero(&mag)));
        vec.push(normalize_mean(min_or_zero(&mag)));
        // Symmetry: ratio of left/right step energy
        let half = frame_count / 2;
        let left_energy: f32 = mag[..half].iter().map(|m| m * m).sum();
        let right_energy: f32 = mag[half..].iter().map(|m| m * m).sum();
        let symmetry = if right_energy > 0.0 {
            left_energy / right_energy
        } else {
            1.0
        };
        vec.push(normalize_mean(symmetry));

        // Pad to 60 with magnitude samples
        for i in 0..53 {
            let idx = (i * frame_count / 53).min(frame_count.saturating_sub(1));
            vec.push(normalize_mean(mag.get(idx).copied().unwrap_or(0.0)));
        }

        vec.truncate(60);
        while vec.len() < 60 {
            vec.push(0.0);
        }

        Ok(Embedding {
            modality: Modality::Gait,
            vector: vec,
        })
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------
fn mean(data: &[f32]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    data.iter().sum::<f32>() / data.len() as f32
}

fn std_dev(data: &[f32], mean_val: f32) -> f32 {
    if data.len() < 2 {
        return 0.0;
    }
    let variance =
        data.iter().map(|v| (v - mean_val).powi(2)).sum::<f32>() / (data.len() - 1) as f32;
    libm::sqrtf(variance)
}

fn min_or_zero(data: &[f32]) -> f32 {
    data.iter().copied().fold(f32::MAX, f32::min).max(0.0)
}

fn max_or_zero(data: &[f32]) -> f32 {
    data.iter().copied().fold(f32::MIN, f32::max).max(0.0)
}

// Normalize timing values (typically 0–500 ms) to 0–1 range
fn normalize_mean(v: f32) -> f32 {
    libm::tanhf(v / 200.0)
}

fn normalize_std(v: f32) -> f32 {
    libm::tanhf(v / 100.0)
}

// ---------------------------------------------------------------------------
// Extractor registry
// ---------------------------------------------------------------------------

/// Get an extractor for a pure-Rust modality (keystroke, touch, gait).
/// ML-based modalities (face, iris, voice, fingerprint) return a stub
/// that errors with `ModelNotLoaded` — use `get_ml_extractor` instead.
pub fn get_extractor(modality: Modality) -> Result<Box<dyn Extractor>, ExtractionError> {
    match modality {
        Modality::Face | Modality::Iris | Modality::Voice | Modality::Fingerprint => {
            Ok(Box::new(MlStubExtractor(modality)))
        }
        Modality::Keystroke => Ok(Box::new(KeystrokeExtractor)),
        Modality::TouchGesture => Ok(Box::new(TouchExtractor)),
        Modality::Gait => Ok(Box::new(GaitExtractor)),
    }
}

/// Create an ML-based extractor using a loaded ONNX model.
/// Only available when the `ml` feature is enabled.
#[cfg(feature = "ml")]
pub fn get_ml_extractor(
    modality: Modality,
    model_bytes: &[u8],
) -> Result<Box<dyn Extractor>, ExtractionError> {
    let extractor = match modality {
        Modality::Face => Box::new(ml::MlExtractor::face(model_bytes)?),
        Modality::Iris => Box::new(ml::MlExtractor::iris(model_bytes)?),
        Modality::Voice => Box::new(ml::MlExtractor::voice(model_bytes)?),
        Modality::Fingerprint => Box::new(ml::MlExtractor::fingerprint(model_bytes)?),
        _ => return get_extractor(modality),
    };
    Ok(extractor)
}

#[cfg(not(feature = "ml"))]
pub fn get_ml_extractor(
    _modality: Modality,
    _model_bytes: &[u8],
) -> Result<Box<dyn Extractor>, ExtractionError> {
    Err(ExtractionError::ModelNotLoaded("ml feature disabled"))
}

/// Stub that returns `ModelNotLoaded` for ML modalities without tract.
struct MlStubExtractor(Modality);

impl Extractor for MlStubExtractor {
    fn modality(&self) -> Modality {
        self.0
    }
    fn extract(&self, _capture: &RawCapture) -> Result<Embedding, ExtractionError> {
        Err(ExtractionError::ModelNotLoaded(match self.0 {
            Modality::Face => "FaceExtractor",
            Modality::Iris => "IrisExtractor",
            Modality::Voice => "VoiceExtractor",
            Modality::Fingerprint => "FingerprintExtractor",
            _ => "MlStubExtractor",
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{Capture, CaptureMeta, MockCapture, RawCapture};

    #[test]
    fn keystroke_extraction_produces_40_dims() {
        let mut cap = MockCapture::new(Modality::Keystroke);
        let raw = cap.capture().unwrap();
        let emb = KeystrokeExtractor.extract(&raw).unwrap();
        assert_eq!(emb.vector.len(), 40);
        assert_eq!(emb.modality, Modality::Keystroke);
    }

    #[test]
    fn touch_extraction_produces_30_dims() {
        let mut cap = MockCapture::new(Modality::TouchGesture);
        let raw = cap.capture().unwrap();
        let emb = TouchExtractor.extract(&raw).unwrap();
        assert_eq!(emb.vector.len(), 30);
    }

    #[test]
    fn gait_extraction_produces_60_dims() {
        let mut cap = MockCapture::new(Modality::Gait);
        let raw = cap.capture().unwrap();
        let emb = GaitExtractor.extract(&raw).unwrap();
        assert_eq!(emb.vector.len(), 60);
    }

    #[test]
    fn ml_stubs_return_model_not_loaded() {
        let raw = MockCapture::new(Modality::Face).capture().unwrap();
        let extractor = MlStubExtractor(Modality::Face);
        assert!(extractor.extract(&raw).is_err());
    }

    #[test]
    fn keystroke_empty_data_returns_insufficient_data() {
        let raw = RawCapture {
            meta: CaptureMeta {
                modality: Modality::Keystroke,
                width: 0,
                height: 0,
                sample_rate: 0,
                timestamp_ms: 1,
                duration_ms: 0,
            },
            data: vec![],
        };
        let result = KeystrokeExtractor.extract(&raw);
        assert!(matches!(result, Err(ExtractionError::InsufficientData)));
    }

    #[test]
    fn touch_empty_data_returns_invalid_format() {
        let raw = RawCapture {
            meta: CaptureMeta {
                modality: Modality::TouchGesture,
                width: 0,
                height: 0,
                sample_rate: 0,
                timestamp_ms: 1,
                duration_ms: 0,
            },
            data: vec![],
        };
        let result = TouchExtractor.extract(&raw);
        assert!(matches!(result, Err(ExtractionError::InvalidFormat)));
    }

    #[test]
    fn gait_empty_data_returns_invalid_format() {
        let raw = RawCapture {
            meta: CaptureMeta {
                modality: Modality::Gait,
                width: 0,
                height: 0,
                sample_rate: 0,
                timestamp_ms: 1,
                duration_ms: 0,
            },
            data: vec![],
        };
        let result = GaitExtractor.extract(&raw);
        assert!(matches!(result, Err(ExtractionError::InvalidFormat)));
    }

    #[test]
    fn keystroke_invalid_format_returns_error() {
        // 3 bytes is not a multiple of 20 (struct size)
        let raw = RawCapture {
            meta: CaptureMeta {
                modality: Modality::Keystroke,
                width: 0,
                height: 0,
                sample_rate: 0,
                timestamp_ms: 1,
                duration_ms: 0,
            },
            data: vec![0u8; 3],
        };
        let result = KeystrokeExtractor.extract(&raw);
        assert!(result.is_err());
    }

    #[test]
    fn gait_single_frame_extracts_with_default_metrics() {
        // 16 bytes = 1 frame, should produce 60-dim output with default values
        let raw = RawCapture {
            meta: CaptureMeta {
                modality: Modality::Gait,
                width: 0,
                height: 0,
                sample_rate: 0,
                timestamp_ms: 1,
                duration_ms: 0,
            },
            data: vec![0u8; 16],
        };
        let emb = GaitExtractor.extract(&raw).unwrap();
        assert_eq!(emb.vector.len(), 60);
    }
}
