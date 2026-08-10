use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use log::{info, warn};

use crate::capture::RawCapture;
use crate::config::Modality;
use crate::error::CaptureError;
use crate::metrics::HUS_METRICS;

#[derive(Debug, Clone, PartialEq)]
pub enum QualityIssue {
    TooDark,
    TooBright,
    Blurred { sharpness: f32 },
    LowSnr { snr_db: f32 },
    Occlusion { fraction: f32 },
    InsufficientData,
}

#[derive(Debug, Clone)]
pub struct QualityReport {
    pub passed: bool,
    pub issues: Vec<QualityIssue>,
    pub overall_score: u8,
}

pub fn check_quality(capture: &RawCapture) -> Result<QualityReport, CaptureError> {
    if capture.data.is_empty() {
        warn!("quality check failed: empty capture data");
        return Err(CaptureError::InsufficientData);
    }
    let mut issues = Vec::new();
    match capture.meta.modality {
        Modality::Face | Modality::Iris => check_image_quality(capture, &mut issues),
        Modality::Voice => check_audio_quality(capture, &mut issues),
        _ => {} // keystroke, touch, gait have no quality pre-check
    }
    let passed = issues.is_empty();
    if passed {
        HUS_METRICS.quality_passed.fetch_add(1, Ordering::Relaxed);
        info!("quality check passed for {:?}", capture.meta.modality);
    } else {
        HUS_METRICS.quality_failed.fetch_add(1, Ordering::Relaxed);
        warn!(
            "quality check failed for {:?}: {:?}",
            capture.meta.modality, issues
        );
    }
    let overall_score = if passed {
        100
    } else {
        (100u32.saturating_sub(issues.len() as u32 * 25)) as u8
    };
    Ok(QualityReport {
        passed,
        issues,
        overall_score,
    })
}

fn check_image_quality(capture: &RawCapture, issues: &mut Vec<QualityIssue>) {
    let data = &capture.data;
    if data.len() < 16 {
        issues.push(QualityIssue::InsufficientData);
        return;
    }
    let pixel_count = data.len() / 4;
    if pixel_count < 64 {
        issues.push(QualityIssue::InsufficientData);
        return;
    }
    let mut total = 0u64;
    let mut min_val = u8::MAX;
    let mut max_val = u8::MIN;
    let mut samples = 0u32;
    for (_i, &b) in data
        .iter()
        .enumerate()
        .step_by(4)
        .take(4096.min(pixel_count))
    {
        total += b as u64;
        if b < min_val {
            min_val = b;
        }
        if b > max_val {
            max_val = b;
        }
        samples += 1;
    }
    if samples == 0 {
        issues.push(QualityIssue::InsufficientData);
        return;
    }
    let mean = (total / samples as u64) as u8;
    if mean < 20 {
        issues.push(QualityIssue::TooDark);
    }
    if mean > 220 {
        issues.push(QualityIssue::TooBright);
    }
    let contrast = max_val.saturating_sub(min_val);
    if contrast < 15 {
        issues.push(QualityIssue::Blurred {
            sharpness: contrast as f32,
        });
    }
    if pixel_count >= 4096 {
        let black_pixels = data.iter().step_by(4).filter(|&&b| b < 10).count();
        let frac = black_pixels as f32 / pixel_count as f32;
        if frac > 0.4 {
            issues.push(QualityIssue::Occlusion { fraction: frac });
        }
    }
}

fn check_audio_quality(capture: &RawCapture, issues: &mut Vec<QualityIssue>) {
    let data = &capture.data;
    if data.len() < 32 {
        issues.push(QualityIssue::InsufficientData);
        return;
    }
    let samples = data.len() / 2;
    let mut sum_sq = 0.0f64;
    for chunk in data.chunks(2) {
        if chunk.len() < 2 {
            break;
        }
        let val = i16::from_le_bytes([chunk[0], chunk[1]]);
        sum_sq += (val as f64).powi(2);
    }
    let rms = (sum_sq / samples as f64).sqrt();
    if rms < 100.0 {
        let snr_db = if rms <= 0.0 {
            -100.0
        } else {
            20.0 * (rms / 32768.0).log10()
        };
        issues.push(QualityIssue::LowSnr {
            snr_db: snr_db as f32,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{CaptureMeta, RawCapture};

    fn make_image(data: Vec<u8>, width: u32, height: u32) -> RawCapture {
        RawCapture {
            meta: CaptureMeta {
                modality: Modality::Face,
                width,
                height,
                sample_rate: 0,
                timestamp_ms: 0,
                duration_ms: 0,
            },
            data,
        }
    }

    #[test]
    fn good_quality_passes() {
        let mut data = vec![0x80u8; 128 * 128 * 4];
        for (i, val) in data.iter_mut().enumerate() {
            *val = ((i * 7) % 200 + 28) as u8;
        }
        let cap = make_image(data, 128, 128);
        let r = check_quality(&cap).unwrap();
        assert!(r.passed);
    }

    #[test]
    fn too_dark_fails() {
        let data = vec![0x05u8; 128 * 128 * 4];
        let cap = make_image(data, 128, 128);
        let r = check_quality(&cap).unwrap();
        assert!(r.issues.iter().any(|i| matches!(i, QualityIssue::TooDark)));
    }

    #[test]
    fn too_bright_fails() {
        let data = vec![0xF0u8; 128 * 128 * 4];
        let cap = make_image(data, 128, 128);
        let r = check_quality(&cap).unwrap();
        assert!(r
            .issues
            .iter()
            .any(|i| matches!(i, QualityIssue::TooBright)));
    }

    #[test]
    fn occlusion_detected() {
        let mut data = vec![0x80u8; 128 * 128 * 4];
        for i in 0..(data.len() / 2) {
            data[i] = 0x00; // half the image is black
        }
        let cap = make_image(data, 128, 128);
        let r = check_quality(&cap).unwrap();
        assert!(r
            .issues
            .iter()
            .any(|i| matches!(i, QualityIssue::Occlusion { .. })));
    }

    #[test]
    fn empty_data_errors() {
        let cap = make_image(vec![], 0, 0);
        assert!(check_quality(&cap).is_err());
    }

    #[test]
    fn audio_low_snr_detected() {
        let data = vec![0x00u8; 8000]; // silent → RMS=0 → low SNR
        let cap = RawCapture {
            meta: CaptureMeta {
                modality: Modality::Voice,
                width: 0,
                height: 0,
                sample_rate: 8000,
                timestamp_ms: 0,
                duration_ms: 1000,
            },
            data,
        };
        let r = check_quality(&cap).unwrap();
        assert!(r
            .issues
            .iter()
            .any(|i| matches!(i, QualityIssue::LowSnr { .. })));
    }
}
