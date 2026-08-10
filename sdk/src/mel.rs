//! PCM → mel-spectrogram conversion for the voice modality.
//!
//! Produces a 100×80×1 NHWC float tensor for ECAPA-TDNN ONNX models.

use alloc::vec;
use alloc::vec::Vec;
use core::f64::consts::PI;

use crate::error::ExtractionError;

/// Minimum audio length required for one full frame.
const MIN_SAMPLES: usize = 256;

/// Convert raw PCM i16 samples to a normalized 100×80 mel-spectrogram tensor.
///
/// Parameters:
/// - `pcm`: interleaved i16 PCM samples (mono)
/// - `sample_rate`: sample rate in Hz (e.g. 16000, 48000)
///
/// Returns 8000 f32 values (100 frames × 80 mel bins), NHWC layout.
pub fn pcm_to_mel(pcm: &[i16], sample_rate: u32) -> Result<Vec<f32>, ExtractionError> {
    if pcm.len() < MIN_SAMPLES || sample_rate == 0 {
        return Err(ExtractionError::InsufficientData);
    }

    // Convert to f64 for processing
    let samples: Vec<f64> = pcm.iter().map(|&s| s as f64 / 32768.0).collect();

    // Pre-emphasis
    let emphasized = pre_emphasis(&samples);

    // Frame parameters: 25ms window, 10ms stride
    let frame_len = (sample_rate as f64 * 0.025).round() as usize;
    let frame_stride = (sample_rate as f64 * 0.010).round() as usize;
    let fft_size = next_pow2(frame_len).max(512);

    let raw_frames = frame_count(emphasized.len(), frame_stride, frame_len);
    let target_frames = 100;
    let offset = if raw_frames > target_frames {
        (raw_frames - target_frames) / 2 // center crop
    } else {
        0
    };

    let window = hann_window(frame_len);
    let filters = mel_filterbank(80, fft_size / 2 + 1, sample_rate);

    let mut tensor = Vec::with_capacity(target_frames * 80);

    // Process each frame (up to target_frames starting from offset)
    for i in 0..target_frames {
        let frame_idx = offset + i;
        if frame_idx >= raw_frames {
            tensor.extend_from_slice(&[0.0; 80]);
            continue;
        }

        let start = frame_idx * frame_stride;
        let end = core::cmp::min(start + frame_len, emphasized.len());

        // Apply window
        let mut frame: Vec<f64> = (start..end)
            .map(|j| emphasized[j] * window.get(j - start).copied().unwrap_or(0.0))
            .collect();

        // Zero-pad to fft_size
        frame.resize(fft_size, 0.0);

        // Compute power spectrum
        let spectrum = power_spectrum(&frame);

        // Apply mel filterbank
        let mut mel_energies = vec![0.0f64; 80];
        for (f_idx, filter) in filters.iter().enumerate() {
            let energy: f64 = filter.iter().zip(spectrum.iter()).map(|(w, s)| w * s).sum();
            mel_energies[f_idx] = (energy + 1e-10).ln();
        }

        // Normalize per-frame: mean 0, variance approximately 1
        let mel_mean: f64 = mel_energies.iter().sum::<f64>() / mel_energies.len() as f64;
        for energy in &mel_energies {
            let val = (energy - mel_mean) / 2.0; // approximate std
            tensor.push(val.clamp(-5.0, 5.0) as f32);
        }
    }

    Ok(tensor)
}

/// High-pass pre-emphasis filter: y[t] = x[t] - 0.97 * x[t-1]
fn pre_emphasis(samples: &[f64]) -> Vec<f64> {
    let mut out = Vec::with_capacity(samples.len());
    if let Some(&first) = samples.first() {
        out.push(first);
    }
    for w in samples.windows(2) {
        out.push(w[1] - 0.97 * w[0]);
    }
    out
}

/// Hann window of length N
fn hann_window(n: usize) -> Vec<f64> {
    (0..n)
        .map(|i| 0.5 * (1.0 - (2.0 * PI * i as f64 / (n - 1) as f64).cos()))
        .collect()
}

/// Real FFT: compute power spectrum |FFT|^2 from real input.
/// Returns `fft_size/2 + 1` power values (DC to Nyquist).
fn power_spectrum(samples: &[f64]) -> Vec<f64> {
    let n = samples.len();
    let mut real = samples.to_vec();
    let mut imag = vec![0.0f64; n];

    fft_dit(&mut real, &mut imag);

    let mut power = Vec::with_capacity(n / 2 + 1);
    for i in 0..=n / 2 {
        let r = real[i];
        let im = imag[i];
        let mag2 = r * r + im * im;
        power.push(mag2 / n as f64);
    }
    power
}

/// Decimation-in-time radix-2 FFT (in-place).
/// `real` and `imag` must have the same length, which must be a power of 2.
fn fft_dit(real: &mut [f64], imag: &mut [f64]) {
    let n = real.len();
    if n <= 1 {
        return;
    }

    // Bit-reversal permutation
    let bits = n.trailing_zeros() as usize;
    for i in 0..n {
        let j = bit_reverse(i, bits);
        if j > i {
            real.swap(i, j);
            imag.swap(i, j);
        }
    }

    // Cooley-Tukey iterative radix-2
    let mut len = 2;
    while len <= n {
        let half = len / 2;
        let angle = -PI / half as f64;
        for i in (0..n).step_by(len) {
            for k in 0..half {
                let w_re = (angle * k as f64).cos();
                let w_im = (angle * k as f64).sin();
                let even_idx = i + k;
                let odd_idx = i + k + half;
                let t_re = w_re * real[odd_idx] - w_im * imag[odd_idx];
                let t_im = w_re * imag[odd_idx] + w_im * real[odd_idx];
                real[odd_idx] = real[even_idx] - t_re;
                imag[odd_idx] = imag[even_idx] - t_im;
                real[even_idx] += t_re;
                imag[even_idx] += t_im;
            }
        }
        len <<= 1;
    }
}

fn bit_reverse(mut x: usize, bits: usize) -> usize {
    let mut y = 0;
    for _ in 0..bits {
        y = (y << 1) | (x & 1);
        x >>= 1;
    }
    y
}

/// Build a triangular mel filterbank.
/// `num_filters`: number of mel filters (80)
/// `fft_bins`: number of FFT magnitude bins (fft_size/2 + 1)
/// `sample_rate`: sample rate in Hz
fn mel_filterbank(num_filters: usize, fft_bins: usize, sample_rate: u32) -> Vec<Vec<f64>> {
    let low_mel = hz_to_mel(0.0);
    let high_mel = hz_to_mel(sample_rate as f64 / 2.0);

    // Equally spaced in mel scale
    let mel_points: Vec<f64> = (0..num_filters + 2)
        .map(|i| low_mel + (high_mel - low_mel) * i as f64 / (num_filters + 1) as f64)
        .collect();

    let hz_points: Vec<f64> = mel_points.into_iter().map(mel_to_hz).collect();
    let bin_points: Vec<usize> = hz_points
        .into_iter()
        .map(|hz| (hz / sample_rate as f64 * 2.0 * (fft_bins - 1) as f64).round() as usize)
        .collect();

    let mut filters = vec![vec![0.0f64; fft_bins]; num_filters];
    for m in 0..num_filters {
        let left = bin_points[m];
        let center = bin_points[m + 1];
        let right = bin_points[m + 2];

        if center >= fft_bins {
            continue;
        }

        // Rising slope
        if center > left {
            let rise = 1.0 / (center - left) as f64;
            let end = center.min(fft_bins - 1);
            for (offset, val) in filters[m][left..=end].iter_mut().enumerate() {
                *val = (offset as f64) * rise;
            }
        }

        // Falling slope
        if right > center {
            let fall = 1.0 / (right - center) as f64;
            let end = right.min(fft_bins - 1);
            for (offset, val) in filters[m][center..=end].iter_mut().enumerate() {
                *val = 1.0 - (offset as f64) * fall;
            }
        }
    }

    filters
}

fn hz_to_mel(hz: f64) -> f64 {
    2595.0 * (1.0 + hz / 700.0).log10()
}

fn mel_to_hz(mel: f64) -> f64 {
    700.0 * (10.0_f64.powf(mel / 2595.0) - 1.0)
}

/// Round up to the next power of 2.
fn next_pow2(x: usize) -> usize {
    if x <= 1 {
        return 1;
    }
    let mut n = x - 1;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    #[cfg(target_pointer_width = "64")]
    {
        n |= n >> 32;
    }
    n + 1
}

fn frame_count(samples: usize, stride: usize, frame_len: usize) -> usize {
    if samples < frame_len {
        return 0;
    }
    1 + (samples - frame_len) / stride
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pre_emphasis() {
        let input = vec![1.0, 2.0, 3.0, 4.0];
        let out = pre_emphasis(&input);
        assert!((out[0] - 1.0).abs() < 1e-10);
        assert!((out[1] - (2.0 - 0.97 * 1.0)).abs() < 1e-10);
    }

    #[test]
    fn test_hann_window_sum() {
        let w = hann_window(512);
        let sum: f64 = w.iter().sum();
        assert!((sum - 256.0).abs() < 1.0, "hann sum = {sum}");
    }

    #[test]
    fn test_fft_impulse() {
        let mut real = vec![0.0f64; 512];
        real[0] = 1.0;
        let mut imag = vec![0.0f64; 512];
        fft_dit(&mut real, &mut imag);
        // Impulse → all FFT coefficients = 1
        for i in 0..512 {
            let mag = (real[i] * real[i] + imag[i] * imag[i]).sqrt();
            assert!((mag - 1.0).abs() < 1e-12, "mag[{i}] = {mag}");
        }
    }

    #[test]
    fn test_power_spectrum_impulse() {
        let samples = {
            let mut s = vec![0.0f64; 512];
            s[0] = 1.0;
            s
        };
        let ps = power_spectrum(&samples);
        assert_eq!(ps.len(), 257);
        // Power spectrum divides by n: |X[k]|^2 / n = 1 / 512
        for &p in &ps {
            let expected = 1.0 / 512.0;
            assert!((p - expected).abs() < 1e-12, "power = {p}");
        }
    }

    #[test]
    fn test_next_pow2() {
        assert_eq!(next_pow2(0), 1);
        assert_eq!(next_pow2(1), 1);
        assert_eq!(next_pow2(2), 2);
        assert_eq!(next_pow2(3), 4);
        assert_eq!(next_pow2(511), 512);
        assert_eq!(next_pow2(512), 512);
    }

    #[test]
    fn test_hz_mel_roundtrip() {
        let hz = 1000.0;
        let mel = hz_to_mel(hz);
        let back = mel_to_hz(mel);
        assert!((back - hz).abs() < 0.5);
    }

    #[test]
    fn test_mel_filterbank_shape() {
        let filters = mel_filterbank(80, 257, 16000);
        assert_eq!(filters.len(), 80);
        assert_eq!(filters[0].len(), 257);
    }

    #[test]
    fn test_frame_count() {
        assert_eq!(frame_count(16000, 160, 400), 98);
        assert_eq!(frame_count(100, 10, 50), 6);
        assert_eq!(frame_count(40, 10, 50), 0);
    }

    #[test]
    fn test_pcm_to_mel_output_shape() {
        // Generate 2 seconds of 16kHz sine wave
        let sample_rate = 16000;
        let num_samples = sample_rate * 2;
        let pcm: Vec<i16> = (0..num_samples)
            .map(|i| {
                let t = i as f64 / sample_rate as f64;
                (32767.0 * (2.0 * PI * 440.0 * t).sin()) as i16
            })
            .collect();
        let tensor = pcm_to_mel(&pcm, sample_rate).expect("mel conversion");
        assert_eq!(tensor.len(), 100 * 80, "expected 8000 floats");
        // Check first value is in reasonable range
        assert!(tensor[0].is_finite());
    }

    #[test]
    fn test_pcm_to_mel_short_audio() {
        let pcm = vec![0i16; 100];
        let result = pcm_to_mel(&pcm, 16000);
        assert!(result.is_err());
    }

    #[test]
    fn test_pcm_to_mel_short_resampled() {
        // 8kHz mock data (1 second = 8000 samples) - should work with 16kHz processing
        // The frame_len for 16kHz is 400, so 8000 samples gives ~48 frames
        let pcm = vec![100i16; 8000];
        let tensor = pcm_to_mel(&pcm, 16000).expect("mel conversion");
        assert_eq!(tensor.len(), 8000);
    }
}
