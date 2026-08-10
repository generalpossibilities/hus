//! ONNX model inference via tract — face, iris, voice, fingerprint.
//!
//! Each modality has a known input shape and preprocessing pipeline.
//! Models are loaded at runtime from bytes (HTTP or bundled asset).

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::f32;

use crate::capture::RawCapture;
use crate::config::Modality;
use crate::error::ExtractionError;
use crate::extract::{Embedding, Extractor};

// tract-onnx crate (behind `ml` feature flag)
use tract_onnx::prelude::*;

// ── Per-modality model metadata ──

#[derive(Clone, Copy)]
pub struct ModelMeta {
    pub modality: Modality,
    /// Input shape (height, width, channels) in NHWC layout.
    /// tract/ONNX uses NHWC in the .onnx files; preprocess produces NHWC.
    pub input_shape: (usize, usize, usize),
    /// Output embedding dimension
    pub output_dim: usize,
    /// Pixel mean for normalization
    pub mean: [f32; 3],
    /// Pixel std for normalization
    pub std: [f32; 3],
    /// Skip tract's declutter/optimizer pass (needed for models with EinSum ops).
    pub skip_optimizer: bool,
}

pub const FACE_MODEL: ModelMeta = ModelMeta {
    modality: Modality::Face,
    input_shape: (112, 112, 3),
    output_dim: 512,
    mean: [0.5, 0.5, 0.5],
    std: [0.5, 0.5, 0.5],
    skip_optimizer: false,
};

pub const IRIS_MODEL: ModelMeta = ModelMeta {
    modality: Modality::Iris,
    input_shape: (128, 128, 3),
    output_dim: 224,
    mean: [0.5, 0.5, 0.5],
    std: [0.5, 0.5, 0.5],
    skip_optimizer: false,
};

pub const VOICE_MODEL: ModelMeta = ModelMeta {
    modality: Modality::Voice,
    input_shape: (100, 80, 1),
    output_dim: 192,
    mean: [0.5, 0.0, 0.0],
    std: [0.5, 1.0, 1.0],
    skip_optimizer: true,
};

pub const FINGERPRINT_MODEL: ModelMeta = ModelMeta {
    modality: Modality::Fingerprint,
    input_shape: (128, 128, 1),
    output_dim: 64,
    mean: [0.5, 0.0, 0.0],
    std: [0.5, 1.0, 1.0],
    skip_optimizer: true,
};

// ── Loaded ONNX model ──

pub struct OnnxModel {
    plan: SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>,
    meta: ModelMeta,
}

impl OnnxModel {
    pub fn load(model_bytes: &[u8], meta: ModelMeta) -> Result<Self, ExtractionError> {
        let (h, w, c) = meta.input_shape;
        let input_shape = tvec!(1isize, h as isize, w as isize, c as isize);

        let pipeline = onnx()
            .model_for_read(&mut &model_bytes[..])
            .map_err(|e| ExtractionError::OnnxLoad(format!("model_for_read: {}", e)))?
            .with_input_fact(0, InferenceFact::dt_shape(f32::datum_type(), input_shape))
            .map_err(|e| ExtractionError::OnnxLoad(format!("input_fact: {}", e)))?;

        let plan = if meta.skip_optimizer {
            pipeline
                .into_typed()
                .map_err(|e| ExtractionError::OnnxLoad(format!("into_typed: {}", e)))?
                .into_runnable()
                .map_err(|e| ExtractionError::OnnxLoad(format!("runnable: {}", e)))?
        } else {
            pipeline
                .into_optimized()
                .map_err(|e| ExtractionError::OnnxLoad(format!("optimize: {}", e)))?
                .into_runnable()
                .map_err(|e| ExtractionError::OnnxLoad(format!("runnable: {}", e)))?
        };

        Ok(OnnxModel { plan, meta })
    }

    pub fn run(&self, input: &[f32]) -> Result<Vec<f32>, ExtractionError> {
        let (h, w, c) = self.meta.input_shape;
        let tensor = Tensor::from_shape(&[1, h, w, c], input)
            .map_err(|e| ExtractionError::OnnxInfer(format!("tensor: {}", e)))?;

        let result = self
            .plan
            .run(tvec!(tensor.into()))
            .map_err(|e| ExtractionError::OnnxInfer(format!("infer: {}", e)))?;

        let output = result[0]
            .to_array_view::<f32>()
            .map_err(|e| ExtractionError::OnnxInfer(format!("output: {}", e)))?;

        let embedding: Vec<f32> = output.iter().copied().collect();
        if embedding.len() != self.meta.output_dim {
            return Err(ExtractionError::OnnxInfer(format!(
                "expected {} dims, got {}",
                self.meta.output_dim,
                embedding.len()
            )));
        }
        Ok(embedding)
    }
}

// ── Tract-based extractor ──

pub struct TractOnnxExtractor {
    modality: Modality,
    model: OnnxModel,
}

impl TractOnnxExtractor {
    pub fn new(modality: Modality, model_bytes: &[u8]) -> Result<Self, ExtractionError> {
        let meta = match modality {
            Modality::Face => &FACE_MODEL,
            Modality::Iris => &IRIS_MODEL,
            Modality::Voice => &VOICE_MODEL,
            Modality::Fingerprint => &FINGERPRINT_MODEL,
            _ => return Err(ExtractionError::ModelNotLoaded("unsupported for ONNX")),
        };
        let model = OnnxModel::load(model_bytes, *meta)?;
        Ok(TractOnnxExtractor { modality, model })
    }
}

impl Extractor for TractOnnxExtractor {
    fn modality(&self) -> Modality {
        self.modality
    }

    fn extract(&self, capture: &RawCapture) -> Result<Embedding, ExtractionError> {
        let meta = match self.modality {
            Modality::Face => &FACE_MODEL,
            Modality::Iris => &IRIS_MODEL,
            Modality::Voice => &VOICE_MODEL,
            Modality::Fingerprint => &FINGERPRINT_MODEL,
            _ => return Err(ExtractionError::ModelNotLoaded("unsupported for ONNX")),
        };

        let input = preprocess(capture, meta)?;
        let vector = self.model.run(&input)?;

        Ok(Embedding {
            modality: self.modality,
            vector,
        })
    }
}

// ── Preprocessing ──

/// Convert raw capture data to normalized float tensor in NHWC layout.
fn preprocess(capture: &RawCapture, meta: &ModelMeta) -> Result<Vec<f32>, ExtractionError> {
    // ── Voice: PCM i16 → mel-spectrogram ──
    if meta.modality == Modality::Voice {
        let bytes_per_sample = 2;
        if capture.data.len() < bytes_per_sample {
            return Err(ExtractionError::InsufficientData);
        }
        let pcm: Vec<i16> = capture
            .data
            .chunks_exact(2)
            .map(|b| i16::from_le_bytes([b[0], b[1]]))
            .collect();
        let sr = if capture.meta.sample_rate > 0 {
            capture.meta.sample_rate
        } else {
            16000
        };
        return crate::mel::pcm_to_mel(&pcm, sr);
    }

    let (h, w, c) = meta.input_shape;
    let expected_pixels = h * w * c;

    // Determine input format from capture metadata or data size.
    let raw_pixels = capture.data.len();

    // Assume RGBA input from canvas (4 bytes per pixel → w*h*4 bytes).
    // Extract the active pixel area: if data is large, it's full camera frame.
    let pixel_count = if raw_pixels >= h * w * 4 {
        h * w
    } else if raw_pixels >= expected_pixels * 4 {
        // Enough RGBA data for expected RGB input
        raw_pixels / 4
    } else {
        return Err(ExtractionError::InsufficientData);
    };

    // Build NCHW tensor with normalization.
    let mut tensor = Vec::with_capacity(expected_pixels);

    if c == 3 {
        // RGB input: interleaved RGBA → planar RGB, resize, normalize.
        let (src_w, src_h) = estimate_dimensions(pixel_count);

        // Sample target pixels with bilinear interpolation.
        for cy in 0..h {
            for cx in 0..w {
                let (sx, sy) = map_coords(cx, cy, w, h, src_w, src_h);
                let src_idx = (sy * src_w + sx) * 4;
                let r = capture.data.get(src_idx).copied().unwrap_or(0) as f32 / 255.0;
                let g = capture.data.get(src_idx + 1).copied().unwrap_or(0) as f32 / 255.0;
                let b = capture.data.get(src_idx + 2).copied().unwrap_or(0) as f32 / 255.0;

                // Normalize per channel.
                tensor.push((r - meta.mean[0]) / meta.std[0]);
                tensor.push((g - meta.mean[1]) / meta.std[1]);
                tensor.push((b - meta.mean[2]) / meta.std[2]);
            }
        }
    } else {
        // Grayscale input (1 channel).
        let (src_w, src_h) = estimate_dimensions(pixel_count);

        for cy in 0..h {
            for cx in 0..w {
                let (sx, sy) = map_coords(cx, cy, w, h, src_w, src_h);
                let src_idx = (sy * src_w + sx) * 4;
                let r = capture.data.get(src_idx).copied().unwrap_or(0) as f32;
                let g = capture.data.get(src_idx + 1).copied().unwrap_or(0) as f32;
                let b = capture.data.get(src_idx + 2).copied().unwrap_or(0) as f32;
                let gray = 0.299 * r + 0.587 * g + 0.114 * b;
                tensor.push((gray / 255.0 - meta.mean[0]) / meta.std[0]);
            }
        }
    }

    // Pad if the tensor is shorter than expected.
    while tensor.len() < expected_pixels {
        tensor.push(0.0);
    }
    tensor.truncate(expected_pixels);

    Ok(tensor)
}

/// Estimate source image dimensions from pixel count.
fn estimate_dimensions(pixel_count: usize) -> (usize, usize) {
    // Assume square-ish aspect ratio.
    let side = (pixel_count as f32).sqrt().ceil() as usize;
    let w = side.min(pixel_count);
    let h = pixel_count / w;
    (w.max(1), h.max(1))
}

/// Map target pixel to source pixel (simple nearest-neighbor — fast, no alloc).
fn map_coords(cx: usize, cy: usize, tw: usize, th: usize, sw: usize, sh: usize) -> (usize, usize) {
    let sx = (cx * sw) / tw;
    let sy = (cy * sh) / th;
    (sx.min(sw - 1), sy.min(sh - 1))
}

// ── Factory ──

/// Create an ONNX-based extractor for the given modality.
/// Returns `None` if the modality doesn't support ONNX.
pub fn try_onnx_extractor(
    modality: Modality,
    model_bytes: &[u8],
) -> Result<TractOnnxExtractor, ExtractionError> {
    TractOnnxExtractor::new(modality, model_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::RawCapture;

    #[test]
    fn test_estimate_dimensions() {
        let (w, h) = estimate_dimensions(112 * 112);
        assert!(w * h >= 112 * 112 - 112);
        assert!(w * h <= 112 * 112 + 112);
    }

    #[test]
    fn test_map_coords() {
        let (sx, sy) = map_coords(0, 0, 112, 112, 640, 480);
        assert_eq!(sx, 0);
        assert_eq!(sy, 0);
        let (sx, sy) = map_coords(111, 111, 112, 112, 640, 480);
        assert_eq!(sx, (111 * 640) / 112);
        assert_eq!(sy, (111 * 480) / 112);
    }

    #[test]
    fn test_face_preprocess_insufficient_data() {
        let meta = &FACE_MODEL;
        let raw = RawCapture {
            meta: crate::capture::CaptureMeta {
                modality: Modality::Face,
                width: 0,
                height: 0,
                sample_rate: 0,
                timestamp_ms: 0,
                duration_ms: 0,
            },
            data: vec![0u8; 10],
        };
        let result = preprocess(&raw, meta);
        assert!(result.is_err());
    }

    #[test]
    fn test_voice_extractor_not_supported_without_ml() {
        #[cfg(not(feature = "ml"))]
        {
            let result = try_onnx_extractor(Modality::Voice, &[]);
            assert!(result.is_err());
        }
    }

    #[cfg(feature = "ml")]
    #[cfg(feature = "std")]
    mod onnx_integration {
        use tract_onnx::prelude::*;

        fn model_path(name: &str) -> std::path::PathBuf {
            let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            p.pop();
            p.push("models");
            p.push(name);
            p
        }

        struct OnnxModelSpec {
            name: &'static str,
            input_shape: &'static [usize],
            input_shape_fact: &'static [isize],
            input_elem_count: usize,
            expected_output_shape: &'static [usize],
            /// Some models crash tract 0.21's declutter pass (e.g. EinSum ops).
            skip_optimizer: bool,
            /// Models whose output dim isn't fixed at export time.
            output_dim_accept: Option<&'static [usize]>,
        }

        const ALL_MODELS: &[OnnxModelSpec] = &[
            OnnxModelSpec {
                name: "arcface.onnx",
                input_shape: &[1, 112, 112, 3],
                input_shape_fact: &[1, 112, 112, 3],
                input_elem_count: 1 * 112 * 112 * 3,
                expected_output_shape: &[1, 512],
                skip_optimizer: false,
                output_dim_accept: None,
            },
            OnnxModelSpec {
                name: "ResNet50_Iris.onnx",
                input_shape: &[1, 128, 128, 3],
                input_shape_fact: &[1, 128, 128, 3],
                input_elem_count: 1 * 128 * 128 * 3,
                expected_output_shape: &[1, 224],
                skip_optimizer: false,
                output_dim_accept: None,
            },
            OnnxModelSpec {
                name: "voxceleb_ECAPA512_LM.onnx",
                input_shape: &[1, 100, 80],
                input_shape_fact: &[1, 100, 80],
                input_elem_count: 1 * 100 * 80,
                expected_output_shape: &[1, 0], // dim checked by output_dim_accept
                skip_optimizer: true,
                output_dim_accept: Some(&[192, 512]),
            },
            // fingerprint_mini.onnx excluded — tract 0.21 Gemm analysis fails;
            // tested separately via OnnxModel::load() below.
        ];

        #[test]
        fn test_all_onnx_models_load_and_infer() {
            for spec in ALL_MODELS {
                let model_bytes = std::fs::read(model_path(spec.name))
                    .unwrap_or_else(|e| panic!("{}: read failed: {}", spec.name, e));

                let pipeline = onnx()
                    .model_for_read(&mut &model_bytes[..])
                    .unwrap_or_else(|e| panic!("{}: model_for_read failed: {}", spec.name, e))
                    .with_input_fact(
                        0,
                        InferenceFact::dt_shape(
                            f32::datum_type(),
                            tvec_from_slice(spec.input_shape_fact),
                        ),
                    )
                    .unwrap_or_else(|e| panic!("{}: with_input_fact failed: {}", spec.name, e));

                let model = if spec.skip_optimizer {
                    pipeline.into_typed().and_then(|m| m.into_runnable())
                } else {
                    pipeline.into_optimized().and_then(|m| m.into_runnable())
                }
                .unwrap_or_else(|e| panic!("{}: into_runnable failed: {}", spec.name, e));

                let data = vec![0.0f32; spec.input_elem_count];
                let tensor = Tensor::from_shape(spec.input_shape, &data)
                    .unwrap_or_else(|e| panic!("{}: tensor creation failed: {}", spec.name, e));

                let result = model
                    .run(tvec!(tensor.into()))
                    .unwrap_or_else(|e| panic!("{}: inference failed: {}", spec.name, e));

                let output = result[0]
                    .to_array_view::<f32>()
                    .unwrap_or_else(|e| panic!("{}: output read failed: {}", spec.name, e));

                let shape: Vec<usize> = output.shape().iter().map(|&d| d).collect();

                assert_eq!(
                    shape[0], 1,
                    "{}: batch dim should be 1, got {:?}",
                    spec.name, shape
                );

                let output_dim = shape[1];
                if let Some(accepted_dims) = spec.output_dim_accept {
                    assert!(
                        accepted_dims.contains(&output_dim),
                        "{}: expected output dim in {:?}, got {} (shape {:?})",
                        spec.name,
                        accepted_dims,
                        output_dim,
                        shape,
                    );
                } else {
                    assert_eq!(
                        &shape, spec.expected_output_shape,
                        "{}: expected shape {:?}, got {:?}",
                        spec.name, spec.expected_output_shape, shape,
                    );
                }
            }
        }

        fn tvec_from_slice(s: &[isize]) -> TVec<isize> {
            s.iter().copied().collect()
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn fingerprint_model_loads_via_onnx_model_api() {
        let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.push("models");
        p.push("fingerprint_mini.onnx");
        let model_bytes = std::fs::read(&p).expect("fingerprint model file");
        let extractor = TractOnnxExtractor::new(Modality::Fingerprint, &model_bytes)
            .expect("fingerprint_mini.onnx should load with NHWC [1,128,128,1] shape");
        assert_eq!(extractor.modality(), Modality::Fingerprint);
    }
}
