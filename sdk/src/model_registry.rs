use crate::config::Modality;

/// Metadata for an ONNX model hosted on Hugging Face Hub.
pub struct ModelInfo {
    pub modality: Modality,
    /// Short name used as filename (e.g. `"arcface.onnx"`).
    pub model_name: &'static str,
    /// HF Hub download URL.
    pub url: &'static str,
    /// Expected file size in bytes (for download progress / sanity).
    pub expected_size: Option<u64>,
    /// SHA-256 hex digest for integrity verification (optional).
    pub sha256_hex: Option<&'static str>,
    /// Output embedding dimension after inference.
    pub output_dim: usize,
}

/// All supported ONNX models.
pub const MODELS: &[ModelInfo] = &[
    ModelInfo {
        modality: Modality::Face,
        model_name: "arcface.onnx",
        url: "https://huggingface.co/hus-sdk/onnx-models/resolve/main/arcface.onnx",
        expected_size: Some(131_000_000),
        sha256_hex: Some("ffe014a45c9488506719d37fd578ece6661bb385535b36e8039975fa5d4683db"),
        output_dim: 512,
    },
    ModelInfo {
        modality: Modality::Iris,
        model_name: "ResNet50_Iris.onnx",
        url: "https://huggingface.co/hus-sdk/onnx-models/resolve/main/ResNet50_Iris.onnx",
        expected_size: Some(99_000_000),
        sha256_hex: Some("7e29ec607d881605ed44d24d059afc83c9a1796eb78ee235c0874de3124233a7"),
        output_dim: 224,
    },
    ModelInfo {
        modality: Modality::Voice,
        model_name: "voxceleb_ECAPA512_LM.onnx",
        url: "https://huggingface.co/hus-sdk/onnx-models/resolve/main/voxceleb_ECAPA512_LM.onnx",
        expected_size: Some(24_000_000),
        sha256_hex: Some("d71b85d9b48058ef68004f04f1b78acebefb9dfcf542e19b976a12a5ad1f10b0"),
        output_dim: 192,
    },
    ModelInfo {
        modality: Modality::Fingerprint,
        model_name: "fingerprint_mini.onnx",
        url: "https://huggingface.co/hus-sdk/onnx-models/resolve/main/fingerprint_mini.onnx",
        expected_size: Some(4_000_000),
        sha256_hex: Some("f634f4e946bb1ce28cf2c0d09bf6c2f622248a03a3b58ffdebc5d8a836856109"),
        output_dim: 64,
    },
];

/// Look up model metadata by modality.
pub fn get_model_info(modality: Modality) -> Option<&'static ModelInfo> {
    MODELS.iter().find(|m| m.modality == modality)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_modalities_have_models() {
        for m in &[
            Modality::Face,
            Modality::Iris,
            Modality::Voice,
            Modality::Fingerprint,
        ] {
            assert!(get_model_info(*m).is_some(), "{:?} missing model", m);
        }
    }

    #[test]
    fn non_ml_modality_returns_none() {
        assert!(get_model_info(Modality::Keystroke).is_none());
        assert!(get_model_info(Modality::TouchGesture).is_none());
        assert!(get_model_info(Modality::Gait).is_none());
    }

    #[test]
    fn model_names_have_extensions() {
        for info in MODELS {
            assert!(
                info.model_name.ends_with(".onnx"),
                "{}: must end with .onnx",
                info.model_name
            );
        }
    }
}
