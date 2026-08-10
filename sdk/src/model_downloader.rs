use std::collections::HashMap;
use std::io::Read;
use std::sync::Mutex;

use alloc::vec::Vec;

use crate::config::Modality;
use crate::error::ExtractionError;
use crate::model_registry::{get_model_info, ModelInfo};

/// In-memory cache: modality → downloaded model bytes.
static MODEL_CACHE: Mutex<Option<HashMap<Modality, Vec<u8>>>> = Mutex::new(None);

/// Download a model from Hugging Face Hub, or return cached bytes.
///
/// If `local_path` is `Some(...)`, the file is loaded from disk first
/// (useful for development / offline testing without network).
pub fn download_model(
    modality: Modality,
    local_path: Option<&str>,
) -> Result<Vec<u8>, ExtractionError> {
    let info = get_model_info(modality)
        .ok_or_else(|| ExtractionError::ModelNotLoaded("no model registered for this modality"))?;

    if let Some(bytes) = try_cache(modality) {
        return Ok(bytes);
    }

    let bytes = if let Some(path) = local_path {
        std::fs::read(path)
            .map_err(|e| ExtractionError::OnnxLoad(format!("read local model {}: {}", path, e)))?
    } else {
        download_from_hf(info)?
    };

    validate_model(&bytes, info)?;
    insert_cache(modality, bytes.clone());
    Ok(bytes)
}

/// Download model bytes from Hugging Face Hub via HTTPS.
fn download_from_hf(info: &ModelInfo) -> Result<Vec<u8>, ExtractionError> {
    let resp = ureq::get(info.url).call().map_err(|e| {
        ExtractionError::OnnxLoad(format!("HTTP download {}: {}", info.model_name, e))
    })?;

    let mut bytes = Vec::new();
    let len: usize = resp
        .header("Content-Length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    if len > 0 {
        bytes.reserve(len);
    }

    let reader = resp.into_reader();
    std::io::Read::take(reader, 200_000_000)
        .read_to_end(&mut bytes)
        .map_err(|e| {
            ExtractionError::OnnxLoad(format!("read response {}: {}", info.model_name, e))
        })?;

    Ok(bytes)
}

/// Validate model bytes against expected size and SHA-256.
fn validate_model(bytes: &[u8], info: &ModelInfo) -> Result<(), ExtractionError> {
    if let Some(expected) = info.expected_size {
        let actual = bytes.len() as u64;
        let tolerance = (expected as f64 * 0.05) as u64;
        if actual.abs_diff(expected) > tolerance {
            return Err(ExtractionError::OnnxLoad(format!(
                "{}: size mismatch: expected ~{}, got {}",
                info.model_name, expected, actual
            )));
        }
    }
    if let Some(hex_digest) = info.sha256_hex {
        use sha2::{Digest, Sha256};
        let actual_hash = Sha256::digest(bytes);
        let expected_hash = decode_hex(hex_digest).ok_or_else(|| {
            ExtractionError::OnnxLoad(format!("{}: invalid sha256_hex", info.model_name))
        })?;
        if actual_hash.as_slice() != expected_hash.as_slice() {
            return Err(ExtractionError::OnnxLoad(format!(
                "{}: SHA-256 mismatch",
                info.model_name
            )));
        }
    }
    Ok(())
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn try_cache(modality: Modality) -> Option<Vec<u8>> {
    let cache = MODEL_CACHE.lock().ok()?;
    cache.as_ref()?.get(&modality).cloned()
}

fn insert_cache(modality: Modality, bytes: Vec<u8>) {
    if let Ok(mut cache) = MODEL_CACHE.lock() {
        cache
            .get_or_insert_with(HashMap::new)
            .insert(modality, bytes);
    }
}

/// Clear the in-memory model cache.
pub fn clear_cache() {
    if let Ok(mut cache) = MODEL_CACHE.lock() {
        *cache = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_size_accepts() {
        let info = ModelInfo {
            modality: Modality::Face,
            model_name: "test.onnx",
            url: "",
            expected_size: Some(100),
            sha256_hex: None,
            output_dim: 512,
        };
        assert!(validate_model(&vec![0u8; 100], &info).is_ok());
        assert!(validate_model(&vec![0u8; 103], &info).is_ok());
        assert!(validate_model(&vec![0u8; 150], &info).is_err());
    }

    #[test]
    fn cache_roundtrip() {
        clear_cache();
        let data = vec![1u8, 2, 3];
        insert_cache(Modality::Face, data.clone());
        assert_eq!(try_cache(Modality::Face), Some(data));
        assert_eq!(try_cache(Modality::Iris), None);
        clear_cache();
        assert_eq!(try_cache(Modality::Face), None);
    }

    #[test]
    fn decode_hex_works() {
        assert_eq!(decode_hex("aabb"), Some(vec![0xaa, 0xbb]));
        assert_eq!(decode_hex("abc"), None);
    }
}
