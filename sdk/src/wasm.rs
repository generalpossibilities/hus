#![cfg(feature = "wasm-capture")]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use wasm_bindgen::prelude::*;

use crate::capture::{CaptureMeta, MockCapture, RawCapture};
use crate::config::Modality;
use crate::error::ExtractionError;

// ---------------------------------------------------------------------------
// Modality <-> u32  (user-facing numbering for JS)
// ---------------------------------------------------------------------------
fn u32_to_modality(m: u32) -> Option<Modality> {
    match m {
        0 => Some(Modality::Keystroke),
        1 => Some(Modality::TouchGesture),
        2 => Some(Modality::Gait),
        3 => Some(Modality::Face),
        4 => Some(Modality::Iris),
        5 => Some(Modality::Voice),
        6 => Some(Modality::Fingerprint),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// f32 <-> byte conversions
// ---------------------------------------------------------------------------
fn bytes_to_f32s(bytes: &[u8]) -> Vec<f32> {
    bytes
        .chunks(4)
        .filter_map(|c| {
            if c.len() == 4 {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(c);
                Some(f32::from_le_bytes(arr))
            } else {
                None
            }
        })
        .collect()
}

fn f32s_to_bytes(data: &[f32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(data.len() * 4);
    for &v in data {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    bytes
}

// ---------------------------------------------------------------------------
// Manual JSON helpers (no serde on the crate)
// ---------------------------------------------------------------------------
fn f32s_to_json(data: &[f32]) -> String {
    if data.is_empty() {
        return "[]".into();
    }
    let mut s = String::from("[");
    for (i, v) in data.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&alloc::format!("{}", v));
    }
    s.push(']');
    s
}

fn parse_f32_json(s: &str) -> Vec<f32> {
    let s = s.trim();
    let inner = s
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or("");
    if inner.is_empty() {
        return Vec::new();
    }
    inner
        .split(',')
        .map(|part| part.trim().parse::<f32>().unwrap_or(0.0))
        .collect()
}

fn extract_error_msg(e: &ExtractionError) -> String {
    match e {
        ExtractionError::ModelNotLoaded(msg) => alloc::format!("model not loaded: {}", msg),
        ExtractionError::InsufficientData => "insufficient data".into(),
        ExtractionError::InvalidFormat => "invalid format".into(),
        ExtractionError::DimensionMismatch { expected, got } => {
            alloc::format!("dimension mismatch: expected {}, got {}", expected, got)
        }
        ExtractionError::OnnxLoad(msg) => alloc::format!("ONNX load: {}", msg),
        ExtractionError::OnnxInfer(msg) => alloc::format!("ONNX infer: {}", msg),
    }
}

// ---------------------------------------------------------------------------
// Platform capture implementations
// ---------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
fn capture_impl_raw(modality: Modality) -> Result<RawCapture, crate::error::CaptureError> {
    use crate::capture::Capture;
    match modality {
        Modality::Keystroke => {
            let mut listener = crate::capture::wasm::KeyListener::new();
            let _ = listener.attach();
            listener.capture()
        }
        Modality::TouchGesture => {
            let mut listener = crate::capture::wasm::TouchListener::new();
            let _ = listener.attach();
            listener.capture()
        }
        Modality::Gait => {
            let mut sensor = crate::capture::wasm::MotionSensor::new();
            let _ = sensor.attach();
            sensor.capture()
        }
        _ => {
            let mut mock = MockCapture::new(modality);
            mock.capture()
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn capture_impl_raw(modality: Modality) -> Result<RawCapture, crate::error::CaptureError> {
    use crate::capture::Capture;
    let mut mock = MockCapture::new(modality);
    mock.capture()
}

// ---------------------------------------------------------------------------
// Groth16 / Poseidon / projection
// ---------------------------------------------------------------------------

use crate::projection::derive_and_project;
use crate::prover::{prove_projected, verify_projected};
use crate::MAX_PROJ_DIM;

/// Opaque handle holding serialized Groth16 proving key + verifying key.
/// Created once, reused across multiple proofs.
#[wasm_bindgen]
pub struct HusHandle {
    pk: Vec<u8>,
    vk: Vec<u8>,
}

#[wasm_bindgen]
impl HusHandle {
    /// Create a HusHandle from hex-encoded proving key and verifying key.
    /// Keys are generated off-device (Phase 2 of Powers of Tau) and stored
    /// on-chain in the HusRegistry contract.
    #[wasm_bindgen(constructor)]
    pub fn new(pk_hex: &str, vk_hex: &str) -> Result<HusHandle, JsValue> {
        let pk = hex_decode(pk_hex).ok_or_else(|| JsValue::from_str("invalid pk_hex"))?;
        let vk = hex_decode(vk_hex).ok_or_else(|| JsValue::from_str("invalid vk_hex"))?;
        Ok(HusHandle { pk, vk })
    }

    /// Full pipeline: project embedding through BioHashing, prove with Groth16.
    ///
    /// * `embedding_json` — JSON array of f32 values (e.g. `"[0.1,0.2,...]"`)
    /// * `seed_hex` — 32-byte hex string (64 hex chars)
    /// * `proj_dim` — projection dimension (≤ 128)
    ///
    /// Returns JSON: `{"commitment_hex":"...","proof_hex":"...","v_obf_json":"...","v_obf_scaled":[int64,...]}`
    pub fn project_and_prove(
        &self,
        embedding_json: &str,
        seed_hex: &str,
        proj_dim: usize,
    ) -> Result<String, JsValue> {
        let embedding: Vec<f32> = parse_f32_json(embedding_json);
        let seed = parse_hex32(seed_hex)?;

        if embedding.is_empty() {
            return Err(JsValue::from_str("embedding is empty"));
        }
        let dim = proj_dim.min(MAX_PROJ_DIM);

        let v_obf = derive_and_project(&seed, &embedding, dim)
            .map_err(|e| JsValue::from_str(&alloc::format!("{:?}", e)))?;

        let (proof_bytes, commitment) = prove_projected(&self.pk, &v_obf)
            .map_err(|e| JsValue::from_str(&alloc::format!("{:?}", e)))?;

        let proof_hex = hex_encode(&proof_bytes);
        let commitment_hex = hex_encode(&commitment);
        let v_obf_json = f32s_to_json(&v_obf);
        let v_obf_scaled = vobf_to_fixed(&v_obf);

        let result = alloc::format!(
            r#"{{"commitment_hex":"{}","proof_hex":"{}","v_obf_json":"{}","v_obf_scaled":[{}]}}"#,
            commitment_hex,
            proof_hex,
            v_obf_json,
            v_obf_scaled
                .iter()
                .map(|v| alloc::format!("{}", v))
                .collect::<Vec<_>>()
                .join(",")
        );
        Ok(result)
    }

    /// Verify a Groth16 proof against a commitment and V_obf.
    pub fn verify(&self, proof_hex: &str, commitment_hex: &str, v_obf_json: &str) -> bool {
        let proof_bytes = match hex_decode(proof_hex) {
            Some(b) => b,
            None => return false,
        };
        let commitment = match hex_decode32(commitment_hex) {
            Some(c) => c,
            None => return false,
        };
        let v_obf: Vec<f32> = parse_f32_json(v_obf_json);

        verify_projected(&self.vk, &proof_bytes, &commitment, &v_obf).unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// Standalone helpers (usable without HusHandle instance)
// ---------------------------------------------------------------------------

/// Project an embedding through BioHashing. Returns V_obf as JSON.
#[wasm_bindgen]
pub fn project_wasm(
    embedding_json: &str,
    seed_hex: &str,
    proj_dim: usize,
) -> Result<String, JsValue> {
    let embedding: Vec<f32> = parse_f32_json(embedding_json);
    let seed = parse_hex32(seed_hex)?;
    if embedding.is_empty() {
        return Err(JsValue::from_str("embedding is empty"));
    }
    let dim = proj_dim.min(MAX_PROJ_DIM);
    let v_obf = derive_and_project(&seed, &embedding, dim)
        .map_err(|e| JsValue::from_str(&alloc::format!("{:?}", e)))?;
    Ok(f32s_to_json(&v_obf))
}

/// Convert f32 V_obf JSON to int64[] ×10⁶ fixed-point (for on-chain storage).
#[wasm_bindgen]
pub fn vobf_to_fixed_wasm(v_obf_json: &str) -> Vec<i64> {
    let v_obf: Vec<f32> = parse_f32_json(v_obf_json);
    vobf_to_fixed(&v_obf)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn parse_hex32(s: &str) -> Result<[u8; 32], JsValue> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(JsValue::from_str("seed_hex must be 64 hex chars"));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
            .map_err(|_| JsValue::from_str("invalid hex in seed_hex"))?;
    }
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| alloc::format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn hex_decode32(s: &str) -> Option<[u8; 32]> {
    let v = hex_decode(s)?;
    if v.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Some(out)
}

fn vobf_to_fixed(v_obf: &[f32]) -> Vec<i64> {
    v_obf
        .iter()
        .map(|v| (*v as f64 * 1_000_000.0) as i64)
        .collect()
}

// ---------------------------------------------------------------------------
// wasm_bindgen exports (original)
// ---------------------------------------------------------------------------

fn capture_error_to_js(e: crate::error::CaptureError) -> JsValue {
    JsValue::from_str(&alloc::format!("{:?}", e))
}

/// Capture keystroke data and return raw sensor data as `Vec<f32>`.
#[wasm_bindgen]
pub fn capture_keystroke() -> Result<Vec<f32>, JsValue> {
    capture_impl_raw(Modality::Keystroke)
        .map(|raw| bytes_to_f32s(&raw.data))
        .map_err(capture_error_to_js)
}

/// Capture touch-gesture data and return raw sensor data as `Vec<f32>`.
#[wasm_bindgen]
pub fn capture_touch() -> Result<Vec<f32>, JsValue> {
    capture_impl_raw(Modality::TouchGesture)
        .map(|raw| bytes_to_f32s(&raw.data))
        .map_err(capture_error_to_js)
}

/// Capture gait data and return raw sensor data as `Vec<f32>`.
#[wasm_bindgen]
pub fn capture_gait() -> Result<Vec<f32>, JsValue> {
    capture_impl_raw(Modality::Gait)
        .map(|raw| bytes_to_f32s(&raw.data))
        .map_err(capture_error_to_js)
}

/// Extract an embedding from raw capture data.
///
/// * `modality` — 0=Keystroke, 1=Touch, 2=Gait, 3=Face, 4=Iris, 5=Voice, 6=Fingerprint
/// * `raw_json` — JSON array of f32 values `[f32,...]`
///
/// Returns the embedding vector as a JSON string, or `{"error": "..."}` on failure.
#[wasm_bindgen]
pub fn extract_embedding(modality: u32, raw_json: &str) -> String {
    let m = match u32_to_modality(modality) {
        Some(m) => m,
        None => return alloc::format!(r#"{{"error":"unknown modality: {}"}}"#, modality),
    };

    let raw_values = parse_f32_json(raw_json);
    let raw_bytes = f32s_to_bytes(&raw_values);

    let capture = RawCapture {
        meta: CaptureMeta {
            modality: m,
            width: 0,
            height: 0,
            sample_rate: 0,
            timestamp_ms: 0,
            duration_ms: 0,
        },
        data: raw_bytes,
    };

    let extractor = match crate::extract::get_extractor(m) {
        Ok(e) => e,
        Err(e) => {
            return alloc::format!(r#"{{"error":"{}"}}"#, extract_error_msg(&e));
        }
    };

    match extractor.extract(&capture) {
        Ok(emb) => f32s_to_json(&emb.vector),
        Err(e) => alloc::format!(r#"{{"error":"{}"}}"#, extract_error_msg(&e)),
    }
}

/// Generate a random 32-byte seed and return it as a hex string.
/// Returns an empty string if getrandom fails.
#[wasm_bindgen]
pub fn generate_seed_wasm() -> String {
    let mut seed = [0u8; 32];
    if getrandom::getrandom(&mut seed).is_err() {
        return String::new();
    }
    seed.iter().map(|b| alloc::format!("{:02x}", b)).collect()
}
