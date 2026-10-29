#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod capture;
pub mod circuit;
pub mod config;
pub mod crypto;
pub mod error;
pub mod extract;
pub mod key;
pub mod liveness;
pub mod mel;
pub mod metrics;
#[cfg(all(feature = "ml", feature = "std"))]
pub mod model_downloader;
pub mod model_registry;
#[cfg(feature = "ml")]
pub mod onnx;
pub mod projection;
pub mod prover;
pub mod quality;
pub mod quality_gate;
#[cfg(feature = "wasm-capture")]
pub mod wasm;

#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
pub mod ffi;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub use config::{
    HusConfig, Modality, ModalityConfig, ModalitySelection, DEFAULT_PROJ_DIM, DEFAULT_RAW_DIM,
    DEFAULT_THRESHOLD, UNIQUENESS_MIN_SCORE,
};
pub use error::{CaptureError, ExtractionError, SdkError};
pub use extract::{Embedding, Extractor};
pub use key::SessionKeys;
pub use liveness::{require_liveness, LivenessResult, LivenessSession};
pub use projection::{derive_and_project, derive_matrix, project};
pub use prover::{attestation_challenge, proof_binding, prove_projected, verify_projected};
pub use quality_gate::{QualityGate, QualityReport};

pub(crate) use circuit::r1cs::MAX_PROJ_DIM;
pub(crate) const PROJ_DIM: usize = MAX_PROJ_DIM;

/// Scale used for on-chain V_obf serialization (fixed-point ×10⁶).
///
/// The on-chain contract scores L2 distances against `THRESHOLD_SCALED`
/// (5000000 = distance 5.0 at this scale), so the encoding MUST be fixed-point
/// ×10⁶ — a raw IEEE-754 bit-pattern encoding makes distances meaningless.
pub const V_OBF_SCALE: i64 = 1_000_000;

/// Convert f32 V_obf values to the int64 fixed-point format expected by the
/// on-chain contract (`SCALE = 10⁶`, matching `HusApp.THRESHOLD_SCALED`).
///
/// The output is always exactly `MAX_PROJ_DIM` (128) elements, matching the
/// shape the in-circuit commitment is computed over (`prover.rs` zero-pads
/// `v_obf` to `MAX_PROJ_DIM` before hashing, and `HusApp` requires
/// `vObfLen == projDim` with the default registry `projDim = 128`). Values
/// beyond `MAX_PROJ_DIM` are truncated; shorter vectors are zero-padded.
///
/// Conversion is `(x as f64 * SCALE) as i64` with Rust's saturating
/// float→int semantics (NaN/±Inf saturate to 0 / i64::MAX / i64::MIN).
pub fn v_obf_to_contract(v: &[f32]) -> Vec<i64> {
    let mut padded = alloc::vec![0.0f32; MAX_PROJ_DIM];
    let n = v.len().min(MAX_PROJ_DIM);
    padded[..n].copy_from_slice(&v[..n]);
    padded
        .iter()
        .map(|x| (*x as f64 * V_OBF_SCALE as f64) as i64)
        .collect()
}

/// Per-modality projection + proof result for on-chain submission.
#[derive(Debug, Clone)]
pub struct ModalityProof {
    pub modality: Modality,
    pub proof_bytes: Vec<u8>,
    pub commitment_hash: [u8; 32],
    pub v_obf: Vec<f32>,
}

/// Projection result without proof (for on-chain proving).
#[derive(Debug, Clone)]
pub struct ModalityProj {
    pub modality: Modality,
    pub v_obf: Vec<f32>,
}

/// High-level HUS client for biometric capture → extraction → ZK proof.
///
/// HUS does NOT authenticate users or compare embeddings.
/// It only reports whether captures are valid and generates
/// uniqueness proofs for on-chain commitment.
///
/// Liveness checking is enforced by `project_and_prove()` —
/// pass `&[LivenessResult]` and the method returns error if any modality failed.
pub struct HusClient {
    app_id: String,
    selection: ModalitySelection,
    extractors: BTreeMap<Modality, Box<dyn Extractor>>,
    quality_gate: QualityGate,
    liveness_seed: [u8; 32],
}

impl HusClient {
    pub fn new(app_id: String, selection: ModalitySelection, liveness_seed: [u8; 32]) -> Self {
        let mut extractors = BTreeMap::new();
        for &modality in selection.modalities() {
            if let Ok(extractor) = crate::extract::get_extractor(modality) {
                extractors.insert(modality, extractor);
            }
        }
        let configs = selection.configs().to_vec();
        let quality_gate = QualityGate::new(configs);
        HusClient {
            app_id,
            selection,
            extractors,
            quality_gate,
            liveness_seed,
        }
    }

    /// Create a liveness session for a given modality.
    pub fn create_liveness_session(&self, modality: Modality) -> crate::liveness::LivenessSession {
        crate::liveness::create_session(modality, &self.liveness_seed)
    }

    /// Require liveness for ALL selected modalities. Returns error if any fail.
    pub fn require_all_liveness(
        &self,
        results: &[crate::liveness::LivenessResult],
    ) -> Result<(), &'static str> {
        for r in results {
            crate::liveness::require_liveness(r)?;
        }
        Ok(())
    }

    pub fn modalities(&self) -> &[Modality] {
        self.selection.modalities()
    }

    pub fn modality_count(&self) -> usize {
        self.selection.modalities().len()
    }

    /// Extract an embedding from raw capture data.
    pub fn extract(
        &self,
        modality: Modality,
        capture: &crate::capture::RawCapture,
    ) -> Result<Vec<f32>, ExtractionError> {
        let extractor = self
            .extractors
            .get(&modality)
            .ok_or(ExtractionError::ModelNotLoaded("no extractor"))?;
        let embedding = extractor.extract(capture)?;
        Ok(embedding.vector)
    }

    /// Register an ML-based extractor for a modality.
    pub fn register_ml_extractor(
        &mut self,
        modality: Modality,
        model_bytes: &[u8],
    ) -> Result<(), ExtractionError> {
        let extractor = crate::extract::get_ml_extractor(modality, model_bytes)?;
        self.extractors.insert(modality, extractor);
        Ok(())
    }

    /// Check whether enough modalities passed quality/extraction.
    pub fn check_quality_gate(&self, passed_flags: &[bool]) -> QualityReport {
        self.quality_gate.assess(passed_flags)
    }

    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    /// Project each modality's embedding through its BioHashing matrix, then
    /// generate a per-modality Groth16 proof on-device.
    ///
    /// Requires liveness results for ALL modalities — returns error if any failed.
    /// `pk`: serialized Groth16 proving key (fetched from HUS Registry).
    /// `binding`: [`proof_binding`] of the owner key and the verifier's
    /// challenge; every proof is made for it.
    /// Returns per-modality proof results for on-chain submission.
    pub fn project_and_prove(
        &self,
        pk: &[u8],
        binding: &[u8; 32],
        embeddings: &BTreeMap<Modality, Vec<f32>>,
        seed_fn: fn(Modality) -> [u8; 32],
        liveness_results: &[LivenessResult],
    ) -> Result<Vec<ModalityProof>, SdkError> {
        self.require_all_liveness(liveness_results)
            .map_err(|e| SdkError::CryptoError { reason: e })?;
        let mut results = Vec::new();
        for cfg in self.selection.configs() {
            if let Some(embedding) = embeddings.get(&cfg.modality) {
                let seed = seed_fn(cfg.modality);
                let v_obf = crate::projection::derive_and_project(&seed, embedding, cfg.proj_dim)?;
                let (proof_bytes, commitment_hash) = crate::prover::prove_projected(pk, &v_obf, binding)?;
                results.push(ModalityProof {
                    modality: cfg.modality,
                    proof_bytes,
                    commitment_hash,
                    v_obf,
                });
            }
        }
        Ok(results)
    }

    /// Full pipeline from raw captures: liveness → extract → project → prove.
    ///
    /// Creates liveness sessions per-modality, verifies each challenge against
    /// the capture data, extracts embeddings, projects through the BioHashing
    /// matrix, and generates per-modality Groth16 proofs.
    pub fn project_and_prove_from_captures(
        &self,
        pk: &[u8],
        binding: &[u8; 32],
        captures: &BTreeMap<Modality, crate::capture::RawCapture>,
        seed_fn: fn(Modality) -> [u8; 32],
    ) -> Result<Vec<ModalityProof>, SdkError> {
        let mut results = Vec::new();
        for cfg in self.selection.configs() {
            if let Some(capture) = captures.get(&cfg.modality) {
                // 1. Liveness check on raw capture
                let mut session = self.create_liveness_session(cfg.modality);
                for i in 0..session.challenge_count() {
                    session
                        .verify_response(i, capture)
                        .map_err(|e| SdkError::CryptoError { reason: e })?;
                }
                let lr = session.finalize();
                crate::liveness::require_liveness(&lr)
                    .map_err(|e| SdkError::CryptoError { reason: e })?;

                // 2. Extract embedding
                let extractor = self
                    .extractors
                    .get(&cfg.modality)
                    .ok_or(SdkError::ExtractionFailed("no extractor"))?;
                let embedding = extractor
                    .extract(capture)
                    .map_err(|_| SdkError::ExtractionFailed("extraction failed"))?;

                // 3. Project → Prove
                let seed = seed_fn(cfg.modality);
                let v_obf =
                    crate::projection::derive_and_project(&seed, &embedding.vector, cfg.proj_dim)?;
                let (proof_bytes, commitment_hash) = crate::prover::prove_projected(pk, &v_obf, binding)?;
                results.push(ModalityProof {
                    modality: cfg.modality,
                    proof_bytes,
                    commitment_hash,
                    v_obf,
                });
            }
        }
        Ok(results)
    }

    /// Project each modality's embedding to V_obf without generating a proof.
    /// Use to generate proofs elsewhere (for example the gateway).
    pub fn project_only(
        &self,
        embeddings: &BTreeMap<Modality, Vec<f32>>,
        seed_fn: fn(Modality) -> [u8; 32],
    ) -> Result<Vec<ModalityProj>, SdkError> {
        let mut results = Vec::new();
        for cfg in self.selection.configs() {
            if let Some(embedding) = embeddings.get(&cfg.modality) {
                let seed = seed_fn(cfg.modality);
                let v_obf = crate::projection::derive_and_project(&seed, embedding, cfg.proj_dim)?;
                results.push(ModalityProj {
                    modality: cfg.modality,
                    v_obf,
                });
            }
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{Capture, MockCapture};

    const TEST_LIVENESS_SEED: [u8; 32] = [0xAB; 32];

    #[test]
    fn client_creation_works() {
        let selection =
            ModalitySelection::new(vec![Modality::Keystroke, Modality::TouchGesture]).unwrap();
        let client = HusClient::new("test".into(), selection, TEST_LIVENESS_SEED);
        assert_eq!(client.modalities().len(), 2);
    }

    #[test]
    fn extract_produces_correct_dim() {
        let selection =
            ModalitySelection::new(vec![Modality::Keystroke, Modality::TouchGesture]).unwrap();
        let client = HusClient::new("test".into(), selection, TEST_LIVENESS_SEED);
        let mut cap = MockCapture::new(Modality::Keystroke);
        let raw = cap.capture().unwrap();
        let vec = client.extract(Modality::Keystroke, &raw).unwrap();
        assert_eq!(vec.len(), 40);
    }

    #[test]
    fn liveness_session_created_per_modality() {
        let selection = ModalitySelection::new(vec![Modality::Face, Modality::Voice]).unwrap();
        let client = HusClient::new("test".into(), selection, TEST_LIVENESS_SEED);
        let face = client.create_liveness_session(Modality::Face);
        assert_eq!(face.challenge_count(), 3);
        let voice = client.create_liveness_session(Modality::Voice);
        assert_eq!(voice.challenge_count(), 2);
    }
}
