//! Face enrolment in one session: liveness, identity, projection, proof and
//! the attestation challenge, all from the same tracked face.
//!
//! The integrator feeds camera frames and face signals in, and gets back a
//! finished request plus the 32-byte challenge to attest. It never handles a
//! vector, an embedding or a proof input of its own choosing, so a genuine,
//! attested app can't be used to register a made-up face.
//!
//! ```text
//! FaceEnrollment::new(challenge)      challenge = the verifier's single-use challenge
//!   .push(signals, frame) ...         until status().phase == Done
//!   .finish(model, pk, seed, owner, app)
//!     → Enrollment { commitment, v_obf, proof, binding, attestation_challenge }
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use crate::config::{Modality, DEFAULT_PROJ_DIM};
use crate::face::Frame;
use crate::face_liveness::{Action, FaceLiveness, FaceSignals, LivenessConfig, Phase, Status};
use crate::projection::derive_and_project;
use crate::prover::{attestation_challenge, proof_binding, ProverKey};
use crate::v_obf_to_contract;

#[derive(Debug, Clone, PartialEq)]
pub enum EnrollError {
    BadChallenge,
    NotLive,
    DifferentFaces { min_similarity: f32 },
    WrongModel,
    Model(String),
    Prove(String),
}

impl core::fmt::Display for EnrollError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EnrollError::BadChallenge => write!(f, "challenge must be at least 16 bytes"),
            EnrollError::NotLive => write!(f, "the liveness check has not passed"),
            EnrollError::DifferentFaces { min_similarity } => {
                write!(f, "the face changed during the session (similarity {min_similarity:.2})")
            }
            EnrollError::WrongModel => write!(f, "face model does not match the pinned model"),
            EnrollError::Model(e) => write!(f, "face model: {e}"),
            EnrollError::Prove(e) => write!(f, "prove: {e}"),
        }
    }
}

/// The face model, checked against the SHA-256 HUS pins for it.
pub struct FaceModel {
    inner: ModelImpl,
}

enum ModelImpl {
    #[cfg(feature = "ml")]
    Onnx(crate::onnx::TractOnnxExtractor),
    #[cfg(test)]
    Fake(fn(&[u8]) -> Vec<f32>),
}

impl FaceModel {
    /// Load the face model. Refused unless its SHA-256 is the one in
    /// [`crate::model_registry`]: every app must embed faces the same way.
    #[cfg(feature = "ml")]
    pub fn load(bytes: &[u8]) -> Result<Self, EnrollError> {
        let info = crate::model_registry::get_model_info(Modality::Face).ok_or(EnrollError::WrongModel)?;
        let want = info.sha256_hex.ok_or(EnrollError::WrongModel)?;
        let got = crate::key::sha256(bytes);
        let mut hex = String::with_capacity(64);
        for b in got {
            use core::fmt::Write;
            let _ = write!(hex, "{b:02x}");
        }
        if hex != want {
            return Err(EnrollError::WrongModel);
        }
        crate::onnx::TractOnnxExtractor::new(Modality::Face, bytes)
            .map(|m| FaceModel { inner: ModelImpl::Onnx(m) })
            .map_err(|e| EnrollError::Model(alloc::format!("{e:?}")))
    }

    #[cfg(test)]
    pub(crate) fn fake(f: fn(&[u8]) -> Vec<f32>) -> Self {
        FaceModel { inner: ModelImpl::Fake(f) }
    }

    #[allow(unused_variables)]
    fn embed(&self, crop: &[u8]) -> Result<Vec<f32>, EnrollError> {
        match &self.inner {
            #[cfg(feature = "ml")]
            ModelImpl::Onnx(m) => {
                use crate::extract::Extractor;
                let capture = crate::capture::RawCapture {
                    meta: crate::capture::CaptureMeta {
                        modality: Modality::Face,
                        width: crate::face::ALIGNED_SIZE as u32,
                        height: crate::face::ALIGNED_SIZE as u32,
                        sample_rate: 0,
                        timestamp_ms: 0,
                        duration_ms: 0,
                    },
                    data: crop.to_vec(),
                };
                m.extract(&capture)
                    .map(|e| e.vector)
                    .map_err(|e| EnrollError::Model(alloc::format!("{e:?}")))
            }
            #[cfg(test)]
            ModelImpl::Fake(f) => Ok(f(crop)),
            #[allow(unreachable_patterns)]
            _ => Err(EnrollError::WrongModel),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EnrollConfig {
    pub liveness: LivenessConfig,
    /// Lowest cosine similarity allowed between any two crops of the session.
    pub min_similarity: f32,
}

impl Default for EnrollConfig {
    fn default() -> Self {
        EnrollConfig { liveness: LivenessConfig::default(), min_similarity: 0.5 }
    }
}

/// A finished request, ready for the verifier once attested.
#[derive(Debug, Clone, PartialEq)]
pub struct Enrollment {
    pub modality_id: u8,
    pub commitment: [u8; 32],
    /// Fixed-point vector as the contract stores it (`v_obf_to_contract`).
    pub v_obf: Vec<i64>,
    pub proof: Vec<u8>,
    pub binding: [u8; 32],
    /// What the device's hardware attestation must carry.
    pub attestation_challenge: [u8; 32],
    /// Lowest similarity seen between the session's face crops (1 for
    /// other modalities).
    pub min_similarity: f32,
}

pub struct FaceEnrollment {
    cfg: EnrollConfig,
    challenge: Vec<u8>,
    liveness: FaceLiveness,
}

impl FaceEnrollment {
    pub fn new(challenge: &[u8], cfg: EnrollConfig) -> Result<Self, EnrollError> {
        let liveness = FaceLiveness::new(challenge, cfg.liveness).ok_or(EnrollError::BadChallenge)?;
        Ok(FaceEnrollment { cfg, challenge: challenge.to_vec(), liveness })
    }

    pub fn actions(&self) -> &[Action] {
        self.liveness.actions()
    }

    pub fn status(&self) -> Status {
        self.liveness.status()
    }

    pub fn push(&mut self, signals: &FaceSignals, frame: Option<&Frame>) -> Status {
        self.liveness.push(signals, frame)
    }

    /// Embed the session's crops, check they are one face, project with the
    /// app's `projection_seed`, prove for `owner_pubkey` and the session's
    /// challenge, and compute the attestation challenge for `app_address`.
    pub fn finish(
        &self,
        model: &FaceModel,
        pk: &ProverKey,
        projection_seed: &[u8; 32],
        owner_pubkey: &[u8],
        app_address: &str,
    ) -> Result<Enrollment, EnrollError> {
        if self.liveness.status().phase != Phase::Done {
            return Err(EnrollError::NotLive);
        }
        let crops = self.liveness.crops().ok_or(EnrollError::NotLive)?;
        let mut embeddings = Vec::with_capacity(crops.len());
        for c in crops {
            embeddings.push(model.embed(c)?);
        }
        let dim = embeddings[0].len();
        if dim == 0 || embeddings.iter().any(|e| e.len() != dim || e.iter().any(|v| !v.is_finite())) {
            return Err(EnrollError::Model("bad embedding".into()));
        }
        let mut min_sim = 1.0f32;
        for i in 0..embeddings.len() {
            for j in i + 1..embeddings.len() {
                min_sim = min_sim.min(cosine(&embeddings[i], &embeddings[j]));
            }
        }
        if !(min_sim >= self.cfg.min_similarity) {
            return Err(EnrollError::DifferentFaces { min_similarity: min_sim });
        }
        let mut mean = alloc::vec![0.0f32; dim];
        for e in &embeddings {
            for (m, v) in mean.iter_mut().zip(e) {
                *m += v / embeddings.len() as f32;
            }
        }

        let mut r = seal(&self.challenge, &mean, Modality::Face, pk, projection_seed, owner_pubkey, app_address)?;
        r.min_similarity = min_sim;
        Ok(r)
    }
}

/// Project an embedding captured in a passed session, prove it for the
/// owner and the session's challenge, and compute the attestation challenge.
pub(crate) fn seal(
    challenge: &[u8],
    embedding: &[f32],
    modality: Modality,
    pk: &ProverKey,
    projection_seed: &[u8; 32],
    owner_pubkey: &[u8],
    app_address: &str,
) -> Result<Enrollment, EnrollError> {
    let v_obf = derive_and_project(projection_seed, embedding, DEFAULT_PROJ_DIM)
        .map_err(|e| EnrollError::Prove(alloc::format!("{e:?}")))?;
    let binding = proof_binding(owner_pubkey, challenge);
    let (proof, commitment) =
        pk.prove(&v_obf, &binding).map_err(|e| EnrollError::Prove(alloc::format!("{e:?}")))?;
    let v_obf = v_obf_to_contract(&v_obf);
    let modality_id = modality.id();
    let attestation_challenge =
        attestation_challenge(app_address, modality_id, &commitment, &v_obf, &proof, &binding);
    Ok(Enrollment {
        modality_id,
        commitment,
        v_obf,
        proof,
        binding,
        attestation_challenge,
        min_similarity: 1.0,
    })
}

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let (mut ab, mut aa, mut bb) = (0.0f32, 0.0f32, 0.0f32);
    for (x, y) in a.iter().zip(b) {
        ab += x * y;
        aa += x * x;
        bb += y * y;
    }
    let d = libm::sqrtf(aa) * libm::sqrtf(bb);
    if d > 0.0 {
        ab / d
    } else {
        0.0
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::face_liveness::tests::{frame, image, passing_trace, CHALLENGE};

    // A stand-in model: the embedding is the crop's colour histogram, so the
    // same scene gives the same vector and a different one doesn't.
    fn histogram(crop: &[u8]) -> Vec<f32> {
        let mut h = alloc::vec![0.0f32; 48];
        for p in crop.chunks_exact(4) {
            for c in 0..3 {
                h[c * 16 + (p[c] as usize >> 4)] += 1.0;
            }
        }
        h
    }

    pub(crate) fn pk() -> ProverKey {
        ProverKey::load(&std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../keep/pk.bin")).expect("keep/pk.bin"))
            .expect("keep/pk.bin is the pinned proving key")
    }

    fn vk() -> Vec<u8> {
        std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../keep/vk.bin")).expect("keep/vk.bin")
    }

    fn live_session(img: &[u8]) -> FaceEnrollment {
        let f = frame(img);
        let mut e = FaceEnrollment::new(&CHALLENGE, EnrollConfig::default()).unwrap();
        for s in passing_trace() {
            e.push(&s, Some(&f));
        }
        assert_eq!(e.status().phase, Phase::Done);
        e
    }

    #[test]
    fn finish_refuses_until_live() {
        let e = FaceEnrollment::new(&CHALLENGE, EnrollConfig::default()).unwrap();
        let m = FaceModel::fake(histogram);
        assert_eq!(e.finish(&m, &pk(), &[1; 32], &[2; 32], "0:ab").unwrap_err(), EnrollError::NotLive);
        assert_eq!(FaceEnrollment::new(&[1; 4], EnrollConfig::default()).err(), Some(EnrollError::BadChallenge));
    }

    #[test]
    fn crops_of_different_faces_are_refused() {
        let img = image();
        let e = live_session(&img);
        // Each call returns a vector pointing somewhere else.
        fn drifting(_: &[u8]) -> Vec<f32> {
            static N: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
            let n = N.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let mut v = alloc::vec![0.0f32; 8];
            v[n % 8] = 1.0;
            v
        }
        let r = e.finish(&FaceModel::fake(drifting), &pk(), &[1; 32], &[2; 32], "0:ab");
        assert!(matches!(r, Err(EnrollError::DifferentFaces { .. })), "{r:?}");
    }

    #[test]
    fn a_live_session_gives_a_request_the_verifier_accepts() {
        let img = image();
        let e = live_session(&img);
        let owner = [9u8; 32];
        let r = e
            .finish(&FaceModel::fake(histogram), &pk(), &[3; 32], &owner, " 0:AbC ")
            .unwrap();
        assert_eq!(r.modality_id, Modality::Face.id());
        assert_eq!(r.v_obf.len(), crate::MAX_PROJ_DIM);
        assert!(r.min_similarity > 0.99);
        assert_eq!(r.binding, proof_binding(&owner, &CHALLENGE));
        assert!(crate::verify_projected(&vk(), &r.proof, &r.commitment, &r.v_obf, &r.binding).unwrap());
        assert_eq!(
            r.attestation_challenge,
            attestation_challenge("0:abc", r.modality_id, &r.commitment, &r.v_obf, &r.proof, &r.binding)
        );
    }

    #[cfg(feature = "ml")]
    #[test]
    fn only_the_pinned_face_model_loads() {
        assert!(matches!(FaceModel::load(b"not a model"), Err(EnrollError::WrongModel)));
    }
}
