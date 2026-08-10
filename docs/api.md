# HUS API Reference

## 1. Rust SDK (`hus-sdk`)

### 1.1 Core Types

```rust
/// One of 7 supported biometric modalities.
pub enum Modality {
    Face,           // 0 — front camera, ArcFace ONNX
    Iris,           // 1 — high-res camera, ResNet50 ONNX
    Voice,          // 2 — microphone, ECAPA-TDNN ONNX
    Fingerprint,    // 3 — capacitive/ultrasonic sensor, ONNX
    Keystroke,      // 4 — keyboard timing (pure Rust)
    TouchGesture,   // 5 — touch gestures (pure Rust)
    Gait,           // 6 — accelerometer (pure Rust)
}

/// App selects 2–7 modalities. Enforced at construction.
pub struct ModalitySelection { /* ... */ }

/// Per-modality configuration.
pub struct ModalityConfig {
    pub modality: Modality,
    pub raw_dim: usize,
    pub proj_dim: usize,     // SDK-side; on-chain uses hardcoded 128
    pub threshold: f32,
    pub min_score: u8,
    pub stability_pct: u8,
}
```

### 1.2 HusClient

```rust
impl HusClient {
    pub fn new(
        app_id: String,
        selection: ModalitySelection,
        liveness_seed: [u8; 32],
    ) -> Self;

    pub fn modalities(&self) -> &[Modality];

    pub fn modality_configs(&self) -> &[ModalityConfig];

    pub fn extract(
        &self, modality: Modality,
        capture: &RawCapture,
    ) -> Result<Vec<f32>, ExtractionError>;

    pub fn project_and_prove(
        &self, pk: &[u8],
        embeddings: &BTreeMap<Modality, Vec<f32>>,
        seed_fn: fn(Modality) -> [u8; 32],
        liveness_results: &[LivenessResult],
    ) -> Result<Vec<ModalityProof>, SdkError>;

    pub fn project_and_prove_from_captures(
        &self, pk: &[u8],
        captures: &BTreeMap<Modality, RawCapture>,
        seed_fn: fn(Modality) -> [u8; 32],
    ) -> Result<Vec<ModalityProof>, SdkError>;

    pub fn project_only(
        &self,
        embeddings: &BTreeMap<Modality, Vec<f32>>,
        seed_fn: fn(Modality) -> [u8; 32],
    ) -> Result<Vec<ModalityProj>, SdkError>;

    pub fn check_quality_gate(&self, passed: &[bool]) -> QualityReport;
}
```

### 1.3 Proof Types

```rust
pub struct ModalityProof {
    pub modality: Modality,
    pub proof_bytes: Vec<u8>,
    pub commitment_hash: [u8; 32],
    pub v_obf: Vec<f32>,
}

pub struct ModalityProj {
    pub modality: Modality,
    pub v_obf: Vec<f32>,
}

/// Convert f32 V_obf to int64 for on-chain contract.
pub fn v_obf_to_contract(v: &[f32]) -> Vec<i64>;
```

### 1.4 Capture Pipeline

```rust
pub struct RawCapture { pub meta: CaptureMeta, pub data: Vec<u8> }

pub struct CaptureMeta {
    pub modality: Modality,
    pub width: u32, pub height: u32,
    pub sample_rate: u32, pub timestamp_ms: u64, pub duration_ms: u32,
}

pub trait Capture { fn capture(&mut self) -> Result<RawCapture, CaptureError>; }

// WASM impls: WebcamCapture, MicCapture, KeyListener, TouchListener, MotionSensor
// Test: MockCapture
```

### 1.5 Quality Pre-check

```rust
pub enum QualityIssue { TooDark, TooBright, Blurred, LowSnr, Occlusion, InsufficientData }
pub struct QualityReport { pub passed: bool, pub issues: Vec<QualityIssue> }
pub fn check_quality(capture: &RawCapture) -> Result<QualityReport, CaptureError>;
```

### 1.6 Liveness Detection

```rust
pub struct LivenessSession { /* ... */ }
impl LivenessSession {
    pub fn challenge_count(&self) -> usize;
    pub fn verify_response(&mut self, index: usize) -> Result<(), CaptureError>;
    pub fn finalize(self) -> LivenessResult;
}
pub fn require_liveness(result: &LivenessResult) -> Result<(), CaptureError>;
pub fn create_session(modality: Modality, seed: &[u8; 32]) -> LivenessSession;
```

### 1.7 Crypto (Poseidon + Groth16)

```rust
use ark_bn254::Fr;
use ark_groth16::{ProvingKey, VerifyingKey};

/// Poseidon hash over Fr elements.
pub fn hash_commitment(inputs: &[Fr]) -> Fr;

/// BioHashing projection + Groth16 proof in one call.
pub fn prove_projected(pk: &[u8], v_obf: &[f32])
    -> Result<(Vec<u8>, [u8; 32]), SdkError>;

/// Verify a Groth16 proof off-chain.
pub fn verify_projected(
    vk: &[u8], proof_bytes: &[u8],
    commitment: &[u8; 32], v_obf: &[f32],
) -> Result<bool, SdkError>;
```

### 1.8 Projection (BioHashing)

```rust
pub fn derive_and_project(seed: &[u8; 32], embedding: &[f32], proj_dim: usize) -> Vec<f32>;
pub fn derive_matrix(seed: &[u8; 32], proj_dim: usize, raw_dim: usize) -> Vec<Vec<f32>>;
pub fn project(matrix_rows: &[Vec<f32>], embedding: &[f32]) -> Vec<f32>;
```

### 1.9 Key Derivation

```rust
pub fn derive_hierarchy(root_seed: &[u8; 32]) -> SessionKeys;
pub struct SessionKeys {
    pub session_key: [u8; 32],
    pub private_signing_key: [u8; 32],
    pub client_seed: [u8; 32],
}
```

### 1.10 Error Types

```rust
pub enum SdkError {
    MatrixDimensionMismatch { expected: usize, got: usize },
    VectorDimensionMismatch { expected: usize, got: usize },
    InvalidSeed,
    CryptoError { reason: &'static str },
    ModalityNotSupported(&'static str),
    ModalitySelectionTooFew { got: usize, min: usize },
}

pub enum CaptureError { NotSupported, DeviceNotAvailable, PermissionDenied, Timeout, /* ... */ }
pub enum ExtractionError { ModelNotLoaded, InvalidFormat, OnnxLoad(String), OnnxInfer(String), /* ... */ }
```

## 2. On-Chain Rust Wrappers (`hus-onchain`)

### 2.1 HusRegistry

| Method | Signature | Description |
|--------|-----------|-------------|
| `register_app` | `(appName: &str, modalityIds: &[u8], signer) → ResultOfSendMessage` | Deploy a new HusApp |
| `set_proving_key` | `(pk: &str, signer) → ResultOfSendMessage` | Set full PK (owner) |
| `set_vk` | `(vk: &str, signer) → ResultOfSendMessage` | Set VK (owner) |
| `set_proving_key_chunk` | `(index: u16, chunk: &[u8], signer) → ResultOfSendMessage` | Upload PK chunk (owner) |
| `clear_proving_key_chunks` | `(signer)` | Reset chunk store (owner) |
| `set_proving_key_hash` | `(hash: &str, signer)` | Set SHA-256 PK hash (owner) |
| `upload_proving_key` | `(pk_bytes: &[u8], signer)` | Full PK upload in chunks |
| `fetch_proving_key` | `() → Vec<u8>` | Reassemble PK from chunks |
| `propose_app_upgrade` | `(appId: &str, newCode: &str, newVk: &str, signer)` | Queue upgrade (owner) |
| `cancel_app_upgrade` | `(appId: &str, signer)` | Cancel pending upgrade (owner) |
| `execute_app_upgrade` | `(appId: &str, signer)` | Execute after delay |
| `get_app_address` | `(appId: &str) → String` | View |
| `get_proving_key` | `() → String` | View |
| `get_vk` | `() → String` | View |
| `get_proving_key_chunk` | `(index: u16) → String` | View |
| `get_proving_key_chunk_count` | `() → u16` | View |
| `get_proving_key_hash` | `() → String` | View |
| `get_version` | `() → String` | Returns "2.4.2" |

### 2.2 HusApp

| Method | Signature | Description |
|--------|-----------|-------------|
| `submit_commitment` | `(commitmentHash: &str, vObf: &[i64], modalityId: u8, signer) → Value` | Off-chain-verified submission (working path) |
| `submit_with_proof` | `(vObf: &[i64], proof: &str, commitment: &str, modalityId: u8, signer)` | Submit with on-chain proof (blocked) |
| `deposit` | `(paymentId: &str, signer)` | Convert SHELL → VMSHELL |
| `check_duplicate` | `(commitmentHash: &str) → bool` | View |
| `get_registration` | `(index: u32) → RegistrationInfo` | View |
| `get_registration_count` | `() → u32` | View |
| `get_app_info` | `() → AppInfo` | Returns vk, appVersion, seedHash, registrationCount |
| `get_balance` | `() → String` | View |
| `get_verification_fee` | `() → String` | Returns "300000000" (0.3 VMSHELL) |
| `get_version` | `() → String` | Returns "2.5.0" |
| `get_modality_configs` | `() → Vec<ChainModalityConfig>` | View |

### 2.3 Data Types

```rust
pub struct AppInfo {
    pub vk: String,
    pub app_version: u32,
    pub seed_hash: String,
    pub registration_count: u32,
}

pub struct RegistrationInfo {
    pub commitment_hash: String,
    pub v_obf: Vec<i64>,
    pub modality_id: u8,
    pub timestamp: u32,
    pub proof: String,
}

pub struct ChainModalityConfig {
    pub modality_id: String,
    pub proj_dim: String,    // always "128" (hardcoded)
    pub min_score: String,   // always "80" (hardcoded)
}
```

## 3. Contract ABIs

### 3.1 HusRegistry

| Method | Signature | Description |
|--------|-----------|-------------|
| `constructor(appCode)` | `(TvmCell)` | Store app template |
| `registerApp(appName, modalityIds)` | `(string, uint8[]) → address` | Deploy HusApp |
| `setProvingKey(pk)` | `(bytes)` | Owner only |
| `setVk(vk)` | `(bytes)` | Owner only |
| `setProvingKeyChunk(index, chunk)` | `(uint16, bytes)` | Owner only |
| `setProvingKeyHash(hash)` | `(uint256)` | Owner only |
| `proposeAppUpgrade(appId, newCode, newVk)` | `(uint256, TvmCell, bytes)` | Owner, 7-day delay |
| `executeAppUpgrade(appId)` | `(uint256)` | Anyone after delay |
| `cancelAppUpgrade(appId)` | `(uint256)` | Owner only |
| `getAppAddress(appId)` | `(uint256) → address` | View |
| `getProvingKey()` | `() → bytes` | View |
| `getVk()` | `() → bytes` | View |
| `getVersion()` | `() → string` | View |

### 3.2 HusApp

| Method | Signature | Description |
|--------|-----------|-------------|
| `constructor(vk, seedHash, modalityIds)` | `(bytes, uint256, uint8[])` | Called by registry |
| `submitCommitment(commitmentHash, vObf, modalityId)` | `(uint256, int64[], uint8) → (bool, uint8)` | Working path |
| `submitWithProof(vObf, proof, commitment, modalityId)` | `(int64[], bytes, uint256, uint8) → (bool, uint8)` | Blocked on Shellnet |
| `deposit(paymentId)` | `(uint256)` | Convert SHELL |
| `checkDuplicate(commitmentHash)` | `(uint256) → bool` | View |
| `getRegistration(index)` | `(uint32) → (bytes32, int64[], uint8, uint32, bytes)` | View |
| `getRegistrationCount()` | `() → uint32` | View |
| `getAppInfo()` | `() → (bytes, uint32, uint256, uint32)` | vk, version, seedHash, regCount |
| `getVerificationFee()` | `() → uint256` | Returns 300000000 |
| `getModalityConfigs()` | `() → ModalityConfig[]` | View |
| `getVersion()` | `() → string` | View |

## 4. Error Codes

| Error | Source | Description |
|-------|--------|-------------|
| `AppNotFound` | HusRegistry | No registry for appId |
| `AppAlreadyRegistered` | HusRegistry | appId already exists |
| `DuplicateCommitment` | HusApp | Commitment already registered |
| `ModalityNotSupported` | HusApp | Unknown modality ID |
| `InsufficientBalance` | HusApp | Contract VMSHELL balance too low |
