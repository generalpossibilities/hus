# HUS System Architecture

## 1. Overview

HUS follows a strict four-layer architecture: Capture → Extract → Isolate → Prove.

```
┌──────────────────────────────────────────────────────────┐
│                    Application Layer                       │
│  (Third-party dApps: DAOs, games, social platforms)       │
│  The app selects 2+ modalities at init.                   │
│  The app receives only VerificationResult — never raw.    │
├──────────────────────────────────────────────────────────┤
│                    HUS Middleware                          │
│  ┌─────────────────────┐   ┌────────────────────────────┐ │
│  │  Client SDK          │   │  Smart Contracts           │ │
│  │  (on-device)         │   │  (on-chain)                │ │
│  ├──────────────────────┤   ├────────────────────────────┤ │
│  │  7 modality capture  │   │  HusRegistry (v2.4.2) —    │ │
│  │  Quality pre-check   │   │    factory + PK/VK storage │ │
│  │  Liveness detection  │   │  HusApp (v2.5.0) —        │ │
│  │  Feature extraction  │   │    per-app immutable       │ │
│  │  Quality gate fusion │   │    L₂ distance + scoring   │ │
│  │  Poseidon hash       │   │    Duplicate detection     │ │
│  │  Groth16 prover      │   │    Timelocked upgrades     │ │
│  │  Off-chain verifier  │   │                             │ │
│  │  Key derivation      │   │                             │ │
│  └──────────────────────┘   └────────────────────────────┘ │
├──────────────────────────────────────────────────────────┤
│                  Data Availability Layer                    │
│              (Acki Nacki Blockchain Storage)               │
└──────────────────────────────────────────────────────────┘
```

**Key limitation:** On-chain Groth16 verification via `gosh.vergrth16` is blocked on Shellnet v3.0.2 — the opcode uses hardcoded ZkLogin proving keys, not custom circuit VKs. The working path is off-chain proof verification + on-chain `submitCommitment()`.

## 2. Module Map

### 2.1 Client SDK (`sdk/src/`)

| Module | File | Responsibility |
|--------|------|---------------|
| `capture` | `capture.rs` | Raw sensor capture: WASM (5 sensors) + MockCapture |
| `config` | `config.rs` | 7 modality configs: raw/proj dims, thresholds, stability ratings |
| `crypto` | `crypto.rs` | Poseidon hash (sponge), field arithmetic |
| `error` | `error.rs` | `SdkError`, `CaptureError`, `ExtractionError` |
| `extract` | `extract.rs` | 3 pure-Rust extractors + ONNX pipeline stubs + `get_extractor()` |
| `quality_gate` | `quality_gate.rs` | Multi-modal quality fusion; zero-alloc hot path |
| `key` | `key.rs` | SHA-256 key hierarchy |
| `liveness` | `liveness.rs` | Per-modality challenge-response liveness detection (18 challenges) |
| `metrics` | `metrics.rs` | `HusMetrics` global atomic counters |
| `onnx` | `onnx.rs` | ONNX model loader: ArcFace, ResNet50-Iris, ECAPA-TDNN |
| `projection` | `projection.rs` | BioHashing: `derive_and_project()`, `derive_matrix()`, `project()` |
| `prover` | `prover.rs` | Groth16 `prove_projected()`, `verify_projected()` (arkworks) |
| `quality` | `quality.rs` | Biometric quality pre-check: blur, SNR, occlusion, brightness |
| `wasm` | `wasm.rs` | `wasm_bindgen` exports for JS |
| `ffi` | `ffi.rs` | C FFI (Python/Go/Java bindings) |

### 2.2 Smart Contracts

#### HusRegistry (v2.4.2)

| Method | Purpose |
|--------|---------|
| `registerApp(appName, modalityIds)` | Deploy a new HusApp (anyone can call) |
| `setProvingKey(pk)` | Set Groth16 proving key (owner) |
| `setVk(vk)` | Set verifying key (owner) |
| `setProvingKeyChunk(index, chunk)` | Upload PK in 32KB chunks (owner) |
| `proposeAppUpgrade(appId, newCode, newVk)` | Queue timelocked upgrade (owner, 7-day delay) |
| `executeAppUpgrade(appId)` | Execute after delay (anyone) |
| `cancelAppUpgrade(appId)` | Cancel pending upgrade (owner) |
| `getAppAddress(appId)` | Lookup deployed app address |
| `getProvingKey()` / `getVk()` | Get stored PK / VK |
| `getProvingKeyChunk(index)` | Get PK chunk |
| `getProvingKeyHash()` | SHA-256 integrity hash |
| `getVersion()` | Returns "2.4.2" |

#### HusApp (v2.5.0, per-app)

| Method | Purpose |
|--------|---------|
| `submitCommitment(commitmentHash, vObf, modalityId)` | Off-chain-verified submission (working path) |
| `submitWithProof(vObf, proof, commitment, modalityId)` | Submit with on-chain proof (blocked on Shellnet) |
| `deposit(paymentId)` | Convert SHELL to VMSHELL for gas |
| `checkDuplicate(commitmentHash)` | Quick duplicate look-up |
| `getAppInfo()` | Returns vk, appVersion, seedHash, registrationCount |
| `getRegistration(index)` | Returns registration details |
| `getRegistrationCount()` | Total registrations |
| `getModalityConfigs()` | Modality configs (projDim=128, minScore=80 hardcoded) |
| `getVerificationFee()` | Returns 0.3 VMSHELL gas estimate |
| `getBalance()` | Contract balance |
| `getVersion()` | Returns "2.5.0" |

## 3. Data Flow

### Registration / Verification Flow

```
1. MODALITY SELECTION (app, init time)
   App picks 2+ modalities → ModalitySelection validates 2..7, no dupes

2. CAPTURE (on-device)
   Each modality captures from its sensor:
     Face/Iris     → WebcamCapture → RGBA pixels
     Voice         → MicCapture    → PCM i16
     Fingerprint   → HwSensor      → vendor blob
     Keystroke     → KeyListener   → key event frames
     TouchGesture  → TouchListener → touch event frames
     Gait          → MotionSensor  → accelerometer frames

3. QUALITY CHECK (on-device)
   check_quality(capture) → QualityReport
     - Image: too dark/bright, blurred, occluded
     - Audio: low SNR

4. LIVENESS (on-device)
   create_session(modality) → challenge-response → LivenessResult

5. EXTRACT (on-device)
   get_extractor(modality) → extract(capture) → Embedding { vector: [f32; N] }

6. QUALITY GATE (on-device)
   client.check_quality_gate(passed_flags) → QualityGateResult

7. PROJECTION (on-device)
   derive_and_project(seed, embedding, proj_dim=128) → V_obf

8. COMMITMENT (on-device)
   Poseidon(V_obf || nonce) → C

9. PROVE (on-device)
   prove_projected(&pk, &v_obf) → (proof_bytes, commitment_hash)

10. VERIFY (off-chain, gateway or SDK)
    verify_projected(&vk, &proof, &commitment, &v_obf) → bool

11. SUBMIT COMMITMENT (on-chain)
    submitCommitment(commitmentHash, vObf, modalityId)
      → Duplicate commitment check
      → L₂ distance against existing V_obf for this modality
      → Store if unique
```

## 4. Modality Configuration

| Modality | Raw dim | Proj dim | Threshold | Min score | Stability | Extract method |
|----------|---------|----------|-----------|-----------|-----------|----------------|
| Face | 512 | 128 | 1.0 | 80 | 85% | ONNX (ArcFace) |
| Iris | 256 | 64 | 0.6 | 90 | 98% | ONNX (ResNet50) |
| Voice | 192 | 64 | 1.2 | 75 | 75% | ONNX (ECAPA-TDNN) |
| Fingerprint | 128 | 48 | 0.5 | 90 | 95% | ONNX (custom) |
| Keystroke | 40 | 16 | 2.0 | 70 | 55% | Pure Rust |
| TouchGesture | 30 | 12 | 2.0 | 65 | 50% | Pure Rust |
| Gait | 60 | 24 | 1.5 | 70 | 60% | Pure Rust |

**Note:** On-chain, all modalities use `PROJ_DIM=128` and `MIN_SCORE=80` (hardcoded contract constants). The per-modality config above is SDK-side for extraction only.

## 5. Security Boundaries

```
┌──────────────────────────────────────────────┐
│  Trusted: User Device                         │
│  (biometric capture, SDK execution, proving)  │
├──────────────────────────────────────────────┤
│  Trusted but verifiable: Acki Nacki           │
│  (smart contract execution, storage)          │
├──────────────────────────────────────────────┤
│  Untrusted: Network, validators               │
│  (assumes honest majority)                    │
└──────────────────────────────────────────────┘
```

## 6. Concurrency Model

- **Per-app partitioning:** Each app has its own HusApp contract. Verification for different apps runs independently.
- **No shared state:** Each HusApp stores only its own registrations.
- **Read-only VK/PK:** VK and PK retrieval from HusRegistry are free view calls.

## 7. Upgrade Model

HusRegistry is the upgrade controller. Individual HusApps are immutable after deploy but can receive **timelocked upgrades**:

```
Owner proposes upgrade ──→ 7-day delay ──→ Anyone executes
```

| Property | How it's preserved |
|----------|-------------------|
| No rug pulls | 7-day timelock gives users time to exit |
| No backdoors | Only code + VK can change. Past registrations are append-only |
| Bug fixes | Critical vulnerabilities can be patched |
| VK rotation | Owner updates VK via proposeAppUpgrade |

## 8. Key Design Decisions

- **Fixed `[ModalityScore; 7]` array in quality gate** — zero-alloc hot path
- **`verify_projected` returns `Result<bool, SdkError>`** — distinguishes bad input from invalid proof
- **Groth16 uses trusted setup** (Powers of Tau Phase 1 on BN254). PK stored on-chain in HusRegistry.
- **L₂ distance on-chain** — avoids floating-point in R1CS while V_obf is already obfuscated
- **PROJ_DIM=128 and MIN_SCORE=80 hardcoded** — apps pass only modality IDs, not configurable thresholds
- **Off-chain Groth16 verify + on-chain submitCommitment** — working path because `gosh.vergrth16` uses ZkLogin VKs, not custom circuit VKs
