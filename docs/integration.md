# HUS Integration Guide

This guide walks through integrating HUS into a third-party application for Sybil resistance.

---

## 1. Prerequisites

### On-Chain

- A deployed HusRegistry contract (on Shellnet)
- An Acki Nacki GraphQL endpoint for sending transactions

### Client-Side

- Rust `stable` toolchain (`rustup target add wasm32-unknown-unknown`)
- Biometric capture capability (camera, microphone, keyboard, etc.)
- ONNX model files for ML modalities (face, iris, voice, fingerprint)

---

## 2. Architecture Overview

```
Your App
    │
    ├── [1] Select 2+ modalities (init-time)
    ├── [2] Capture raw biometrics (HUS-owned)
    ├── [3] Quality pre-check (blur, SNR, occlusion)
    ├── [4] Extract embedding → [f32; N] (per modality)
    ├── [5] Liveness detection
    ├── [6] Quality gate → composite verdict
    ├── [7] BioHashing projection → V_obf (128-dim)
    ├── [8] Poseidon commitment + Groth16 proof
    ├── [9] **Verify proof off-chain**
    └── [10] submitCommitment(commitmentHash, vObf, modalityId) on-chain
```

**Key principle:** Raw biometrics never leave the device. The chain sees only commitments and projected vectors. On-chain Groth16 verification is blocked on Shellnet (the `gosh.vergrth16` opcode uses hardcoded ZkLogin VKs); proof verification happens off-chain.

---

## 3. Step-by-Step Integration

### 3.1 Add Dependencies

```toml
[dependencies]
hus-sdk = { path = "path/to/hus/sdk" }
hus-onchain = { path = "path/to/hus/onchain" }
```

### 3.2 Choose Modalities

```rust
use hus_sdk::{Modality, ModalitySelection};

let selection = ModalitySelection::new(vec![
    Modality::Keystroke,
    Modality::TouchGesture,
    Modality::Gait,
])?; // validates 2+ modalities, no duplicates
```

### 3.3 Initialize Client

```rust
use hus_sdk::HusClient;

let client = HusClient::new(
    "my_app_id".into(),
    selection,
    liveness_seed,  // [u8; 32] from chain or generated
);
```

### 3.4 Capture, Extract, Liveness

> For face and typing on a phone, use the enrolment sessions instead
> ([liveness.md](liveness.md)): liveness, capture, proof and the
> attestation challenge in one session that the app can't steer. The
> per-modality `LivenessSession` below only checks that a signal is
> present; it is not liveness.

```rust
use hus_sdk::{
    capture::{Capture, MockCapture, RawCapture},
    quality::check_quality,
    liveness::{create_session, require_liveness},
    extract::get_extractor,
};
use std::collections::BTreeMap;

let mut embeddings = BTreeMap::new();

for modality in client.modalities() {
    // 1. Liveness session
    let mut session = client.create_liveness_session(*modality);
    for i in 0..session.challenge_count() {
        session.verify_response(i)?;
    }
    require_liveness(&session.finalize())?;

    // 2. Capture + quality
    let mut capturer = MockCapture::new(*modality);
    let raw = capturer.capture()?;
    raw.validate()?;
    let q = check_quality(&raw)?;
    if !q.passed {
        eprintln!("Low quality: {:?}", q.issues);
        continue;
    }

    // 3. Extract embedding
    let extractor = get_extractor(*modality)?;
    let emb = extractor.extract(&raw)?;
    embeddings.insert(*modality, emb.vector);
}
```

### 3.5 Quality Gate

```rust
let mut passed_flags: Vec<bool> = Vec::new();
for modality in client.modalities() {
    passed_flags.push(embeddings.contains_key(modality));
}
let gate = client.check_quality_gate(&passed_flags);
if !gate.all_passed {
    return Err("not enough modalities passed quality gate");
}
```

### 3.6 Project + Prove + Verify

```rust
use hus_sdk::prover::{prove_projected, verify_projected};

let pk = fetch_proving_key_from_registry().await?;  // bytes
let vk = fetch_verifying_key_from_registry().await?; // bytes

let mut results = Vec::new();
for cfg in client.modality_configs() {
    let embedding = &embeddings[&cfg.modality];
    // BioHashing projection + Groth16 proof
    let (proof_bytes, commitment_hash) = prove_projected(
        &pk, embedding,
    )?;

    // Off-chain verification (critical — this is the only verification path)
    let valid = verify_projected(
        &vk, &proof_bytes, &commitment_hash, embedding,
    )?;
    if !valid {
        return Err("proof verification failed");
    }

    // Convert for contract
    let v_obf_contract = hus_sdk::v_obf_to_contract(embedding);
    results.push((commitment_hash, v_obf_contract, cfg.modality as u8));
}
```

### 3.7 Register App (One-Time)

```rust
use hus_onchain::hus_registry::HusRegistry;

let registry = HusRegistry::new(context, registry_address);

// Register app — anyone can call. Deploys a HusApp with the given modalities.
let app_address = registry.register_app("my-app", &[0u8, 4u8, 6u8]) // Face, Keystroke, Gait
    .await?;
```

### 3.8 Fund HusApp

```rust
use hus_onchain::hus_app::HusApp;

let app = HusApp::new(context, app_address);

// Deposit SHELL → VMSHELL for gas
app.deposit("payment-1", signer).await?;
```

### 3.9 Submit Commitment (Working Path)

```rust
// Submit each modality's proof-verified data
for (commitment_hash, v_obf, modality_id) in &results {
    let result = app.submit_commitment(
        *commitment_hash,
        v_obf,
        *modality_id,
        signer.clone(),
    ).await?;
    // Result includes value0=isUnique, value1=score
}
```

---

## 4. Multi-Modal Selection

| Count | Required to pass | Example |
|-------|-----------------|---------|
| 2 | 2 (all) | Keystroke + Touch |
| 3 | 3 (all) | Face + Voice + Keystroke |
| 4 | 3 | Face + Iris + Voice + Keystroke |
| 5 | 4 | Face + Iris + Voice + Fingerprint + Keystroke |
| 6 | 5 | Face + Iris + Voice + Fingerprint + Keystroke + Touch |
| 7 | 6 | All 7 |

Required count = `ceil(count * 3/4)` for ≥4, else all.

---

## 5. Testing

```bash
cargo test --lib -p hus-sdk          # SDK unit tests
cargo test -p hus-onchain             # Onchain wrappers
cargo test -p hus-gateway             # Gateway tests
cargo bench -p hus-sdk                # Benchmarks
```

---

## 6. Best Practices

- Use 3+ modalities for production; 2 is minimum
- Include at least one passive modality (keystroke, touch, gait)
- Always verify the Groth16 proof off-chain before submitting
- ONNX models require model files — download via `scripts/download_models.sh`

---

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `ModalitySelectionTooFew` | < 2 modalities | Add at least 2 |
| `DuplicateCommitment` | User already registered | Inform user |
| `InsufficientBalance` | HusApp VMSHELL balance low | Call `deposit()` |
| Proof verify fails | Wrong VK or corrupted proof | Check VK matches registry |
