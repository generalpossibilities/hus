# Human Uniqueness System (HUS) — Technical Whitepaper

**Version:** 2.5.0  
**Status:** Deployed on Shellnet (Acki Nacki testnet)  
**Target chain:** Acki Nacki (core v3.0.2)  
**Proving system:** Groth16 over BN254  
**Hash function:** Poseidon (P128Pow5T3)

---

## 1. Abstract

The Human Uniqueness System (HUS) is a decentralized biometric middleware that solves the *Sybil resistance problem* for permissionless applications without compromising user privacy. It does not own identities, track users across apps, or store raw biometric data. It answers one question: *"Is this human already registered in this app?"*

HUS follows the **ISO/IEC 24745** standard for cancelable biometrics: templates must be irreversible, unlinkable, and renewable. It achieves this through BioHashing (per-app matrix projection), Poseidon commitments, Groth16 zero-knowledge proofs on BN254, and on-chain L₂ distance computation on projected vectors.

**Key architecture note:** The `gosh.vergrth16` opcode on Acki Nacki v3.0.2 uses hardcoded ZkLogin proving keys — it cannot verify custom circuit proofs. HUS instead verifies Groth16 proofs **off-chain**: the app's verifier (for example the gateway) checks each proof and signs `submitVerified()`, which stores the commitment, the obfuscated vector and the proof. The contract accepts registrations only from the verifier key the app operator named.

---

## 2. Problem Statement

Decentralized applications require Sybil resistance to enforce one-person-one-vote or fair-distribution. Existing solutions fall into three categories:

| Approach | Privacy | Unlinkability | Autonomy |
|----------|---------|---------------|----------|
| KYC / government ID | None | None | Low |
| Web-of-trust / social | Partial | None | Medium |
| Biometric on-chain storage | None | App-dependent | High |
| **HUS** | **Full** | **Full** | **High** |

HUS is designed for the Acki Nacki blockchain's parallel execution model, where contracts run in isolated threads and communicate via verifiable events.

---

## 3. Protocol Architecture

### 3.1 ISO/IEC 24745 — Cancelable Biometrics

| Property | Requirement | HUS Implementation |
|----------|-------------|-------------------|
| **Irreversibility** | Cannot recover raw biometric from stored template | BioHashing projection reduces ℝ⁵¹² → ℝ¹²⁸, which is information-destroying. Poseidon commitment is preimage-resistant. |
| **Unlinkability** | Same user in different apps produces different templates | Per-app seeds produce statistically independent projection matrices. $V_A = V \times M_A \neq V \times M_B$. |
| **Renewability** | On breach, issue new template without changing the biometric | Change the app seed → new projection matrix → completely different template. |

### 3.2 Multi-Modality Pipeline

HUS supports **7 biometric modalities** — apps select 2+ at registration:

| Modality | Type | Raw dim | Projected dim | Stability | Extraction |
|----------|------|---------|---------------|-----------|------------|
| Face | Visual | 512 | 128 | 85% | ONNX (ArcFace) |
| Iris | Visual | 256 | 64 | 98% | ONNX (ResNet50) |
| Voice | Audio | 192 | 64 | 75% | ONNX (ECAPA-TDNN) |
| Fingerprint | Tactile | 128 | 48 | 95% | ONNX (custom) |
| Keystroke | Behavioral | 40 | 16 | 55% | Pure Rust |
| TouchGesture | Behavioral | 30 | 12 | 50% | Pure Rust |
| Gait | Behavioral | 60 | 24 | 60% | Pure Rust |

Each modality passes through a **quality gate** (blur, SNR, occlusion) and **liveness detection** (challenge-response) before extraction.

### 3.3 Data Flow

```
User Device                        Off-chain Verifier          Acki Nacki Chain
───────────                        ─────────────────          ────────────────
   │                                                                    
   ├─ Capture biometrics                                                
   ├─ Quality check + liveness                                          
   ├─ Extract feature V ∈ ℝᴺ (per modality)                            
   ├─ Fetch seed from chain                          │                  
   │  ───────────────────────────────────────────────│► getAppInfo()    
   │  ◄──────────────────────────────────────────────│── seedHash       
   │                                                                    
   ├─ M = derive_matrix(seed, N, k=128)                                 
   ├─ V_obf = V × M                                                    
   ├─ C = Poseidon(V_obf ‖ nonce)                    │                  
   ├─ π = Groth16_Prove(V_obf, nonce, C)             │                  
   │                                                 │                  
   ├─── send (C, V_obf, π) ───────────────────────►  │                  
   │  Verify π via verify_projected()                │                  
   │  (BN254 pairing, ~2ms)                          │                  
   │  If invalid → reject                             │                  
   │               submitVerified(C, V_obf, proof, mod) │
   │                              ──────────────────────────────────►  │
   │                                                                    ├─ Check duplicate commitment
   │                                                                    ├─ L₂ distance vs stored V_obf
   │                                                                    ├─ Score = f(min_distance)
   │                                                                    ├─ Reject if score ≥ 80
   │                                                                    ├─ Store registration if accepted
   │                                                                    ├─ Emit event
   │                                ◄──────────────────────────────────│ result {isUnique, score}
   │  ◄──────────────────────────────────────────────│── result         
```

**The chain does not verify the Groth16 proof on TVM.** `gosh.vergrth16` uses built-in ZkLogin proving keys, not the contract's VK, so the earlier `submitWithProof()` could not check anything and was removed, as was the proofless `submitCommitment()`. Proof verification happens off-chain in the app's verifier. The chain stores the proof with the vector, so anyone can re-check it.

### 3.4 On-Chain Proof Verification (Future)

The `gosh.vergrth16` opcode accepts `(vk_hash, proof, public_inputs)` but its VK is hardcoded at the protocol level for ZkLogin — it does not use the contract's stored `_vk`. A new opcode (`gosh.vergroth16`) that accepts an explicit VK parameter would enable on-chain proof verification. Until then, off-chain verification is the working path.

---

## 4. Mathematical Framework

### 4.1 Application Isolation (BioHashing)

For each app, the contract stores a 32-byte seed hash at deploy time. The client SDK derives per-modality projection matrices $M_{m} \in \mathbb{R}^{128 \times N}$ via deterministic Gram-Schmidt orthogonalization on pseudo-random rows seeded by SHA-256(seedHash ‖ modalityId).

$$V_{obf} = V_{raw} \times M_m$$

The projection is **dimension-reducing** (raw N → 128) and **irreversible** — $V_{raw}$ cannot be recovered.

### 4.2 Euclidean Distance (On-Chain)

Biometric capture is inherently noisy. The contract computes L₂ distance directly against all stored vectors for the same modality:

$$D = \sqrt{\sum_{i=1}^{128} (V_{new, i} - V_{existing, i})^2}$$

Distance is computed using integer arithmetic scaled by $10^6$ to avoid floating-point divergence:

$$\text{THRESHOLD\_SCALED} = 5\,000\,000$$
$$D_{scaled} = \sum (V_{new} - V_{existing})^2 \times 10^6 / 128$$
$$\text{Score} = \min(100,\; D_{scaled} \times 100 / \text{THRESHOLD\_SCALED})$$

### 4.3 Uniqueness Boundary

**Score ≥ 80** is considered the same human and rejected. This threshold (`MIN_SCORE = 80`) is a contract constant — apps cannot override it:

| Score range | Verdict |
|-------------|---------|
| 0–79 | Unique — accepted |
| 80–100 | Duplicate — rejected |

The projected vector dimension (`PROJ_DIM = 128`) and modality count minimum (`MIN_MODALITIES = 2`) are also contract constants. Apps supply only a list of `uint8[] modalityIds` at registration.

### 4.4 Commitment Scheme

The projected vector is committed via **Poseidon hash**:

$$C = \text{Poseidon}(V_{obf} \parallel \text{nonce})$$

The nonce is randomly generated per submission. On-chain only `C_hash = keccak256(C)` is stored as `bytes32`, reducing storage cost.

---

## 5. Zero-Knowledge Proof System

### 5.1 Proof Statement

The user proves knowledge of a valid preimage for their commitment:

$$
\begin{aligned}
\text{Given:} &\quad C_{public} \\
\text{Prove:} &\quad \exists \; V_{obf}, \; \text{nonce} \in \mathbb{F}_r^{k+1} \text{ such that} \\
&\quad C = \text{Poseidon}(V_{obf} \parallel \text{nonce}),\quad k = 128
\end{aligned}
$$

Public inputs: the Poseidon commitment $C$ (4–5 field elements, depending on compression). Private witness: $V_{obf}$ (128 field elements) + nonce (1 field element).

### 5.2 Proving System

HUS uses **Groth16** over **BN254** with R1CS constraint system (arkworks).

| Component | Details |
|-----------|---------|
| Circuit | `UniquenessCircuit` — Poseidon hash in R1CS |
| Hash | Poseidon (P128Pow5T3, width 3), ~1,200 constraints per squeeze |
| Total constraints | ~2,000 (128-dim vector hashing) |
| Prover | `prove_projected(pk, &v_obf)` — ark-groth16 |
| Verifier | `verify_projected(vk, &proof, &commitment)` — off-chain |
| Trusted setup | Powers of Tau Phase 1 (BN254, universal) |
| PK size | ~17 MB (chunked upload: 544 × 32KB) |
| Proof size | ~128 bytes |

### 5.3 Duplicate Detection

1. **Commitment uniqueness:** Contract rejects duplicate `commitmentHash` (replay protection).
2. **Biometric similarity:** L₂ distance against all stored `vObf` for the same modality. If any score ≥ 80, reject.

Stored `vObf` is already obfuscated and application-specific — it leaks no cross-app information and cannot be reversed to reconstruct the biometric.

---

## 6. Smart Contract Architecture

### 6.1 HusRegistry (Factory)

*Version 2.4.2, deployed on Shellnet*

| Storage | Type | Description |
|---------|------|-------------|
| `_appCode` | `TvmCell` | HusApp source code (deploy template) |
| `_provingKey` | `bytes` | Full Groth16 proving key (17 MB) |
| `_vk` | `bytes` | Groth16 verifying key (VK) |
| `_ownerPubkey` | `uint256` | Owner's public key (set-only functions) |
| `_appRegistry` | `mapping(uint256 ⇒ address)` | appId → HusApp address |
| `_pendingUpgrades` | `mapping(uint256 ⇒ PendingUpgrade)` | Timelocked upgrade queue |
| `_provingKeyChunks` | `mapping(uint16 ⇒ bytes)` | 32 KB PK chunks |
| `_provingKeyChunkCount` | `uint16` | Total PK chunks |
| `_provingKeyHash` | `uint256` | SHA-256 of full PK (integrity check) |

| Method | Access | Description |
|--------|--------|-------------|
| `constructor(appCode)` | Deployer | Store app template |
| `registerApp(appName, modalityIds)` | Anyone | Deploy new HusApp, return address |
| `setProvingKey(pk)` | Owner | Set full PK directly |
| `setProvingKeyChunk(index, chunk)` | Owner | Upload PK in 32 KB chunks |
| `clearProvingKeyChunks()` | Owner | Reset chunk store |
| `setProvingKeyHash(hash)` | Owner | Set SHA-256 integrity hash |
| `setVk(vk)` | Owner | Set verifying key |
| `proposeAppUpgrade(appId, newCode, newVk)` | Owner | Queue upgrade (7-day delay) |
| `cancelAppUpgrade(appId)` | Owner | Cancel pending upgrade |
| `executeAppUpgrade(appId)` | Anyone | Execute after delay expires |

### 6.2 HusApp (Per-App, Immutable)

*Version 2.5.0*

| Storage | Type | Description |
|---------|------|-------------|
| `husRegistry` | `address` (static) | Deployer registry |
| `appId` | `uint256` (static) | App identity (derived from name) |
| `_vk` | `bytes` | Verifying key (set by registry) |
| `_seedHash` | `uint256` | Per-app seed hash |
| `_appVersion` | `uint32` | Version counter (increments on upgrade) |
| `_registrationCount` | `uint32` | Total registrations |
| `_seenCommitments` | `mapping(uint256 ⇒ bool)` | Replay protection |
| `_registrations` | `Registration[]` | Stored registrations |
| `_modalityConfigList` | `ModalityConfig[]` | Modality configurations |
| `_modalityConfigMap` | `mapping(uint8 ⇒ ModalityConfig)` | Lookup by ID |

**ModalityConfig** is a struct with `modalityId`, `projDim`, `minScore`. In v2.5.0, every config has `projDim=128` and `minScore=80` — these are contract constants, not app-configurable. The struct is retained for forward-compatibility.

| Method | Access | Description |
|--------|--------|-------------|
| `constructor(vk, seedHash, modalityIds)` | Registry only | Deploy with VK, seed, and modality list |
| `submitVerified(commitmentHash, vObf, proof, modalityId)` | The app's verifier key only | Register after the verifier has checked the proof off-chain |
| `setVerifier(verifierPubkey)` | The app operator's key | Name the verifier key (zero turns registration off) |
| `checkDuplicate(commitmentHash)` | Anyone | Quick lookup (view) |
| `deposit(paymentId)` | Anyone | Convert SHELL → VMSHELL for gas |
| `upgradeCode(newCode, newVk)` | Registry only | Timelocked upgrade |
| `setVk(newVk)` | Registry only | Update VK |
| `getVerificationFee()` | Anyone | Returns 0.3 VMSHELL (gas estimate) |
| `getAppInfo()` | Anyone | Returns vk, appVersion, seedHash, regCount |
| `getModalityConfigs()` | Anyone | Returns modality configurations |
| `getRegistration(index)` | Anyone | Returns registration details |

### 6.3 State Transition Rules

1. **App onboarding:** Anyone calls `registerApp(appName, modalityIds)` on the registry. The registry derives `appId` deterministically from `appName`, generates a random `seedHash`, and deploys a HusApp with the stored VK and app code.
2. **Registration:** After off-chain proof verification, the verifier calls `submitVerified(commitmentHash, vObf, proof, modalityId)`. The contract checks duplicate commitment, computes L₂ distance, and stores the registration if unique.
3. **Rejection:** Score ≥ 80 or duplicate commitment → transaction fails (exit code).
4. **Append-only:** Registrations are never deleted.
5. **Timelocked upgrades:** The registry can propose an upgrade via `proposeAppUpgrade()`. After 7 days (`UPGRADE_DELAY = 604800` seconds), anyone can call `executeAppUpgrade()`. Pending upgrades can be cancelled by the owner.

### 6.4 Registration Storage

```solidity
struct Registration {
    bytes32 commitmentHash;
    int64[]  vObf;          // projected vector (128 × i64)
    uint8    modalityId;
    uint32   timestamp;
    bytes    proof;         // empty in working path
}
```

The `vObf` is stored as `int64[]` where each element is the IEEE 754 bit pattern of an f32 sign-extended to 64 bits. Total storage per registration: ~1,060 bytes (128 × 8 + 32 + 1 + 4 + overhead).

---

## 7. Security Analysis

### 7.1 Threat Model

| Threat | Mitigation |
|--------|-----------|
| Raw biometric leak | Biometrics never leave the device. Only obfuscated commitments are transmitted. |
| Cross-app tracking | Different seeds → different matrices → statistically independent projections. |
| Replay attack | Duplicate commitment check (`_seenCommitments` mapping). |
| Fake biometric injection | Multi-modality requirement (≥2) + liveness detection + quality gate. |
| Sybil via synthetic data | Quality gate + per-modality liveness + on-chain L₂ distance. |
| ZK proof forgery | Groth16 soundness under KZG assumptions on BN254. Trusted setup via Powers of Tau Phase 1. |
| Contract upgrade abuse | 7-day timelock on all upgrades. Past registrations are append-only. |

### 7.2 Privacy Guarantees

- **Unlinkability:** Two projections of the same vector with different app seeds are computationally indistinguishable from random.
- **Anonymity:** The ZK proof hides the nonce. On-chain `vObf` is application-specific and pre-obfuscated.
- **Minimal disclosure:** The chain learns only: (1) commitment hash, (2) projected vector (already obfuscated), (3) modality ID. No biometric data or identity mapping is stored.

### 7.3 Cryptographic Primitives

| Primitive | Algorithm | Notes |
|-----------|-----------|-------|
| Commitment | Poseidon (P128Pow5T3) | ZK-friendly, ~1,200 R1CS constraints |
| ZK proof | Groth16 (R1CS) | BN254, Powers of Tau Phase 1 |
| Seed generation | `tvm.randomize()` + SHA-256 | On-chain, per-app |
| Key derivation | SHA-256 | Session keys from root seed |
| Contract upgrade | Timelock (604800s) | 7-day delay, cancelable by owner |

---

## 8. Performance

### 8.1 Computation (Native x86_64)

| Operation | Time |
|-----------|------|
| Matrix-vector product (128×512) | ~15 µs |
| Euclidean distance (128-dim) | ~0.5 µs |
| Poseidon commitment (129 inputs) | ~3 µs |
| Groth16 proof generation (~2k constraints) | 1–5s native, 3–10s WASM |
| Groth16 proof verification (off-chain) | ~2 ms (BN254 pairing) |
| Key generation (128-dim circuit) | ~20 min (one-time) |

### 8.2 Storage

| Item | Size |
|------|------|
| HusApp deployment | ~1.5 KB code + state |
| Per registration | ~1,060 bytes |
| Proving key (Groth16) | ~17 MB |
| Verifying key | ~584 bytes |
| Groth16 proof (compressed) | ~128 bytes |

### 8.3 Network (On-Chain Transactions)

| Message | Size | Gas (VMSHELL) |
|---------|------|---------------|
| `submitVerified` | ~1.3 KB | ~0.3 |
| `registerApp` | ~0.5 KB | ~3.0 (deploy) |
| `setProvingKeyChunk` | ~32 KB | ~0.1 |
| `checkDuplicate` (view) | ~0.1 KB | 0 |

---

## 9. Deployment

### 9.1 Prerequisites

- Acki Nacki validator node (GraphQL endpoint, e.g., Shellnet)
- Wallet with sufficient SHELL balance (fund via GiverV3 faucet)
- `sold` compiler (v0.79.3+, commit `bbe763d9`)
- Groth16 proving key (generated via `cargo run --example keygen`)

### 9.2 Deploy Script

The recommended deployment method is:

```bash
./scripts/deploy.sh <GRAPHQL_URL> <WALLET_JSON_PATH>
```

The script:
1. Compiles `HusRegistry.sol` and `HusApp.sol` with `sold` (two-pass: first for `.tvc`, then with `--abi-json` for `.abi.json`)
2. Extracts the `HusApp` code cell (base64) for the registry's constructor
3. Funds the deployer wallet via GiverV3 (0.3 VMSHELL)
4. Deploys HusRegistry, setting the app code template

After deploy, the owner must:
1. Set the verifying key: `setVk(vk_hex_bytes)`
2. Upload the proving key in 32KB chunks: `setProvingKeyChunk(index, chunk)` × ~544
3. Set the PK integrity hash: `setProvingKeyHash(sha256(pk))`

### 9.3 Client SDK Integration

```rust
use hus_sdk::{HusClient, ModalitySelection, Modality};

let selection = ModalitySelection::new(vec![
    Modality::Face,
    Modality::Keystroke,
])?;

let client = HusClient::new(
    "my_app".into(),
    selection,
    liveness_seed,  // [u8; 32] from chain
);

// Extract, project, and prove
let proofs = client.project_and_prove(
    &proving_key,           // fetched from registry
    &embeddings,            // BTreeMap<Modality, Vec<f32>>
    seed_fn,                // fn(Modality) -> [u8; 32]
    &liveness_results,      // &[LivenessResult]
)?;

// Verify proof off-chain
for mp in &proofs {
    let valid = verify_projected(
        &vk,
        &mp.proof_bytes,
        &mp.commitment_hash,
        &mp.v_obf,
    )?;
}

// Submit commitment + v_obf on-chain
let v_obf_contract = v_obf_to_contract(&mp.v_obf);
onchain_client.submit_commitment(
    app_id,
    commitment_hash,
    &v_obf_contract,
    modality_id,
)?;
```

### 9.4 E2E Example

A full end-to-end example is at `onchain/examples/verify_and_submit.rs`:

```bash
cargo run --example verify_and_submit -- \
  --network https://shellnet.ackinacki.org/graphql \
  --registry <registry-address> \
  --public-key <hex> \
  --secret-key <hex> \
  --input-path /path/to/capture
```

The example: captures biometrics → project → generate Groth16 proof → verify off-chain → verifier signs `submitVerified` → check result.

### 9.5 Known Limitations

- **`gosh.vergrth16` blocked:** The opcode only accepts ZkLogin VKs, not contract-stored VKs. A new opcode (`gosh.vergroth16`) with explicit VK parameter is required for on-chain proving.
- **PK size:** 17 MB proving key uploaded in 544×32 KB chunks (~544 transactions). High latency for initial deployment.
- **Single owner pubkey:** If lost, owner-only functions (setVK, PK upload, upgrades) are permanently locked. Multi-sig planned.

---

## 10. Roadmap

| Phase | Deliverable | Status |
|-------|-------------|--------|
| Core SDK | Capture, extract, project, prove, verify | ✅ Complete |
| Groth16 circuit | Poseidon + R1CS (~2k constraints) | ✅ Complete |
| Smart contracts v2.5.0 | HusRegistry + HusApp (timelocked upgrades) | ✅ Deployed on Shellnet |
| Off-chain E2E | verify_projected + submitVerified | Not re-run after the change |
| REST gateway | 11 endpoints, auth, CORS | ✅ Complete |
| JS SDK | npm package (@hus-js-sdk/sdk) | ✅ Complete |
| C FFI | Python, Go, Java, iOS bindings | ✅ Complete |
| Multi-modality (7) | Face, iris, voice, fingerprint, keystroke, touch, gait | ✅ Complete |
| Liveness detection | 18 challenges across 7 modalities | ✅ Complete |
| Chunked PK upload | 32 KB chunks (~544 tx) | ✅ Implemented |
| Proving key integrity | SHA-256 hash verification | ✅ Implemented |
| On-chain proving | gosh.vergroth16 (future opcode) | 📅 Blocked on protocol |
| Production audit | Third-party security review | 📅 Planned |

---

## 11. References

1. ISO/IEC 24745:2011 — Information technology — Security techniques — Biometric information protection.
2. Grassi, L., et al. "Poseidon: A New Hash Function for Zero-Knowledge Proof Systems." USENIX 2021.
3. Groth, J. "On the Size of Pairing-Based Non-interactive Arguments." EUROCRYPT 2016.
4. Ben-Sasson, E., et al. "Zerocash: Decentralized Anonymous Payments from Bitcoin." IEEE S&P 2014.
5. Teuwen, P. "Cancelable Biometrics: A Review." arXiv:2105.05928, 2021.
6. Acki Nacki Blockchain Documentation. https://ackinacki.io/docs
7. arkworks: zkSNARK ecosystem. https://arkworks.rs

---

*HUS is experimental software. Use at your own risk. No warranty is provided.*
