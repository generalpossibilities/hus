# Human Uniqueness System (HUS)

> Decentralized biometric middleware for Sybil resistance — verifies a user is a unique human without ever learning *which* human they are.

[![CI](https://github.com/generalpossibilities/hus/actions/workflows/ci.yml/badge.svg)](https://github.com/generalpossibilities/hus/actions/workflows/ci.yml)
![rustc](https://img.shields.io/badge/rustc-stable-lightgrey)
![wasm](https://img.shields.io/badge/target-wasm32--unknown--unknown-purple)

---

## HUS in Simple Terms

On the internet, anyone can create 10, 100, or 10,000 accounts. For DAOs, online games, or any system that needs one-person-one-vote, this is a problem.

HUS solves it by asking: **"Has this person already signed up?"** — without ever seeing their face, storing their photo, or knowing who they are.

Here is how it works in four steps:

1. **Scan yourself on your device.** Your phone reads your face, typing rhythm, or voice and turns it into a secret set of numbers. All on your device. Nothing leaves.

2. **The numbers get scrambled.** HUS applies BioHashing (a unique matrix projection) that is different for every app. If you sign up for App A and App B, both apps see completely different data — they can never tell it is the same person. This prevents cross-app tracking. (ISO/IEC 24745 cancelable biometrics.)

3. **A cryptographic commitment is created.** HUS locks those scrambled numbers into a Poseidon hash commitment and generates a Groth16 zero-knowledge proof — a mathematical guarantee that the commitment contains valid data without ever opening it.

4. **The proof goes to the blockchain.** The proof is verified off-chain; the commitment and obfuscated vector are stored on-chain. The contract computes L2 distance against every previous registration, checks for duplicates, and either accepts or rejects.

**The result:** Apps get Sybil resistance. Users keep their privacy. No photos, fingerprints, or identity documents ever leave your device.

---

## Overview

HUS is a decentralized biometric middleware. It follows the **ISO/IEC 24745** standard for cancelable biometrics: irreversible, unlinkable, and renewable templates.

| Principle | Mechanism |
|-----------|-----------|
| **No identity ownership** | HUS is an algorithmic evaluator — unlink it and apps lose access. |
| **Cross-app unlinkability** | Per-app matrix projection guarantees different apps see different vectors for the same user. |
| **Anonymous dedup** | Poseidon commitment + Groth16 proof + on-chain L2 distance detect duplicates without revealing identity. |
| **Immutable contracts** | HusApp has no owner after deploy. Timelocked upgrades via HusRegistry (7-day delay). |

**Architecture:** `Phone → Off-chain verify → Acki Nacki chain` (on-chain Groth16 via `gosh.vergrth16` is blocked — built-in ZkLogin VKs, not custom circuit VKs. Off-chain proof verification + on-chain commitment storage is the current working path. On-node WASM execution via `gosh.runwasm` is validated end-to-end in a local executor harness and pending a live Shellnet run — see [avm/shellnet-runwasm-request.md](avm/shellnet-runwasm-request.md).)


## Integrate in any language

HUS exposes a **REST API** so any app — Python, JavaScript, Go, Rust, C, Java, Swift — can integrate without blockchain dependencies.

```
curl -X POST http://localhost:3000/api/v1/check \
  -H 'Content-Type: application/json' \
  -d '{"app_address":"0x...","commitment_hash":"0x..."}'
# → {"duplicate":false}
```

See [SETUP.md](SETUP.md) for Python, JS, Go, Rust, and C examples. Full API reference at [docs/api-gateway.md](docs/api-gateway.md).

### Quick Start (Rust developer)

```bash
cargo build --release
cargo test
```

Run the gateway:

```bash
cargo run -p hus-gateway -- \
  --network <graphql-endpoint> \
  --registry <registry-address> \
  --public-key <hex> \
  --secret-key <hex> \
  --attest-policy attest/policy.example.json   # your app's policy; see docs/attestation.md
```

### Deploy HusRegistry on Shellnet

```bash
./scripts/deploy.sh https://shellnet.ackinacki.org/graphql /path/to/wallet.keys.json
```

---

## Repository Structure

```
hus/
├── Cargo.toml                        # Workspace root (sdk, onchain, gateway)
├── rust-toolchain.toml               # Stable Rust + WASM target
├── contracts/onchain/                # GOSH Solidity contracts (v2.5.0)
│   ├── HusApp.sol                    #   Per-app immutable contract
│   ├── HusRegistry.sol               #   Factory contract (timelocked upgrades)
│   └── build/                        #   Compiled .tvc, .abi.json, .code
├── sdk/                              # Core SDK (Rust → WASM / C FFI / staticlib)
│   ├── src/
│   │   ├── lib.rs                    #   HusClient, Modality, quality gate
│   │   ├── projection.rs             #   BioHashing: derive_matrix + project
│   │   ├── prover.rs                 #   Groth16 prove + verify (arkworks)
│   │   ├── crypto.rs                 #   Poseidon hash
│   │   ├── circuit/                  #   R1CS circuit + Poseidon constraints
│   │   ├── capture.rs                #   Sensor capture trait + WASM impls
│   │   ├── extract.rs               #   Feature extractors (pure Rust + ONNX)
│   │   ├── liveness.rs              #   18 challenge types across 7 modalities
│   │   ├── quality.rs               #   Per-modality quality checks
│   │   ├── quality_gate.rs          #   Multi-modality quality fusion
│   │   ├── key.rs                    #   Key derivation hierarchy
│   │   ├── onnx.rs                   #   ONNX model inference (tract-onnx)
│   │   ├── wasm.rs                   #   WASM bindings
│   │   └── ffi.rs                    #   C FFI (Python/Go/Java bindings)
│   ├── examples/
│   │   └── keygen.rs                #   Generate Groth16 PK/VK
│   └── js/                           #   @hus-js-sdk/sdk npm package
├── onchain/                          # Rust wrappers for TVM SDK
│   ├── src/
│   │   ├── hus_app.rs               #   HusApp client (submit, query)
│   │   ├── hus_registry.rs          #   HusRegistry client (register, set VK/PK)
│   │   └── lib.rs                   #   Re-exports
│   ├── abi/                          #   Contract ABIs
│   └── examples/
│       ├── verify_and_submit.rs     #   E2E: prove off-chain, submit on-chain
│       ├── set_pk.rs                #   Upload proving key in chunks
│       └── check_pk.rs              #   Verify uploaded PK integrity
├── gateway/                          # REST API gateway (axum)
│   └── src/main.rs                  #   11 endpoints, auth, CORS
├── scripts/
│   ├── deploy.sh                    #   Full deploy: compile → fund → deploy
│   ├── download_models.sh           #   Fetch ONNX models from Hugging Face
│   └── android-build.sh / ios-build.sh
├── docs/
│   ├── whitepaper.md                #   Technical whitepaper
│   ├── codebase-overview.md         #   Full codebase walkthrough
│   ├── api.md, api-gateway.md       #   API references
│   ├── architecture.md              #   4-layer architecture
│   ├── deployment.md                #   Deployment runbook
│   ├── integration.md               #   Third-party integration guide
│   ├── design-rationale.md          #   20 design decisions
│   ├── security.md                  #   Threat model & mitigations
│   └── proving-architecture.md      #   On-device proving details
└── keep/                            # Dev notes, audit, RUNWASM smoke harness + tvc-utils
```

---

## API Overview

### REST Gateway (recommended for most integrators)

See [docs/api-gateway.md](docs/api-gateway.md) for full reference.

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/status` | Health check |
| `POST /api/v1/register-app` | Deploy a new HusApp (takes appName + modalityIds) |
| `POST /api/v1/app-info` | Query app info |
| `POST /api/v1/project` | BioHashing projection |
| `POST /api/v1/prove` | Generate Groth16 proof |
| `POST /api/v1/verify` | Off-chain proof verification |
| `POST /api/v1/submit` | Submit commitment + V_obf (legacy, no proof) |
| `POST /api/v1/submit-with-proof` | Submit with Groth16 proof (blocked on Shellnet) |
| `POST /api/v1/check` | Check duplicate by commitment hash |
| `POST /api/v1/deposit` | Fund HusApp gas pool |

### On-Chain Contracts

#### HusRegistry (factory)

| Method | Description |
|--------|-------------|
| `registerApp(appName, modalityIds)` | Deploy a new immutable HusApp (anyone can call) |
| `setProvingKey(pk)` | Set proving key (owner only) |
| `setVk(vk)` | Set verifying key (owner only) |
| `setProvingKeyChunk(index, chunk)` | Upload PK in 32KB chunks (owner only) |
| `proposeAppUpgrade(appId, newCode, newVk)` | Queue a timelocked upgrade (owner, 7-day delay) |
| `executeAppUpgrade(appId)` | Execute after delay expires (anyone) |
| `cancelAppUpgrade(appId)` | Cancel pending upgrade (owner only) |
| `getAppAddress(appId)` | Lookup deployed app |
| `getProvingKeyChunk(index)` / `getProvingKeyChunkCount()` | Fetch PK chunks |
| `getProvingKeyHash()` | SHA-256 integrity hash |
| `getVk()` / `getProvingKey()` | Get current VK / PK |
| `getVersion()` | Returns "2.4.2" |

#### HusApp (per-app, immutable)

| Method | Description |
|--------|-------------|
| `submitWithProof(vObf, proof, commitment, modalityId)` | Submit with Groth16 proof (blocked — opcode uses ZkLogin VKs) |
| `submitCommitment(commitmentHash, vObf, modalityId)` | Off-chain-verified submission (working path) |
| `deposit(paymentId)` | Convert SHELL to VMSHELL for gas |
| `getAppInfo()` | Return vk, appVersion, seedHash, registrationCount |
| `getRegistrationCount()` | Total registrations |
| `getRegistration(index)` | Registration details |
| `getModalityConfigs()` | Modality configs (projDim=128, minScore=80) |
| `getVerificationFee()` | Return 0.3 VMSHELL gas estimate per submission |
| `getBalance()` | Contract balance |
| `getVersion()` | Returns "2.5.0" |

---

## Benchmarks

| Operation | Time | Notes |
|-----------|------|-------|
| Matrix projection (128×512) | ~15 µs | Stack-allocated |
| Euclidean distance (128-dim) | ~0.5 µs | Stack-allocated |
| Poseidon commitment (64 inputs) | ~3 µs | |
| Groth16 proof generation (~2k constraints) | 1–5 s | Native; 3–10 s WASM |
| Groth16 proof verification (off-chain) | ~2 ms | arkworks BN254 pairing |
| Key generation (128-dim circuit) | ~20 min | One-time per deployment |

---

## Security

- **Privacy:** Raw biometrics never leave the device. Only obfuscated projected vectors reach the chain.
- **Unlinkability:** Different apps get different projection seeds → different vectors.
- **Anonymity:** Groth16 proof hides the nonce; stored V_obf is application-specific and non-reversible.
- **Immutable contracts with timelocked upgrades:** HusApp has no owner. The registry can propose upgrades with a 7-day delay, and past registrations are append-only.
- **Sybil resistance:** Multi-modality (2+) + liveness detection + quality gate + on-chain L2 distance check.

See [docs/security.md](docs/security.md) for the full threat model.

---

## Roadmap

| Phase | Status |
|-------|--------|
| SDK: capture, extract, project, prove, verify | ✅ Complete |
| Groth16 circuit (Poseidon + R1CS) | ✅ Complete |
| Smart contracts (Registry + per-app HusApp) v2.5.0 | ✅ Deployed on Shellnet |
| On-chain E2E: off-chain verify + submitCommitment | ✅ Working |
| REST gateway + JS SDK | ✅ Complete |
| C FFI for Python/Go/Java/iOS | ✅ Complete |
| Multi-modality (7 modalities) | ✅ Complete |
| Liveness detection (18 challenges) | ✅ Complete |
| Timelocked upgrade mechanism | ✅ Implemented |
| Chunked proving key upload (17MB) | ✅ Implemented |
| Production audit | 📅 Planned |



## License

MIT License. See [`LICENSE.md`](LICENSE.md).
