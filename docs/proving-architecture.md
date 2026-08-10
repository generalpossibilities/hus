# HUS Proving Architecture: On-Device Proving + Off-Chain Verification

## Problem

Groth16 proof generation (BN254) takes ~1–5 s native, ~3–10 s on WASM. The `gosh.vergrth16` opcode is blocked on Shellnet v3.0.2 — it uses hardcoded ZkLogin VKs, not custom circuit VKs.

**Solution:** Prove on-device via arkworks (native or WASM), **verify off-chain** via `verify_projected()`, submit only the commitment hash + obfuscated vector on-chain via `submitCommitment()`.

## Flow

```
┌─────────────────────────────────────────────────────────────┐
│ USER DEVICE (Phone / Browser / WASM)                        │
│                                                             │
│  1. Capture biometric (camera/mic/touch)                    │
│  2. Extract embedding (ONNX model, local)                   │
│  3. Project to V_obf via BioHashing (128-dim)               │
│  4. Prove: C = Poseidon(V_obf || nonce),                    │
│            π = Groth16_Prove(pk, V_obf, nonce, C)           │
│  5. Verify off-chain: verify_projected(vk, π, C, V_obf)     │
│  6. Submit: submitCommitment(C_hash, V_obf, modalityId)     │
│     → on-chain L2 duplicate detection                       │
│     → stores if unique                                      │
└─────────────────────────────────────────────────────────────┘
```

**Key property:** The proof is verified off-chain. On-chain `submitWithProof()` exists but cannot verify custom circuits because `gosh.vergrth16` is hardcoded for ZkLogin.

## Single Proving Path: On-Device (arkworks)

```
User → SDK → project_and_prove() → ark-groth16 (native/WASM) → (proof, commitment)
     → verify_projected() → off-chain check → submitCommitment()
```

- Proving key fetched from HusRegistry (`getProvingKey()` — free view call)
- VK fetched from HusRegistry (`getVk()` — free view call)
- All HusApps share the same universal circuit (Poseidon preimage proof, ~2000 constraints)
- The proof is **discarded** after successful off-chain verification

## Security Model

| Data | What it is | Sensitivity |
|------|-----------|-------------|
| `V_obf` | Projected vector (embedding × random seed matrix) | Low. App-specific, non-reversible per ISO/IEC 24745 |
| `proof` | Groth16 proof bytes (128B) | None. Public data |
| `commitment` | Poseidon hash of (V_obf \|\| nonce) | None. Public data |

| Layer | Trust model |
|-------|------------|
| Blockchain | Trustless (consensus) |
| Proof verification | arkworks off-chain (client or gateway) |
| User device | Fully trusted |

## On-Chain Verification (Future)

The `gosh.vergrth16` opcode accepts `(vk_hash, proof, public_inputs)` but its VK is hardcoded at the protocol level for ZkLogin — it does not use the contract's stored `_vk`. A new opcode (`gosh.vergroth16`) that accepts an explicit VK parameter would enable on-chain verification. Until then:

- **`submitWithProof()`** — exists but blocked on Shellnet
- **`submitCommitment()`** — the working path (off-chain verify + on-chain store)

## App Registration

```
App dev → HusRegistry.registerApp("my-app", [0, 4, 6])
              │
              ├─ appId = hash(caller_pubkey, appName)
              ├─ seedHash = tvm.rand()
              ├─ deploys HusApp(vk, seedHash, modalityIds)
              │    └─ app dev receives appAddress
```

## WASM Prover Binary

Location: `sdk/js/` — compiles via `wasm-pack` to `wasm32-unknown-unknown`.

- Exports: `prove(v_obf) → { proof, commitment }`
- Under the hood: arkworks Groth16 over BN254 compiled to WASM
- Binary size: ~2.8MB (wasm + js glue)

## Performance

| Operation | Time | Gas (if on-chain) |
|-----------|------|-------------------|
| Groth16 prove (native) | 1–5 s | n/a |
| Groth16 prove (WASM) | 3–10 s | n/a |
| Groth16 verify (off-chain) | ~2 ms | n/a |
| `submitCommitment` (on-chain) | ~30 s | ~0.3 VMSHELL |

## Gas Model

Gas for `submitCommitment` is paid from the HusApp contract's VMSHELL balance:

```
User sends SHELL → deposit(paymentId) → gosh.cnvrtshellq() converts to VMSHELL
                                               ↓
                                      HusApp balance (VMSHELL)
                                               ↓
                        submitCommitment() → tvm.accept()
                                               ↓
                        gas deducted from HusApp balance
```
