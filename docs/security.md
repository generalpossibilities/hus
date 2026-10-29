# HUS Security Model

## 1. Threat Model

HUS operates under the following trust assumptions:

- **User device is trusted by the user.** The SDK runs on the user's device and the user controls their own biometric data.
- **The Acki Nacki blockchain is trust-but-verify.** Consensus is assumed honest-majority. Smart contract execution is verifiable.
- **The network is untrusted.** All communication occurs over TLS. Validator nodes may be Byzantine.
- **Third-party apps are untrusted.** Apps should not be able to extract information about users beyond the uniqueness result.

---

## 2. Adversary Capabilities

| Adversary | Capabilities | Cannot Do |
|-----------|-------------|-----------|
| Network observer | Read encrypted traffic metadata | Decrypt TLS payloads |
| Malicious validator | Reorder/withhold transactions | Forge ZK proofs |
| Compromised app | Submit any data to HUS contract | Extract raw biometrics from HUS |
| External attacker | MITM, replay requests | Generate valid proof without biometric |
| Sybil attacker | Create many accounts | Bypass biometric uniqueness check |

---

## 3. Privacy Guarantees

### 3.1 Raw Biometric Never Leaves Device

The full biometric vector $V \in \mathbb{R}^{512}$ exists only in the device's memory during capture and projection. After matrix multiplication, the original $V$ cannot be recovered from the projected $V_{obf}$ because the projection is dimension-reducing ($512 \rightarrow 128$) and information-destroying.

### 3.2 Cross-App Unlinkability

Two apps A and B with different seeds $S_A$ and $S_B$ produce different matrices $M_A$ and $M_B$. For the same biometric vector $V$:

$$V_A = V \times M_A \neq V \times M_B = V_B$$

Unless the seeds are related (which they are not — they are independently random), the projected vectors are computationally indistinguishable from random.

### 3.3 Anonymity via ZK Proofs

The ZK proof system (Groth16 on BN254 in production) proves the statement:

> "I know a vector $V_{obf}$ and nonce such that Poseidon$(V_{obf} \| \text{nonce}) = C$"

without revealing $V_{obf}$ or $V_{obf}'$. This ensures:
- The prover's biometric data is hidden
- The matched registry entry (if any) is hidden
- The prover's previous submissions are hidden

---

## 4. Cryptographic Guarantees

### 4.1 Commitment Binding

Poseidon is computationally binding. Given a commitment $C$, it is infeasible to find a different preimage $(V_{obf}', \text{nonce}')$ such that Poseidon$(V_{obf}' \| \text{nonce}') = C$.

### 4.2 Commitment Hiding

Poseidon is preimage-resistant. Given $C$, it is infeasible to recover $V_{obf}$ or the nonce.

### 4.3 Proof Soundness

With Groth16 on BN254 (Powers of Tau trusted setup), a malicious prover cannot forge a valid proof for a false statement assuming the hardness of the discrete log problem in the random oracle model.

---

## 5. Attack Vectors and Mitigations

### 5.1 Replay Attack

**Threat:** An attacker captures a valid submission (commitment + proof) and resubmits it.  
**Mitigation:** The smart contract checks `registry.biometric_hashes.contains(&commitment)` before accepting. Duplicate commitments are rejected.

### 5.2 Biometric Spoofing

**Threat:** An attacker presents a fake biometric (photo, silicone finger, deepfake video).  
**Mitigation:** 
- Hardware attestation (see [attestation.md](attestation.md)): every verification and registration must come from the integrator's unmodified app on a genuine, locked device, for exactly that request. This stops scripts, emulators, rooted phones and repackaged apps from feeding in made-up vectors. It does not stop a photo or screen held up to a real phone's camera.
- Still open: liveness at the capture layer, with a server-issued challenge.

### 5.3 Statistical Linkage

**Threat:** An attacker with access to multiple app registries attempts to link identities across apps.  
**Mitigation:** Different seeds → different matrices → different projected vectors. Without the projection seed, the commitment reveals nothing about the underlying biometric. The ZK proof reveals even less.

### 5.4 Front-Running

**Threat:** A validator observes a pending uniqueness proof and submits a conflicting proof.  
**Mitigation:** Acki Nacki's parallel execution model includes transaction ordering guarantees. The `user_account` field in the submission prevents account-level replay.

### 5.5 Sybil Attack

**Threat:** An attacker creates many accounts for the same human to gain disproportionate influence.  
**Mitigation:** The uniqueness score threshold (≥ 80) rejects re-registrations of the same biometric. The ZK proof ensures the rejecter cannot determine which account triggered the match.

---

## 6. Production Hardening Checklist

| Item | Priority | Status |
|------|----------|--------|
| Groth16 off-chain verify + verifier-signed submitVerified E2E | Critical | Not re-run after the change |
| Chunked proving key upload (17MB) | High | ✅ Done |
| Timelocked upgrade mechanism | High | ✅ Implemented |
| Third-party security audit | Critical | 📅 |
| Bug bounty program | Medium | 📅 |
| Formal verification of scoring logic | Medium | 📅 |
| On-chain Groth16 verification (future gosh.vergroth16 opcode) | Medium | 📅 Blocked |

---

## 7. Responsible Disclosure

If you discover a security vulnerability in HUS, please report it privately to `security@hus-protocol.io`. Please do not disclose vulnerabilities publicly until they have been addressed.

---

## 8. Known Limitations

- **No formal verification.** Smart contract logic has been manually reviewed.
- **Proving time.** Groth16 proof generation (~2000 constraints) takes 1–5s (native), 3–10s (WASM).
- **No on-chain Groth16 verification.** The `gosh.vergrth16` opcode uses hardcoded ZkLogin VKs, not custom circuit VKs. Proof verification is off-chain.
