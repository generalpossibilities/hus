# HUS Design Rationale — Why Every Piece Exists

## 0. End-to-End Pipeline Walkthrough

Before diving into individual decisions, here is the complete pipeline from start to finish:

```
                     USER DEVICE                                     │    BLOCKCHAIN
                                                                     │
 1. CAPTURE                                                          │
    App requests biometric from sensor (camera, mic, touchscreen…)   │
    ↓                                                                │
 2. QUALITY CHECK                                                    │
    Is the capture usable? Not too dark, not blurry, not too noisy   │
    ↓                                                                │
 3. LIVENESS DETECTION                                               │
    Challenge-response: blink, smile, repeat phrase, walk steps…     │
    ↓                                                                │
 4. FEATURE EXTRACTION                                               │
    Raw sensor data → embedding vector V (e.g. 512 floats for face)  │
    ↓                                                                │
 5. MATRIX PROJECTION (BioHashing)                                   │
    V × M_app = V_obf (dimension-reduced, app-specific, irreversible)│
    ↓                                                                │
 6. COMMITMENT                                                       │
    C = Poseidon(V_obf || nonce) — a sealed envelope                 │
    ↓                                                                │
 7. ZK PROOF GENERATION                                              │
    π = Groth16 proof: "I know V_obf and nonce that hash to C"      │
    ↓                                                                │
 8. SUBMIT TO CHAIN (C, V_obf, π)                                    │
    ────────────────────────────────────────────────────────────────►│
                                                                      │
                                                                      │ 9. VERIFY PROOF (on-chain)
                                                                      │    gosh.vergrth16(publicInputs, proof)
                                                                      │    ↓
                                                                      │10. CHECK COMMITMENT DUPLICATE (on-chain)
                                                                     │    Is C already in the registry?
                                                                     │    ↓
                                                                     │11. COMPUTE L₂ DISTANCE
                                                                     │    min_dist = min(||V_obf - V_existing||₂)
                                                                     │    score = calculate_score(min_dist, threshold)
                                                                     │    ↓
                                                                     │12. ACCEPT OR REJECT
                                                                     │    score ≥ 80 → duplicate, reject
                                                                     │    score < 80 → unique, store V_obf + C
                                                                     │    ↓
   ◄─────────────────────────────────────────────────────────────────│13. RETURN VerificationResult
```

The 13 steps break into two domains:
- **Steps 1–7** happen on the user's device. Raw biometrics exist only here.
- **Steps 8–13** involve the blockchain. The chain never sees raw data.

---

## 1. Why HUS Exists

**Problem:** Permissionless systems (DAOs, games, social platforms) need Sybil resistance — one person should not get 10,000 votes or 10,000 accounts. Existing solutions all leak privacy:

| Approach | What it reveals | Whose data? |
|----------|-----------------|-------------|
| KYC / government ID | Your real name, address, ID number | You give it to a corporation |
| Web-of-trust / social graph | Who you know, your connections | You expose your network |
| Biometric on-chain hash | If hash is broken, your face is public | Irreversible |

**HUS's answer:** Answer one question — *"Has this person already signed up for this app?"* — without ever learning their identity, storing their biometric, or knowing which previous registration matched.

---

## 2. Why Biometrics

Biometrics are the only Sybil-resistant signal that is **intrinsic to a human**. Unlike:
- **Proof-of-work** — you can rent compute
- **Proof-of-stake** — you can borrow capital
- **Social verification** — you can create fake social graphs
- **CAPTCHAs** — solvable by AI, outsourced to click farms

Biometrics require *your actual body* to be present. Combined with liveness detection, this makes automated Sybil attacks extremely expensive.

## 3. Why Cancelable Biometrics (ISO/IEC 24745)

Storing raw biometrics (even hashed) is dangerous because biometrics are not passwords — you can't change your face when it leaks. The ISO/IEC 24745 standard mandates three properties:

**Irreversibility:** Given the stored template, an attacker cannot recover the original biometric.

**Unlinkability:** The same person registering in two different apps produces completely different templates — the apps cannot collude to track the user.

**Renewability:** If a database is breached, the app changes its unique key (seed), and the same face generates a completely new template. The stolen data becomes useless.

HUS achieves all three through **BioHashing (matrix projection)** — the raw embedding is multiplied by an app-specific matrix derived from a random seed. The result is:
- Dimension-reduced (e.g., 512 → 128), which is information-destroying → **irreversible**
- Different per app (different seed → different matrix) → **unlinkable**
- Change the seed → new template for the same face → **renewable**

---

## 4. Why 7 Modalities

HUS supports Face, Iris, Voice, Fingerprint, Keystroke, TouchGesture, and Gait. The app chooses what works for its context.

**Why not just one?** Single-modality systems fail when that sensor is unavailable, the user has a disability affecting that modality, or an attacker finds a spoof for that specific sensor. Multi-modality forces attackers to spoof *multiple independent biometrics simultaneously*, which is exponentially harder.

**Why include behavioral modalities (keystroke, touch, gait)?** They require zero special hardware — every phone has a keyboard, touchscreen, and accelerometer. They work passively in the background with no user friction.

**Why include fingerprint?** While mobile OS restricts raw fingerprint access, enterprise hardware (bank kiosks, voting terminals, border control) has dedicated fingerprint scanners that export feature vectors. HUS doesn't dictate hardware — the app knows what sensors are available.

---

## 5. Why Capture on Device

Raw biometrics should never exist anywhere except the user's device memory. If the device is compromised during capture, only that session is at risk — not a central database of millions of faces.

HUS owns the capture pipeline through the `Capture` trait. The app calls `capturer.capture()` and receives a `RawCapture` — but the app never inspects the raw pixel/audio data. It passes it straight to the extractor.

---

## 6. Why Quality Pre-Check

Before extracting features, HUS checks capture quality:

| Check | Why |
|-------|-----|
| Too dark / too bright | Face or iris capture in bad lighting produces garbage embeddings |
| Blurred | Motion blur or out-of-focus makes geometry extraction unreliable |
| Low SNR | Background noise degrades voice feature extraction |
| Occlusion | Partially covered face (mask, hand) produces incomplete vectors |

**Without quality checks,** the system would accept bad captures, generate noisy embeddings, and produce unreliable distance scores — leading to false rejections (user is actually unique but system says duplicate) or false acceptances (duplicate passes as unique).

---

## 7. Why Liveness Detection

A photo of someone's face is not the person. A recorded voice is not the speaker. Liveness detection forces the user to respond to unpredictable challenges (blink, smile, repeat a phrase, walk a few steps).

HUS implements per-modality challenge-response:
- **Face:** blink, smile, depth movement
- **Voice:** repeat a random phrase, hum
- **Gait:** walk natural, turn around

This prevents deepfakes, photos, silicon masks, and voice recordings from passing verification.

---

## 8. Why Feature Extraction on Device

The embedding extractor runs entirely on the user's device. For behavioral modalities (keystroke, touch, gait), extraction is pure Rust math — no external files needed. For ML modalities (face, iris, voice, fingerprint), the ONNX model runs locally via `tract`.

**Why not extract server-side?** Sending raw captures to a server defeats the entire privacy model. The device captures → immediately discards the raw image → keeps only the embedding vector (which is already non-reversible). No raw biometric ever leaves the device.

---

## 9. Why Matrix Projection (BioHashing)

This is the core of HUS's privacy model. The raw embedding $V \in \mathbb{R}^n$ is multiplied by an app-specific projection matrix $M \in \mathbb{R}^{k \times n}$:

$$V_{obf} = V \times M$$

**Why this specific approach?**

1. **Cross-app unlinkability:** App A and App B have different seeds, so different matrices. The same face produces completely different $V_{obf}$ in each app. Collusion between apps reveals nothing.

2. **Irreversibility:** The projection reduces dimension (e.g., $512 \rightarrow 128$), which is mathematically information-destroying. Given $V_{obf}$ and $M$, there are infinitely many $V$ that satisfy $V_{obf} = V \times M$.

3. **Renewability:** If the app's database is breached, the app generates a new seed. The same user's old $V_{obf}$ is worthless — they just re-enroll with the new matrix.

4. **Distance preservation:** The projection approximately preserves Euclidean distances (Johnson-Lindenstrauss lemma). If two embeddings are similar in the original space, their projected versions remain similar. This is what makes on-chain L₂ distance meaningful.

5. **Deterministic from seed:** The matrix is derived purely from the 32-byte seed via Gram-Schmidt orthogonalization on pseudo-random rows. No randomness needed at enrollment time — just the seed. This means the client can derive the matrix independently without the server sending it.

---

## 10. Why Poseidon (not SHA-256) for Commitments

The commitment $C = \text{Poseidon}(V_{obf} \parallel \text{nonce})$ binds the user to their projected vector without revealing it.

**Why Poseidon instead of SHA-256?**

| Property | SHA-256 | Poseidon |
|----------|---------|----------|
| R1CS constraints | ~30,000 per hash | ~1,200 per sponge |
| ZK friendliness | Not designed for ZK | Designed for ZK circuits |
| Security | 128-bit | 128-bit (conjectured) |
| Implementation complexity | High in R1CS | Low (algebraic) |

Poseidon is an algebraic hash that uses only field operations (addition, multiplication) in $\mathbb{F}_p$, making it ~25× cheaper than SHA-256 inside a ZK circuit. Since the proof must hash the preimage inside the circuit, using Poseidon dramatically reduces proving time.

**Why include a nonce?** Without a nonce, $C = \text{Poseidon}(V_{obf})$ would allow brute-force preimage searches. The nonce (a random field element chosen per enrollment) expands the search space to $2^{254}$ — computationally infeasible.

---

## 11. Why Groth16 on BN254 (and its Limitation on Shellnet)

HUS uses **Groth16 on BN254** with off-chain verification via arkworks.

**Why Groth16 on BN254:**

1. **Efficient off-chain verification.** arkworks Groth16 verification on BN254 takes ~2 ms. The proof is 128 bytes, small enough for any bandwidth budget.

2. **Mobile proving.** Groth16 proving completes in ~1–5 s (native) to 3–10 s (WASM) for the ~2000-constraint Poseidon circuit.

3. **Proof size.** 128 bytes (3 BN254 group elements).

4. **Phase 1 trusted setup.** BN254 Powers of Tau is a universal ceremony — no circuit-specific ceremony needed.

**Why BN254 (over BLS12-381):** arkworks has mature BN254 support, and GOSH TVM's `VERGRTH16` opcode (if unblocked) would natively verify BN254 proofs.

**Important limitation:** The `gosh.vergrth16` opcode on Shellnet v3.0.2 uses **hardcoded ZkLogin proving keys**, not the contract's stored VK. Custom circuit Groth16 proofs cannot be verified on-chain. Until a new opcode (`gosh.vergroth16`) is available with explicit VK parameterization, proof verification happens off-chain via `verify_projected()`.

---

## 12. Why L₂ Distance On-Chain (Not in the ZK Circuit)

**The current design:** The ZK circuit proves $C = \text{Poseidon}(V_{obf} \parallel \text{nonce})$. The L₂ distance check against existing registrations happens in the smart contract, not the circuit.

**Why not put distance inside the circuit?**

- **Floating-point is expensive in R1CS.** Euclidean distance requires squaring, summing, and square-root of floating-point values. Fixed-point workarounds exist but add significant complexity and constraints.
- **V_obf is already safe to store.** The projected vector is application-specific and non-reversible. Storing it on-chain doesn't leak the original biometric or enable cross-app tracking.
- **Contract-side distance is simple and auditable.** The L₂ computation is ~20 lines of Rust in the contract — easy to review, formally verify, and maintain.

**The trade-off:** The chain learns $V_{obf}$ (the projected vector). But since $V_{obf}$ is:
1. Already dimension-reduced and non-reversible
2. Application-specific (different per app)
3. Bound to a specific seed

...this is an acceptable disclosure. The alternative (distance inside ZK circuit) would increase proving time by ~3× and add significant circuit complexity for marginal privacy gain.

---

## 13. Why Duplicate Check by Commitment AND by Distance

Two different checks prevent two different attacks:

| Attack | Check that stops it |
|--------|--------------------|
| **Replay:** Attacker captures a valid submission and resubmits it | Commitment uniqueness — same $C$ rejected |
| **Same biometric, new commitment:** Attacker is the same person but uses a different nonce to get a different $C$ | L₂ distance — same $V_{obf}$ produces score ≥ 80 |

Both checks are necessary. Without commitment uniqueness, replay is trivial. Without distance check, a user could bypass uniqueness by incrementing their nonce.

---

## 14. Why Multi-Modality

Requiring multiple biometric modalities at once provides:

1. **Harder to spoof:** An attacker must simultaneously spoof face + voice + keystroke patterns, not just one.
2. **Graceful degradation:** If one sensor is unavailable (no camera, too noisy for voice), the user still passes with remaining modalities.
3. **Higher confidence:** The fusion of independent biometric signals is more reliable than any single signal. A keystroke pattern + gait + face is exponentially harder to fake than just a face.

The quality gate (`check_quality_gate`) determines how many must pass:
- 2-3 modalities: all must pass
- 4+ modalities: ceil(count × 3/4) must pass

This ensures a single noisy modality doesn't block a legitimate user, while preventing attackers from exploiting a single weak modality.

---

## 15. Why Liveness + Quality Gate Are Separate Steps

The pipeline is: **Capture → Quality → Liveness → Extract → Project → Commit → Prove**

Each step filters out different failure modes:

| Step | Filters out |
|------|-------------|
| Capture | No sensor, permission denied, timeout |
| Quality | Bad lighting, blur, low SNR, occlusion |
| Liveness | Photo, recording, deepfake, mask |
| Extract | Malformed data, unsupported format |
| Project | Wrong seed, dimension mismatch |
| Prove | Invalid circuit, bad parameters |

Separating these steps means each can produce a specific error message, making debugging straightforward.

---

## 16. Why Contract Stores V_obf (not Just Hashes)

The `Registration` struct stores the full projected vector `v_obf` as `int64[]` (IEEE 754 f32 bit patterns sign-extended) alongside the commitment hash.

**Why the full vector?** The L₂ distance computation needs the raw projected values, not a hash. If only hashes were stored, the contract couldn't compute distance between a new submission and existing registrations.

**Is this safe?** Yes, because:
- $V_{obf}$ is already obfuscated by the projection matrix (irreversible)
- $V_{obf}$ is application-specific (different seed → different values)
- The raw embedding $V$ is never stored
- The app seed is not stored on-chain (only in the app's backend)

---

## 17. Why Timelocked Upgrades (Not Full Immutability)

HUS contracts started as **fully immutable**, but two hard lessons from production use forced a change:

**What went wrong with full immutability:**
1. **The `address(0)` vs `addr_none` bug** — A Solidity edge case on GOSH caused new HusApp deployments to fail. With immutable contracts, every deployed HusApp would have been permanently broken.
2. **No VK rotation** — If the Groth16 verifying key needed updating (e.g., trusted setup ceremony extended, cryptographic weakness found), every existing HusApp would be stuck with the old key.
3. **Modality configs frozen** — Threshold tuning, dimension adjustments, and modality additions all required a new registry + full user re-enrollment — a Sybil attack opportunity (adversary re-enrolls first).

**The compromise — timelocked upgrades:**

```
Owner proposes upgrade ──→ 7-day timelock ──→ Anyone executes
     ↓                          ↓
   Stored in                 Users can exit
   pendingUpgrades           if they disagree
```

| Property | How it's preserved |
|----------|-------------------|
| **No rug pulls** | 7-day timelock gives users time to withdraw or migrate |
| **No backdoors** | Only the `HusApp` code and VK can change. Past registrations are immutable — no admin can delete or modify them |
| **Bug fixes** | Critical vulnerabilities can be patched (after the timelock) |
| **VK rotation** | Registry owner updates VK → proposes upgrade → each HusApp gets the new VK after delay |
| **No forced upgrades** | The timelock is enforced in contract code, not in social coordination |

### The mechanism

**`HusRegistry`** is the upgrade controller:
- `proposeAppUpgrade(appId, newCode, newVk)` — Owner encodes the new HusApp code + VK
- `cancelAppUpgrade(appId)` — Owner can cancel before the timelock expires
- `executeAppUpgrade(appId)` — Anyone can trigger after 7 days; registry sends an internal message to the HusApp

**`HusApp`** receives upgrades from the registry only:
- `upgradeCode(newCode, newVk)` — Verifies `msg.sender == husRegistry`, then calls `tvm.setcode(newCode)` to replace the contract code while preserving all state (registrations, commitments, counters)
- `setVk(newVk)` — VK-only update without a full code replacement (lower risk, no timelock)

### Why this is better than full immutability

| Scenario | Immutable | Timelocked |
|----------|-----------|------------|
| Critical bug in L₂ distance | Redeploy → all users re-enroll | Patch after 7 days → no re-enrollment |
| User does not trust new code | Must trust the original deploy | Can withdraw/exist before timelock expires |
| VK compromised | All registrations invalidated | Rotate VK, existing proofs still valid |
| Modality config tuning | Requires new deploy | Can be included in code upgrade |
| Proving key too large (17MB) | Stuck with oversized keys | Upgrade to chunked-key version |

### What stays immutable

Past registrations cannot be altered, deleted, or reordered. The `_registrations` array and `_seenCommitments` mapping are append-only. An upgrade can change **how** future submissions are verified, but not **what** was already accepted.

This preserves the core security guarantee: *"No one can retroactively delete my uniqueness proof."*

---

## 18. Why Acki Nacki

HUS targets Acki Nacki because:

- **WASM smart contracts** — HUS's contract compiles to WASM and runs natively without EVM translation overhead
- **Parallel execution** — AN runs contracts in isolated threads, so HUS verification for different apps runs in parallel
- **Rust-native SDK** — The contract language is the same as the SDK (Rust), reducing the paradigm gap
- **No gas for view calls** — Reading app seeds and registry data is free

The contract also works on any WASM-capable chain with minimal adaptation.

---

## 19. What HUS Does NOT Do

| What people sometimes expect | Why HUS doesn't do it |
|------------------------------|-----------------------|
| **Authenticate users** ("Is this Alice?") | HUS answers uniqueness, not identity. It doesn't know *who* you are. |
| **Store identity mappings** | No mapping from wallet → real identity. No KYC records. |
| **Provide cross-app identity** | App A cannot query "is this user in App B?" — different seeds prevent this. |
| **Guarantee liveness** | Liveness detection raises the bar but is not perfect. Defense-in-depth with multi-modality reduces risk. |
| **Cryptographic security before trusted setup** | BN254 Powers of Tau is a Phase 1 ceremony — universal, not circuit-specific. The same parameters secure all circuits on BN254. The ceremony has been run by multiple independent parties. |
| **Work without user consent** | The user must actively capture their biometrics. Passive/enrollment without consent is not possible. |
| **Replace passwords** | HUS is not an authentication system. It's a duplicate-check oracle for registration gates. |
| **On-chain Groth16 verification** | `gosh.vergrth16` uses ZkLogin VKs, not custom circuit VKs. Proof verification is off-chain until a new opcode ships. |

---

## 20. Summary of Design Goals

| Goal | How HUS achieves it |
|------|-------------------|
| No raw biometric storage | Capture + extract on device; only $V_{obf}$ and $C$ reach the chain |
| Cross-app unlinkability | Per-app matrix projection from independent seeds |
| Irreversible templates | Dimension-reducing projection + Poseidon commitment |
| Renewable on breach | New seed → new matrix → new template; old data useless |
| Sybil resistance | Duplicate commitment + L₂ distance rejection on-chain |
| Multi-modality resilience | 7 modalities, quality gate, graceful degradation |
| Liveness assurance | Challenge-response per modality |
| Immutability with timelocked upgrades | HusApp immutable after deploy; registry can propose upgrades with 7-day delay |
| Auditability | ~20-line L₂ distance in contract, simple scoring function |
| Client-side privacy | Raw data never leaves device memory |

---

*This document reflects HUS v0.3.0. Design decisions may evolve as the system matures.*
