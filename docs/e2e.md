# HUS End-to-End Flow

## Summary

1. Deploy HusRegistry (one-time, any deployer)
2. Owner sets VK and uploads proving key (chunked, ~544 tx)
3. Developer calls `registerApp(appName, modalityIds)` → deploys HusApp
4. Developer funds HusApp via `deposit(paymentId)` with SHELL
5. User captures biometric via HUS SDK → extracts → projects → V_obf
6. SDK generates Groth16 proof locally
7. **Proof verified off-chain** via `verify_projected()` (working path)
8. Gateway calls `HusApp.submitCommitment(commitmentHash, vObf, modalityId)`
9. HusApp checks L2 duplicate detection against existing registrations
10. If unique, stores registration; emits `UniquenessResult` event

## Phase A — Deploy HusRegistry (one-time)

```bash
./scripts/deploy.sh https://shellnet.ackinacki.org/graphql /path/to/wallet.keys.json
```

The script:
1. Compiles `HusRegistry.sol` and `HusApp.sol` with `sold` (two-pass: first for `.tvc`, then `--abi-json`)
2. Extracts HusApp code cell (base64) for the registry's constructor
3. Funds deployer via GiverV3
4. Deploys HusRegistry with constructor param: `appCode` (TvmCell)

### Post-deploy (owner only)
- `setVk(vk)` — set verifying key
- `setProvingKeyChunk(index, chunk)` × ~544 — upload 17MB PK in 32KB chunks
- `setProvingKeyHash(hash)` — set SHA-256 integrity hash

## Phase B — Register an App (permissionless)

```bash
# Anyone can call registerApp
tvm-cli call <registry_address> registerApp \
  '{"appName":"my-app","modalityIds":[0,4,6]}'
```

- HUS derives `appId = hash(msg.pubkey(), appName)`, generates `seedHash` via `tvm.randomize()`
- Deploys a new `HusApp` with hardcoded `PROJ_DIM=128` and `MIN_SCORE=80`
- Developer funds the HusApp: `HusApp.deposit(paymentId)` — sends SHELL for gas

## Phase C — User Registration (phone-side)

1. **Capture**: raw biometric data from device sensors
2. **Extract**: on-device ML → embedding vector (e.g., 512-dim for face)
3. **Quality gate**: verify enough modalities passed
4. **Project**: `derive_and_project(seed, embedding, 128)` → V_obf (ISO/IEC 24745)
5. **Commit**: `C = Poseidon(V_obf || nonce)` → 32-byte commitment
6. **Prove**: `prove_projected(&pk, &v_obf)` → (proof_bytes, commitment_hash)
7. **Verify**: `verify_projected(&vk, &proof, &commitment, &v_obf)` → bool

## Phase D — On-Chain Submission (working path)

```rust
let result = app.submit_commitment(
    commitment_hash,  // hex string
    &v_obf,           // Vec<i64> (f32 bit patterns sign-extended)
    modality_id,      // u8
    signer,
).await?;
```

The contract:
1. Checks `_seenCommitments[commitmentHash]` for replay prevention
2. Iterates all registrations of the same `modalityId`, computes L2 distance
3. Score = `f(min_distance)` — if ≥ 80, reject as duplicate
4. If unique: stores `Registration{commitmentHash, vObf, modalityId, timestamp, proof}`
5. Emits `UniquenessResult(appId, isUnique, score)`

## Phase E — Result

- Gateway returns transaction receipt
- App reads via `getRegistration(index)` → `(commitmentHash, vObf, modalityId, timestamp, proof)`

## Who Pays

| Step | Who Pays | Asset |
|------|----------|-------|
| Contract deploy | Deployer | SHELL |
| `registerApp` | Caller | SHELL |
| `deposit()` | Developer | SHELL → VMSHELL |
| `submitCommitment` | HusApp balance (funded via deposit) | VMSHELL |

## Known Limitation

`submitWithProof()` exists but cannot verify custom Groth16 proofs on-chain — the `gosh.vergrth16` opcode uses hardcoded ZkLogin VKs. The working path is off-chain verify + `submitCommitment()`.
