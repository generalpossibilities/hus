# Request to the Acki Nacki AVM team: native Groth16 (BN254) verification on AVM

**From:** HUS team (Human Uniqueness System)
**To:** Acki Nacki AVM team
**Date:** 9 October 2026
**Priority:** High for us. It decides whether HUS can verify proofs on-chain on AVM.

---

> **Update, 13 October 2026: newer measurements and a working contract.**
> - **Per-message FUEL cap:** pinned to about **10M** (a metered 9.88M-FUEL
>   operation passes, 9.97M fails with VM status 31).
> - **Pure-WASM Groth16 after optimisation:** about **342M FUEL** in the best
>   case (trusted key, 2 public inputs), **533M** for our current 129-input
>   circuit. That's still 34–53× over the cap, so the figures below (681M,
>   6–12M) are superseded.
> - **Our ask is now the Ethereum-standard set:** `bn254_g1_add`,
>   `bn254_g1_mul` and `bn254_pairing_check` (EIP-196/197), priced like
>   EIP-1108. With them a 2-input verification costs about 1.9M FUEL.
> - **Spec, library, test vectors and a working AVM registry contract** (MIT),
>   laid out for the AVM SDK's `examples/`:
>   [branch `avm-sdk`](https://github.com/generalpossibilities/hus/tree/avm-sdk),
>   spec in `examples/hus-zk/HOST-FUNCTIONS.md`.

## TL;DR

HUS is moving from our earlier TVM design to **AVM**. We need contracts to verify **Groth16 proofs on BN254 against their own verifying key**. Today that isn't possible in a single AVM message.

We measured it on the AVM local stand. A pure-WASM Groth16 verifier deploys, but one verification needs about **681 million FUEL**. The per-message cap we measured is **6–12 million FUEL**.

**What we're asking for**, most to least preferred:

1. **A native Groth16 verification host function** on AVM, accepting a custom verifying key.
2. **Native BN254 primitives** (pairing check, G1 add/mul), so contracts can verify Groth16 cheaply themselves.
3. **If neither is planned, a supported way to make it work for HUS:** a higher FUEL tier for a whitelisted verifier package, an official verifier contract, or guidance on an approved multi-message pattern.

---

## Why we are moving to AVM

HUS gives apps Sybil resistance without identity:
- A phone turns a person's biometrics into a projected vector, using a **per-app seed**, so different apps can't link the same person.
- The phone commits to that vector with Poseidon and proves it with **Groth16**.
- The chain checks the proof, stores the commitment and the obfuscated vector, and rejects duplicates.

On the previous TVM design we hit two walls:

- **`gosh.vergrth16`** verifies only against the protocol's built-in ZkLogin verifying keys. A custom circuit's key can't be used.
- **`gosh.runwasm`** worked end to end in our local executor harness. But it needs an operator to place our WASM file on each node (`config/wasm/<sha256>`) and whitelist its hash. That keeps verification dependent on node configuration rather than on the chain. Our earlier request is in `avm/shellnet-runwasm-request.md`.

## Why native Groth16 matters for decentralisation

Acki Nacki is building toward a decentralised chain where the chain itself, not trusted servers, decides what is valid. For zero-knowledge applications that means verification has to happen **on-chain**:

- **Without it:** every ZK project on AVM runs its own off-chain verifiers and asks users to trust them. Data and trust stay centralised, in the verifier operators.
- **With it:** proofs and their verification live on-chain. Anyone can check them, no gateway is needed, and the data stays decentralised.

## Why Groth16 specifically, and not only Halo2

We know Acki Nacki already supports **Halo2/KZG** verification natively on TVM (`ZKHALO2VERIFY`), and we value that. We checked AVM as well:
- The contract SDK states: *"The crate deliberately has no host imports."*
- Neither `avm-local-stand` nor `avm-contract-build` contains any Halo2, KZG, Groth16 or pairing support.
- Compiled AVM contracts import nothing from the runtime.

HUS proves **on mobile phones**, with **per-app seeds**, and Groth16 is the practical fit for that:

- **Proof size:** a Groth16 proof is **128 bytes compressed** (256 bytes uncompressed). Halo2 proofs are several kilobytes. Size matters for mobile upload and for on-chain storage and fees.
- **Verification cost:** Groth16 verification is **constant**, three pairings plus a small multi-scalar multiplication, whatever the circuit size. It is the cheapest verification among the common proof systems.
- **Mobile proving:** our circuit (Poseidon commitment plus a 128-dimensional vector, about 2k constraints) generates a proof in **under about 1 s on a server CPU and about 5.7 s on a 2010 laptop CPU**, measured natively with arkworks and our production keys. Verification off-chain takes 20–40 ms. A Halo2 version of the same circuit would mean heavier proving on low-end phones, where HUS has to work.
- **Ecosystem:** Groth16 on BN254 is the de facto standard. Ethereum's precompiles (EIP-196/197) and the tooling around them (circom/snarkjs, gnark, arkworks) all use it. Many ZK projects could deploy to AVM unchanged if AVM supported it.

A native Groth16 path would therefore serve far more than HUS: identity, voting, private payments and gaming projects that prove on mobile could all verify on AVM.

## What we measured on AVM

**Environment:**
- AVM SDK release built from `gosh-sh/acki-nacki` @ `335a0f09fdbc98eb7a1056c0f6b84cd4f39d889e` and `gosh-sh/avm-sdk` @ `0cbca40fad9a8f11863197cbcbaf6208651752b9`;
- `avm-local-stand` and `avm-contract-build`;
- Wasmtime profile `AVM_WASMTIME_X86_64_V3_V1` (Wasmtime 36.0.12);
- a real HUS proof generated with our production proving key, plus a tampered copy as a negative control.

### 1. Code size: fits only with a minimal verifier

| Verifier contract | WASM size | Deploy |
|---|---|---|
| arkworks (`ark-groth16` + `ark-bn254`), `opt-level=3` | 348 KB | `BodyTooLarge` |
| arkworks, size-optimised (`opt-level="z"`, LTO, `panic=abort`, stripped) | 110 KB | `BodyTooLarge` |
| arkworks, uncompressed proof input (no G2 decompression) | 103.5 KB | `BodyTooLarge` |
| Minimal verifier on `substrate-bn`, raw coordinates, 8.7 KB key embedded | **63.9 KB** | **Deploys** |

With padded test contracts, a 57.4 KB contract deploys and a 65.6 KB one is rejected. So the effective limit is about **64 KiB per deploy message**. The minimal verifier gives the same results as arkworks natively: the valid proof passes and the tampered one fails.

### 2. Compute: about 55–110× over the per-message FUEL cap

Every call that ran the cryptography stopped with **`local call returned VM status 31`**. That stayed the same with `fuel_fee_shells` at 10⁶, 10⁷, 10⁸ and 10⁹. Our reading is that this is the per-message execution cap (`max_message_execution_fuel`), not the paid budget.

We bracketed the cap with a fixed calibration loop inside the same contract. **6.1M FUEL passes; 12.3M FUEL fails.**

We then measured the verifier's FUEL with the same Wasmtime fuel metering, on the same WASM build settings:

| Step (HUS circuit, 129 public inputs) | FUEL | Fits in one message? |
|---|---|---|
| Building G1 points only | 0.08M | yes |
| **Validating one G2 point** (subgroup check) | **55M** | no |
| Parsing the verifying key and proof (4 G2 checks) | 221M | no |
| + multi-scalar multiplication over 129 inputs | 393M | no |
| **Full Groth16 verification** | **681M** | **no** (about 55–110× over) |

**What optimisation could achieve:** we plan to cut our public inputs to 2 (passing the vector separately, bound by an in-circuit hash) and to precompute the verifying key (constant `e(α,β)`, prepared γ/δ, no re-validation of our own key). By our estimate a pure-WASM verification would still need **about 150M FUEL or more**, still 15–25× over the cap. In pure WASM, Groth16 can't run in one AVM message. Run natively (about 2 ms with arkworks off-chain, less with an optimised native verifier), it is trivial.

---

## What we're asking for

### Option 1 (preferred): a Groth16 verification host function

```text
groth16_bn254_verify(vk: bytes, public_inputs: bytes, proof: bytes) -> bool
```

- **Custom verifying key** supplied by the caller (or stored by the contract), so any circuit can use it, not only ZkLogin.
- **Encoding:** raw big-endian coordinates compatible with Ethereum's EIP-197, so keys and proofs exported by snarkjs, gnark and arkworks work directly.
- **Pricing:** a fixed FUEL charge plus a small cost per public input, like the EIP-1108 pricing for the Ethereum precompiles.

### Option 2: native BN254 primitives

If a dedicated Groth16 function isn't desirable, expose the building blocks with EIP-196/197 semantics:

```text
bn254_g1_add(p1, p2) -> p
bn254_g1_mul(p, scalar) -> p          (or bn254_g1_msm(points, scalars) -> p)
bn254_pairing_check(pairs: [(G1, G2)]) -> bool
```

Contracts then implement Groth16 (and other pairing-based schemes) in a few lines, at native speed.

### Option 3: if native support isn't planned soon, help us make it work for HUS

Any of these would let HUS verify on AVM in the meantime:

- **A higher FUEL tier** for a whitelisted verifier package (by code hash), enough for one Groth16 verification, at a price set by the protocol.
- **An official verifier contract or library** deployed by Acki Nacki that other contracts call, paid per verification.
- **Guidance on an approved multi-message pattern:** splitting one verification across many messages with intermediate state. We can build this, but it would take about 15–40 messages per proof, so we would want to know it's considered acceptable before investing in it.

---

## Questions

1. What are the **mainnet values** of `max_message_execution_fuel` and `fuel_per_shell`? Are they the same as the local stand's defaults?
2. Is the **~64 KiB deploy/publish body limit** final, and is chunked code publication planned?
3. Is a **ZK or crypto host interface** (Groth16, BN254, Poseidon, signatures) on the AVM roadmap?
4. Would you accept a **contribution** from us (specification, test vectors, benchmark contracts, or a reference implementation) towards Option 1 or 2?

## What we can provide

Everything is in our repository under `avm/groth16-avm/` (see its README):

- The test contracts we used:
  - the arkworks verifier;
  - the minimal `substrate-bn` verifier;
  - a staged diagnostic contract for FUEL calibration.
- A Wasmtime fuel-measurement harness and the stand scripts that reproduce every number above.
- Real HUS test vectors: verifying key, a valid proof and a tampered proof, in arkworks and raw EIP-197 formats, with SHA-256 hashes.
- Our time, to help specify, test or benchmark a native implementation.

Thank you for building AVM. We're glad to be early users, and we'd like HUS to be among the first projects that verify zero-knowledge proofs fully on-chain on it.

**HUS team**
