# HUS on AVM: one person, one registration

Contracts and a library that let any Acki Nacki AVM application enforce **one
registration per person** without collecting identities, using HUS (Human
Uniqueness System): a phone turns a person's biometrics into an obfuscated
vector with a per-app seed and proves it with a Groth16 proof; the chain keeps
the vector and rejects anyone too close to an existing registration.

Everything here is MIT-licensed. It is laid out like
[`gosh-sh/avm-sdk`](https://github.com/gosh-sh/avm-sdk), so each directory under
`examples/` can be copied into that repository's `examples/` and built there.

| Path | What |
|---|---|
| `examples/hus-registry/` | AVM contract: per-app uniqueness registry. Works today. |
| `examples/hus-zk/` | Library: BN254 `g1_add`, `g1_mul`, `pairing_check` (EIP-196/197 encoding) and Groth16 verification, with a pure-WASM backend and a native backend over proposed host functions. |
| `examples/hus-zk/HOST-FUNCTIONS.md` | The specification of the three host functions we ask AVM to add. |
| `examples/bn254-ops/` | AVM contract: G1 add and multiplication through `hus-zk`, checked on the stand; with `--features native`, also the pairing check. |
| `scripts/` | Local-stand end-to-end and load tests. |

## `hus-registry`

Deploy one registry per app; the deploy salt names the app, and the init data
is the config (`Config::encode` in `src/registry.rs`): vector dimension,
duplicate threshold, LSH parameters and seed, storage precision, verification
mode, attestors.

`hus.register` takes `commitment (32) | v_obf (dim × i64 LE, ×10⁶ fixed point) | proof`
and returns status 0 or one of:

| Status | Meaning |
|---|---|
| 3001 | malformed registration |
| 3002 | caller is not an attestor (attestor mode) |
| 3003 | **duplicate person**: a stored vector is closer than the threshold |
| 3004 | the commitment is already registered (replay) |
| 3005 | this registry shard is full (2,000 people; checked after 3003/3004, so a full shard still recognises people it holds) |
| 3006 | a `v_obf` value does not fit i32 |
| 3007 | proof verification requested but not built in (no native host functions) |
| 3008 | the Groth16 proof does not verify |

**Duplicate detection that fits AVM.** Comparing a new vector with one stored
vector costs about 25k FUEL, so a full scan stops fitting a message after a few
hundred users. Vectors are bucketed by a sign random projection (8 ±1
hyperplanes, 256 buckets); a new vector is compared with its own bucket plus
the buckets reached by flipping its least-certain bits (up to 4, so at most 16
buckets).
On synthetic data (128-dimension Gaussian vectors, rescans with noise σ = 0.1
per coordinate, threshold L2 < 5; not real biometrics), with 1,500 people
registered: **2,999 of 3,000 rescans caught**, and a new person is compared
with 25 stored vectors on average, 133 at worst.

**Compact records, because storage rent is per byte.** Each registration
stores a 16-byte replay key (the commitment's two halves XORed), its bucket
(2 bytes), and `v_obf` at a configurable precision: `cell` bytes per
coordinate (1, 2 or 4) in steps of `quant_step`. The default, 1 byte in steps
of 1/16 (values beyond ±8.0 are clamped), makes a 128-dimension record
146 bytes instead of 546, about a quarter of the rent. Only the stored copy is
rounded; the incoming vector keeps full precision, and on the synthetic data
above recall is unchanged. `cell = 4, quant_step = 1` stores vectors exactly
(530 bytes) for apps whose vectors do not suit the default range.

**Verification modes.**
- `Attestor`: only configured external signers (gateways that verified the
  Groth16 proof off-chain) may register; with no attestors, anyone may. Proofs
  travel in the message, so anyone can re-verify them later.
- `NativeGroth16`: the contract verifies the proof itself with `hus-zk`. Build
  with `--features native-groth16`; it imports the three `avm_crypto` host
  functions and nothing else. The `groth16` feature alone uses the pure-WASM
  backend, which the native tests use with a real HUS proof.

## What we learned about AVM (release `avm-dev-335a0f09fdbc`)

These may be useful to the AVM team and to other developers:

1. **The per-message FUEL cap is about 10M** (most likely exactly
   10,000,000), whatever `fuel_fee_shells` is: a metered 9.88M-FUEL G1
   multiplication passes and a 9.97M one fails with VM status 31
   (`scripts/stand-fuel-cap.sh`). Groth16 in WASM is about 34× over it; see
   `examples/hus-zk/HOST-FUNCTIONS.md`.
2. **Deploy bodies are limited to about 64 KiB** (`BodyTooLarge` between
   57.4 KB and 65.6 KB of WASM).
3. **A full state replace is limited to about 64 KiB**: a `FullReplace` state
   of 65,594 bytes is accepted and one of 66,140 fails with VM status 43.
   Larger accounts work when the contract returns `DataPatchList` whenever the
   runtime asks for it (`required_state_output_mode`): one `hus-registry`
   account holds a full shard of 2,000 registrations (292 KB with compact
   records; the earlier 546-byte format reached 709 KB) with every
   registration accepted and every rescan still caught
   (`scripts/stand-load.sh 2000`).
4. **`init` receives the whole canonical deploy payload (`ACDP`)**, code
   included, and the SDK has no accessor for the init data inside it.
   `deploy_init_data` in `hus-registry` reads it from the layout of this
   release (salt length u16 at 266, init field length u32 at 268, salt at
   288, then the init field as an ABI `bytes` value). Decoding it by hand is
   fragile: our first version read another field that happened to equal the
   old config's length, and broke as soon as the config grew. An SDK
   accessor would make this robust.
5. **Contracts must be built without SIMD** (`-C target-cpu=mvp` when building
   outside `avm-contract-build`): the profile disables `wasm_simd`.
6. **Unused `fuel_fee_shells` is burned** when the message requests no
   callback. A registration succeeds with a reserve of 1 SHELL (0 is refused
   with `RouteRequiresFee`), and is then charged 2 SHELL plus any storage rent
   due; a reserve of 100,000 adds exactly 100,000.
7. **The local stand charges storage rent on every touch, unlike mainnet
   TVM.** On `avm-local-stand` rent is about 1 SHELL per byte per second,
   collected when the account is next touched: a 40-person registry (6.3 KB)
   owed about 543 million SHELL after one day (`scripts/stand-cost.sh 40`).
   On mainnet TVM, storage is charged only after an account has been
   inactive for 30 days, and same-thread internal messages within a DApp are
   effectively free. `docs/fuel-and-fees.md` says AVM's local-free route
   "does not waive storage rent". Which rent policy will AVM mainnet
   use? It decides whether a busy registry pays for storage at all.
8. **`avm-local-stand` needs an x86-64-v3 CPU** (AVX2, BMI2, FMA, MOVBE); on
   older machines every deploy fails with `EngineBuildFailed`.

## Build and test

Requirements: Linux x86-64-v3, Rust via rustup (the toolchain is pinned in
`rust-toolchain.toml`), the AVM SDK release installed with its `crates/`
reachable as `./crates` (symlink it, or copy `examples/*` into an `avm-sdk`
checkout), `jq`.

```bash
cd examples/hus-zk && cargo test --release                 # BN254 + Groth16 conformance
cd ../hus-registry && cargo test --release --features groth16
avm-contract-build build --manifest-path examples/hus-registry/Cargo.toml
cargo build --release --example gen --manifest-path examples/hus-registry/Cargo.toml
scripts/stand-e2e.sh          # deploy, register, rescan (3003), replay (3004)
scripts/stand-load.sh 2000    # a full shard, then rescans (3003) and one more (3005)
avm-contract-build build --manifest-path examples/bn254-ops/Cargo.toml
scripts/stand-bn254.sh        # G1 add/mul results vs Python; full-width mul exceeds the cap
scripts/stand-fuel-cap.sh     # bisects the per-message FUEL cap
scripts/stand-cost.sh 40      # charge per registration, and storage rent over time
```

## License

MIT, see `LICENSE.md`.
