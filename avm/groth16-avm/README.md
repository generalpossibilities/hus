# groth16-avm: Groth16 (BN254) verification on AVM, test material

Everything behind the numbers in [`../avm-groth16-native-request.md`](../avm-groth16-native-request.md).
It was measured on 9 October 2026 with the AVM SDK release built from:
- `gosh-sh/acki-nacki` @ `335a0f09fdbc98eb7a1056c0f6b84cd4f39d889e`;
- `gosh-sh/avm-sdk` @ `0cbca40fad9a8f11863197cbcbaf6208651752b9`.

The tools were `avm-local-stand` and `avm-contract-build`, with Wasmtime profile `AVM_WASMTIME_X86_64_V3_V1` (Wasmtime 36.0.12).

## Layout

| Path | What |
|---|---|
| `contracts/hus-groth16/` | AVM contract with the arkworks verifier (`ark-groth16` + `ark-bn254`), a direct port of `verifier/src/verify.rs`. 348 KB, or 110 KB size-optimised: rejected with `BodyTooLarge`. |
| `contracts/hus-g16-bn/` | Minimal AVM verifier on `substrate-bn` using raw coordinates. 63.9 KB: **deploys**. Verification exceeds the per-message FUEL cap (VM status 31). |
| `contracts/hus-g16-dbg/` | Diagnostic version. It records what it received in its state, and a trailing stage byte selects the work done: 0 nothing, 1 parse, 2 parse + MSM, 3 parse + pairing, 4 full, 5 G1 points only, 6 one G2 point, `0x10+k` a calibration loop of 1000·2^k rounds. |
| `vectors/` | Real HUS test vectors (see below). |
| `tools/husfix/` | Native tools on the HUS SDK. `main` generates `good.bin`/`bad.bin` with the production proving key; `convert` produces the raw-coordinate files and checks the `substrate-bn` verifier natively; `bench` times proving and verification; `pkload` times proving-key loading. |
| `tools/fuelmeter/` | Wasmtime fuel measurement of the same verifier (`guest` is wasm32, `host` is the native Wasmtime runner with `consume_fuel`). |
| `stand-scripts/` | The scripts used against `avm-local-stand`: deploy, call, stage sweep, and the deploy-size bisection with padded contracts. They expect the AVM SDK checkout at `/home/ubuntu/avm-sdk`; adjust the paths. |

The contracts depend on `avm-contract-sdk` via `../../crates/avm-contract-sdk`, so copy them into `avm-sdk/examples/` before running `avm-contract-build`.

## Test vectors

The circuit has 129 public inputs, `[commitment] ++ v_obf[128]`. The proof is for `v_obf[i] = i / 100`.

| File | Format | SHA-256 |
|---|---|---|
| `vk.bin` | arkworks `VerifyingKey<Bn254>`, uncompressed (same as `keep/vk.bin` and `verifier/assets/vk.bin`) | `85459f4c…fab017` |
| `vk_raw.bin` | raw: α G1 · β G2 · γ G2 · δ G2 · `n` u32 BE · IC[n] G1 (n = 130) | `58c9101f…f3830a` |
| `good.bin` | HUS wire format: `[plen u32 LE][proof (arkworks compressed, 128 B)][commitment 32 B][v_obf 128 × i64 LE]`, 1,188 B. **Valid.** | `f7028576…1c9895` |
| `bad.bin` | as `good.bin` with `v_obf[0] + 1`. **Must fail.** | `5ca733fc…f350a` |
| `good_raw.bin` | raw: A G1 · B G2 · C G1 · commitment (Fr BE) · v_obf 128 × i64 LE, 1,312 B. **Valid.** | `fa7e0ab9…40bd1a` |
| `bad_raw.bin` | raw form of `bad.bin`. **Must fail.** | `3bd06505…48d00a1` |

Raw encoding is big-endian. G1 is `x | y` (64 B); G2 is `x.c1 | x.c0 | y.c1 | y.c0` (128 B), the EIP-197 order used by Ethereum's pairing precompile.

On AVM, a `bytes` ABI argument reaches the contract as a u32 LE length followed by the data. With the CLI, pass it as a `"0x…"` hex string.

## Results

**Deploy size:** a 57.4 KB contract deploys and a 65.6 KB one is rejected (`BodyTooLarge`), so the limit is about 64 KiB per deploy message.

**FUEL**, measured with Wasmtime fuel metering on the same build settings:

| Step | FUEL | In AVM |
|---|---|---|
| Calibration loop, 256k rounds | 6.1M | passes |
| Calibration loop, 512k rounds | 12.3M | VM status 31 |
| G1 points only | 0.08M | passes |
| One G2 point (subgroup check) | 55M | VM status 31 |
| Parse key + proof | 221M | VM status 31 |
| + MSM over 129 inputs | 393M | VM status 31 |
| **Full verification** | **681M** | VM status 31 |

VM status 31 appeared regardless of `fuel_fee_shells`, from 10⁶ to 10⁹. The per-message cap therefore lies **between 6.1M and 12.3M FUEL**.

**Natively** (HUS SDK, production keys), proof generation itself takes **under about 1 s on a server CPU and about 5.7 s on a 2010 laptop CPU**, once the proving key is loaded:

| Machine | Proving-key load, validated | Proving-key load, unchecked | `prove_projected` total | Verify |
|---|---|---|---|---|
| AMD EPYC (shared vCPU) | 27.2 s | 0.04 s | 27.0 s (proving itself < ~1 s, within noise) | ~22 ms |
| Intel i7 M620 (2010 laptop) | 39.9 s | 0.05 s | 45.6 s (proving itself ≈ 5.7 s) | ~39 ms |

`prove_projected` deserialises the 17 MB proving key with full point validation on every call, and that dominates the total. Checking the key's SHA-256 once (HusRegistry publishes it) and then loading it unchecked, or keeping it in memory, removes the delay.
