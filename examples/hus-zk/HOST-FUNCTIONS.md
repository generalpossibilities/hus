# Proposed AVM host functions: BN254 (EIP-196 / EIP-197)

Three host functions would make zero-knowledge proof verification practical on
AVM: the same three curve operations Ethereum has offered since 2017 (EIP-196
and EIP-197, repriced by EIP-1108). This document specifies them precisely
enough to implement, and `hus-zk` already calls them through its `native`
feature, so contracts written against `hus-zk` need no change once a runtime
provides them.

## Why

Measured with Wasmtime fuel metering on the AVM build settings (release
`avm-dev-335a0f09fdbc`), against a per-message cap we bracketed at 6.1M–12.3M
FUEL:

| Operation in pure WASM (`substrate-bn`) | FUEL |
|---|---|
| G1 addition | 0.08M |
| G1 scalar multiplication, 21-bit scalar | 1.3M |
| G1 scalar multiplication, full 254-bit scalar | 16.3M |
| G2 subgroup check (needed for every untrusted G2 point) | 57M |
| One Miller loop | 68M |
| Final exponentiation | ≈ 91M |
| Groth16, best case (trusted key, 2 public inputs, `e(α,β)` precomputed) | ≈ 342M |

Everything but G1 addition is over the cap on its own, so no amount of
optimisation inside a contract makes Groth16 fit one message. Natively the same
verification takes about 1–2 ms.

## Import module `avm_crypto`

All pointers are offsets in the calling contract's linear memory. All values
are big-endian, in exactly the byte layout of Ethereum's precompiles, so keys
and proofs exported by snarkjs, gnark, circom and arkworks work unchanged.

```text
bn254_g1_add(input_ptr: i32, output_ptr: i32) -> i32
    input:  128 bytes  = P (64) | Q (64)
    output: 64 bytes   = P + Q

bn254_g1_mul(input_ptr: i32, output_ptr: i32) -> i32
    input:  96 bytes   = P (64) | s (32)
    output: 64 bytes   = s · P

bn254_pairing_check(input_ptr: i32, input_len: i32, output_ptr: i32) -> i32
    input:  k × 192 bytes = k × (G1 (64) | G2 (128)),  k ≥ 0
    output: 1 byte     = 1 if ∏ e(G1_i, G2_i) = 1, else 0  (k = 0 → 1)
```

Encodings:
- field element: 32 bytes, must be `< p` (the BN254 base-field modulus);
- G1: `x | y`; `0…0` (64 zero bytes) is the point at infinity;
- G2: `x.c1 | x.c0 | y.c1 | y.c0` (imaginary part first, as in EIP-197);
  `0…0` (128 zero bytes) is infinity;
- scalar: any 256-bit value; it is reduced mod r.

Return value: `0` success; otherwise the output is left unchanged and the code
says why:

| Code | Meaning |
|---|---|
| 1 | a coordinate is not `< p` |
| 2 | a G1 point is not on the curve |
| 3 | a G2 point is not on the twist, or not in the order-r subgroup |
| 4 | `input_len` is not a multiple of 192 |
| 5 | a pointer range is outside linear memory |

These match the EIP-196/197 failure conditions exactly; an EVM treats all of
them as a failed call, AVM can return the code.

## FUEL price

Charge a fixed price per call, like EIP-1108 does in gas:

| Function | EIP-1108 gas | Suggested FUEL |
|---|---|---|
| `bn254_g1_add` | 150 | `150 × K` |
| `bn254_g1_mul` | 6,000 | `6,000 × K` |
| `bn254_pairing_check` | 45,000 + 34,000 · k | `(45,000 + 34,000 · k) × K` |

`K` maps gas to FUEL and is the runtime's choice. With `K = 10`, a full
Groth16 verification with 2 public inputs (2 multiplications, 2 additions, one
4-pair check) costs about 1.93M FUEL: well inside one message, and still
priced by the work done. Charging up front, before the host function runs,
keeps the meter deterministic.

## Reference implementations

- [`substrate-bn`](https://crates.io/crates/substrate-bn) (MIT/Apache-2.0):
  the library behind several EVMs' alt_bn128 precompiles. `hus-zk`'s pure-WASM
  backend (`src/soft.rs`) is exactly the host-side logic needed: about 60 lines.
- [`ark-bn254`](https://crates.io/crates/ark-bn254): an independent
  implementation; `hus-zk`'s tests cross-check every operation against it.

## Test vectors

`cargo test` in `examples/hus-zk` runs:
- random G1 additions and multiplications against arkworks;
- infinity handling, off-curve points, out-of-range coordinates, a G2 point
  outside the subgroup, wrong input length;
- pairing bilinearity, and its failure with a wrong scalar;
- a real HUS Groth16 proof (129 public inputs) and two tampered versions.

A host implementation should also pass Ethereum's precompile vectors
(`bn256Add`, `bn256ScalarMul`, `bn256Pairing` in go-ethereum's
`core/vm/testdata/precompiles`).

## What it costs a contract with the host functions

Groth16 with `n` public inputs: `n` multiplications, `n` additions and one
4-pair check, i.e. `(45,000 + 4 × 34,000 + n × 6,150) × K` FUEL. HUS's
current circuit (129 inputs) would be about 9.7M FUEL at `K = 10`; the 2-input
version planned for AVM about 1.9M.
