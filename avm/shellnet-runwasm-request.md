# Shellnet operator request — enable RUNWASM (wasm execution on-node)

**From:** HUS team (RUNWASM e2e investigation, 2026-08-09)
**To:** Acki Nacki Shellnet operators
**Priority:** Medium — unblocks the final on-chain integration test for HUS

---

## TL;DR

We need two small things on the Shellnet node to run WASM (`gosh.runwasm`) from a TVM contract. Everything else (contract, ABI, deploy flow, keys) is ready on our side.

1. **Place the wasm binary file** at `config/wasm/66fddc0a71151e975d5f2105cb5ba1db191bf19e5841d09907733525b571c48e` (sha256 = name of the file; content = the `docs:adder/add@0.1.0` component, byte-identical copy in repo at `avm/wasm-smoke-harness/config/wasm/66fddc0a71151e975d5f2105cb5ba1db191bf19e5841d09907733525b571c48e`; source build: `avm/runwasm-smoke/add.wit (local build artifact add.wasm, untracked)`).
2. **Optional but recommended:** add the same sha256 to the node's `wasm_hash_whitelist` so both the hash-mode path and the `wasm_external` path are fully unblocked.

## Why

HUS registers users with a zero-knowledge proof. The current on-chain path (`gosh.vergrth16`) is blocked on Shellnet because the opcode uses hardcoded ZkLogin VKs, not custom circuit VKs. The alternative that works on the node without any opcode changes is **`gosh.runwasm`** — TVM loads a WASM component by hash, executes a function, and returns a cell. We validated this end-to-end in a local executor harness (tvm-sdk `v3.0.4.an`, same pins as acki-nacki main):

| Scenario | exit_code | meaning |
|---|---|---|
| run-hash (`wasmHash` only, empty `wasmBinary`) | 0 | hash-mode: node loads file from `config/wasm/{hash}`, runs it |
| run-inline (real `wasmBinary` + no config file) | 0 | inline mode: binary passed in the call (`wasm_external` feature) |
| run-missing (hash, no config file) | 33 | `WasmWhitelistMissingBinary` — file not found |
| run-forbidden (file present, hash not whitelisted) | 32 | `WasmWhitelistForbiddenHash` |

Wasm result proven: `add([0x01,0x02])` returns `[3]` and the contract persists it in c4.

## What we found (implementation behavior, no spec doc exists)

- VM instruction docs order: `wasmHash, wasmArgs, wasmFunction, wasmModule, wasmBinary`; sold pushes args left-to-right, so the contract must call `gosh.runwasm(abi.encode(hash), abi.encode(args), abi.encode(func), abi.encode(module), abi.encode(binary))` — same as acki-nacki's own `contracts/mvsystem/Miner.sol`.
- `wasmHash` must be encoded as `bytes` (ref-chain cell), not `bytes32` — the executor reads it via `TokenValue::read_bytes` (ABI v2.4). `abi.encode(bytes32)` → CellUnderflow (exit 9).
- **File-check happens before whitelist-check** in `engine/core.rs` `get_wasm_binary_by_hash` (~line 856): missing file → 33; file present but not whitelisted → 32. Hash-mode (`get_precompiled_wasm_binary_by_hash`) reads the file with no hash/whitelist check; `wasm_external` requires BOTH whitelist membership AND file content-hash match (`extern_check_hash`).
- A node built WITHOUT the `wasm_external` feature (acki-nacki main defaults) **cannot** run inline binaries — the caller must pass only the hash, and the file must exist locally.

## What we need from you

1. Drop the file at `config/wasm/66fddc0a71151e975d5f2105cb5ba1db191bf19e5841d09907733525b571c48e` on the Shellnet node(s).
   - File content: byte-identical to `avm/wasm-smoke-harness/config/wasm/66fddc0a71151e975d5f2105cb5ba1db191bf19e5841d09907733525b571c48e` in this repo (15,080 bytes, sha256 `66fddc0a…`; source build `avm/runwasm-smoke/add.wit (local build artifact add.wasm, untracked)`, also in-repo). If you prefer a different wasm, we can adapt — we just need *a* known binary at *its* sha256 name to test the flow.
2. (Recommended) Add `66fddc0a71151e975d5f2105cb5ba1db191bf19e5841d09907733525b571c48e` to the node's `wasm_hash_whitelist`.
3. Tell us when it's live, and whether the node was built with or without the `wasm_external` feature.

## What we'll do once it's live

- Redeploy `runWasmSmoke_pubkey` v2 (addr `0:97360b6b41553bb85dfdf5784250c1cdfa6707f22f8226de4cfb9c16942f87e1`) or a fresh copy on Shellnet.
- Call `runWasm5(hash, args, func, module, binary="")` and confirm exit 0 + persisted result `[3]` on-chain.
- Measure real SHELL gas cost per `runwasm` call for the audit.
- Then swap the `docs:adder` stub for the real HUS prover wasm and test the `[proof_bytes | commitment]` wire format.

## A wish for the roadmap

While `gosh.runwasm` is the pragmatic path for today — and we're genuinely
excited to run our prover as WASM on the node — HUS's long-term design goal
is **native Groth16 verification on-chain**: an opcode that lets a contract
verify a proof against *its own* verifying key, not only the protocol's
hardcoded ZkLogin keys. Something along the lines of the
`vergrth16WithVK(vk, public_inputs, proof)` instruction teased in the Acki
Nacki News SDK notes, or simply opening up `gosh.vergrth16` to accept a VK
parameter.

With such a primitive, the whole uniqueness check stays inside the chain —
no off-chain verifier, no WASM hop: just a proof, a commitment, and finality.
This is not a blocker for the request above; consider it a humble feature
wish from a team building privacy-preserving identity infrastructure on
Acki Nacki.

## Artifacts (already in repo)

- Contract: `avm/runwasm-smoke/runWasmSmoke_pubkey.sol` (+ `.abi.json`, `.code`, deploy tvc in same dir)
- Wasm: `avm/wasm-smoke-harness/config/wasm/66fddc0a71151e975d5f2105cb5ba1db191bf19e5841d09907733525b571c48e` (byte-identical to the node file; source build `avm/runwasm-smoke/add.wit (local build artifact add.wasm, untracked)`)
- Local harness: `avm/wasm-smoke-harness` (Rust, uses tvm-sdk v3.0.4.an via path dep) — reproduces the full matrix above offline
- Findings & matrix: `keep/audit.md` item 4
