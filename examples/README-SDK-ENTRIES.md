# Entries for the AVM SDK's `examples/README.md`

Ready to paste under "Example Set" when these examples are copied into
`gosh-sh/avm-sdk`.

### `hus-registry`

A message-isolated, data-heavy application contract: a per-app uniqueness
registry (one person, one registration) for HUS. It:

- reads its config from the deploy init data inside the canonical deploy
  payload (`ACDP`);
- accepts an external `hus.register` call carrying a commitment, an
  obfuscated vector and a proof;
- rejects a replayed commitment (3004) and any vector within the duplicate
  threshold of a stored one (3003), using LSH buckets so each check compares
  with about 25 stored vectors instead of all of them;
- stores compact 146-byte records and grows past 64 KiB of state by
  returning `DataPatchList` whenever the runtime asks for it (a full shard of
  2,000 records is 292 KB);
- optionally verifies a Groth16 proof through `hus-zk` (`native-groth16`
  feature, which imports the proposed BN254 host functions).

Use it to exercise large state, patch-based state updates, init data and
contract-defined error codes. `scripts/stand-e2e.sh` and
`scripts/stand-load.sh 2000` run it on the stand.

### `hus-zk` (library)

BN254 `g1_add`, `g1_mul` and `pairing_check` in exactly the EIP-196/197 byte
encoding, plus Groth16 verification. It has a pure-WASM backend and a native
backend over the three proposed `avm_crypto` host functions, specified in
`hus-zk/HOST-FUNCTIONS.md`. `cargo test` cross-checks every operation against
arkworks, and checks a real HUS proof and tampered ones.

### `bn254-ops`

A message-isolated contract that runs `hus-zk`'s G1 operations on the stand
(`bn254.call`). It shows where the per-message FUEL cap (about 10M) falls: an
addition and short-scalar multiplications fit, a full-width multiplication
fails with VM status 31. With `--features native`, it also calls the
pairing check.
