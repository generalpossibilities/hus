# AVM team answers to our issues (October 2026)

We filed five issues on [gosh-sh/avm-sdk](https://github.com/gosh-sh/avm-sdk)
while building `hus-registry`, and commented on a sixth (#1). The AVM team
(Futurizt) answered all of them on **15 October 2026, 23:20 UTC**.

Their answers describe a **candidate** that is built, tested and reviewed but
**not published**: draft [PR #17](https://github.com/gosh-sh/avm-sdk/pull/17),
SDK `3531573`, runtime `b3488b4`. The newest release is still
`avm-dev-06e96ef71006` (SDK 0.2.0, 14 October). Every number below is a
**local-stand value**: the team says mainnet values are not set yet. All six
issues are still open.

| Issue | Answer | What it means for HUS |
|---|---|---|
| [#18](https://github.com/gosh-sh/avm-sdk/issues/18) BN254 host functions | Not in the candidate. They would need a formal runtime/ABI proposal covering encodings, field and subgroup checks, infinity and malformed-input handling, deterministic implementation and FUEL prices, with a security review and cross-executor tests. | **On-chain Groth16 stays blocked.** Proof checking stays off-chain, or waits for a protocol proposal. |
| [#19](https://github.com/gosh-sh/avm-sdk/issues/19) FUEL cap | 10,000,000 FUEL per message, 100,000,000 per bucket, 1,000,000 FUEL per SHELL. Paying more cannot exceed the message cap. Status 31 is `VM_WASM_OUT_OF_FUEL`, and failures now show `fuel_used`, `fuel_budget` and the cap. | Confirms our measurement (finding 1 in the README). |
| [#20](https://github.com/gosh-sh/avm-sdk/issues/20) Size limits | The 64 KiB `FullReplace` threshold applies to the **previous whole account image**, header and balances included; it is not a state cap. Init must use `FullReplace`. State data is capped at **1 MiB** in both modes, and input/output envelopes at 1 MiB too. A patch is limited to 262,144 bytes and 512 ranges. A message body (the whole deploy envelope) is limited to 65,536 bytes. Status 43 is `VM_ABI_OUTPUT_MISSING`, not oversized output; oversized output is status 45. | A shard can grow to about **1 MiB**, roughly 6,000–7,000 compact records (146 B each) after overhead, if every update past 64 KiB is a patch. Our status-43 reading in finding 3 was the missing-output case: past 64 KiB the runtime wanted a patch. |
| [#21](https://github.com/gosh-sh/avm-sdk/issues/21) Storage rent | Local stand: **1 SHELL per charged byte-second**, collected before WASM execution, together with any prior debt. The **third unpaid attempt freezes** the account. Paying in full clears the debt; unfreezing also needs normal transaction costs. **No 30-day grace period** is specified, and the mainnet price is not set. An untouched account runs no rent collection until its next transaction. `inspect --account` shows `storage_last_paid`, `storage_due_payment` and `storage_unpaid_tx_count`. Guest code has no way to read its own rent debt. | **Storage is not free on AVM**, at least on the stand. Every shard needs a SHELL reserve, or it freezes after three unpaid touches. We need the mainnet price before we can work out what HUS will cost. |
| [#22](https://github.com/gosh-sh/avm-sdk/issues/22) Address depends on init data | Account id = `blake3("AVM_ACCOUNT_ID" ‖ u16 ui_len ‖ ui ‖ package_id ‖ owner_id ‖ u16 salt_len ‖ salt ‖ blake3(init_data))`; full address = `dapp_id ‖ account_id`. There is no init-independent (CREATE2-style) mode. `deploy --quote-address` computes an address in advance. They suggest a shared factory or deployment id, or an authenticated linking step after deploy; the authorization and race rules belong to the application. | **Confirms our design:** shards are deployed first, then linked by a one-time signed "set peers" step. |
| [#1](https://github.com/gosh-sh/avm-sdk/issues/1) Reading constructor data | The candidate adds `MessageInput::deploy()` with `init_data()`, `salt()`, `ui_name()`, `owner_id()` and `package_id()`, borrowed from the raw body. Envelope framing is parsed in the guest; canonical validation stays in the host. | When it is released, `hus-registry` drops its hand-written `deploy_init_data` parser (finding 4), which caused our offset bug. |

## Effect on the sharded registry plan

- **Fixed shard count, linked after deploy:** confirmed by #22.
- **Shard size:** plan for up to about 1 MiB per shard with patch output,
  rather than the 292 KB we tested.
- **Rent reserve:** each shard needs funding and a refill process. A shard
  that freezes stops accepting registrations, and duplicate checks that
  depend on it stop too.
- **Proof checks:** no BN254 host functions, so Groth16 verification stays
  off-chain or waits for a protocol proposal (`examples/hus-zk/HOST-FUNCTIONS.md`).

## Still open

- Mainnet values for the FUEL cap, the size limits and the rent price.
- Release of PR #17, after which `hus-registry` moves to `input.deploy()`
  and is re-tested on the stand.
