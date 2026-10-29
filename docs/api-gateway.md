# HUS REST Gateway

A language-agnostic HTTP gateway for HUS. Any application calls these endpoints over HTTP — no SDK binding needed.

## Quick Start

```bash
cargo run -p hus-gateway -- \
  --network https://shellnet.ackinacki.org/graphql \
  --registry <HusRegistry-address> \
  --public-key <protocol-wallet-public-hex> \
  --secret-key <protocol-wallet-secret-hex>
```

The gateway fetches VK/PK from the registry on startup.

## Endpoints

### GET /api/v1/status

```bash
curl http://localhost:3000/api/v1/status
```

```json
{
  "version": "0.1.0",
  "network": "https://shellnet.ackinacki.org/graphql",
  "registry": "0x..."
}
```

### POST /api/v1/project — BioHashing projection

```bash
curl -X POST http://localhost:3000/api/v1/project \
  -H 'Content-Type: application/json' \
  -d '{
    "seed": "abababababababababababababababababababababababababababababababab",
    "embedding": [0.1, 0.2, 0.3]
  }'
```

```json
{
  "v_obf": [0.05, -0.12, 0.33, ...]
}
```

Projection dimension is 128 (hardcoded).

### POST /api/v1/prove — Generate ZK proof

```bash
curl -X POST http://localhost:3000/api/v1/prove \
  -H 'Content-Type: application/json' \
  -d '{
    "v_obf": [0.05, -0.12, 0.33]
  }'
```

```json
{
  "proof": "base64-encoded-proof-bytes",
  "commitment": "hex-32-byte-commitment"
}
```

### POST /api/v1/verify — Verify proof off-chain

```bash
curl -X POST http://localhost:3000/api/v1/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "proof": "base64-encoded-proof",
    "commitment": "hex-32-bytes",
    "v_obf": [0.05, -0.12, 0.33]
  }'
```

```json
{
  "valid": true
}
```

**This is the critical verification step.** On-chain Groth16 verification via `gosh.vergrth16` is blocked on Shellnet — proofs must be verified off-chain before submission.

### POST /api/v1/register-app — Deploy HusApp

```bash
curl -X POST http://localhost:3000/api/v1/register-app \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "my-app",
    "modality_ids": [0, 4, 6]
  }'
```

```json
{
  "message_hash": "deadbeef...",
  "app_address": "dapp_id::account_id",
  "app_id": "a1b2c3d4...",
  "seed_hash": "e5f6g7h8..."
}
```

`modality_ids` are the selected biometric modalities (e.g., 0=Face, 4=Keystroke, 6=Gait). The contract uses hardcoded `PROJ_DIM=128` and `MIN_SCORE=80`.

### POST /api/v1/submit — Verify the proof, then register

The gateway checks the Groth16 proof off-chain against the commitment and
all 128 `v_obf` values (the circuit's public inputs). Only if it verifies
does the gateway sign `submitVerified` on the app contract with its own key.
Callers never send keys.

Set-up, once per app: the app operator names the gateway's public key as
the app's verifier (`HusApp.setVerifier`, signed by the operator key that
registered the app). The contract refuses registrations from any other key.

```bash
curl -X POST http://localhost:3000/api/v1/submit \
  -H 'Content-Type: application/json' \
  -d '{
    "app_address": "dapp_id::account_id",
    "commitment": "hex-32-bytes",
    "v_obf": [123456, -789012, ...],
    "proof": "hex",
    "modality_id": 0
  }'
```

```json
{
  "message_hash": null,
  "is_unique": true
}
```

`v_obf` is the canonical encoding, `hus_sdk::v_obf_to_contract`: each value
×10⁶ as an integer, padded to 128.

**Why not verify on chain?** On TVM, `gosh.vergrth16` accepts only the
network's built-in (ZkLogin) verifying keys, not HUS's. The proof is stored
with the registration so anyone can re-check it against the stored vector.
On-chain verification is the AVM verifier (`avm/groth16-avm`), for networks
that can run it. The old `submit-with-proof` route, and the contract's
`submitWithProof` and proofless `submitCommitment`, are removed.

### POST /api/v1/check — Check duplicate commitment

```bash
curl -X POST http://localhost:3000/api/v1/check \
  -H 'Content-Type: application/json' \
  -d '{
    "app_address": "dapp_id::account_id",
    "commitment_hash": "hex-32-bytes"
  }'
```

```json
{
  "duplicate": false
}
```

### POST /api/v1/app-info — Get HusApp info

```bash
curl -X POST http://localhost:3000/api/v1/app-info \
  -H 'Content-Type: application/json' \
  -d '{
    "app_address": "dapp_id::account_id"
  }'
```

```json
{
  "vk": "0x...",
  "app_version": 1,
  "seed_hash": "0x...",
  "registration_count": 0
}
```

### POST /api/v1/deposit — Fund a HusApp

```bash
curl -X POST http://localhost:3000/api/v1/deposit \
  -H 'Content-Type: application/json' \
  -d '{
    "app_address": "dapp_id::account_id",
    "payment_id": "pay-123",
    "signer": { "public_key": "0x...", "secret_key": "0x..." }
  }'
```

## Integration Examples

### Python

```python
import requests
HUS = "http://localhost:3000"

# Register app with modalities
r = requests.post(f"{HUS}/api/v1/register-app", json={
    "name": "my-app",
    "modality_ids": [0, 4, 6]
})
data = r.json()
app_addr = data["app_address"]
```

### JavaScript

```javascript
const HUS = "http://localhost:3000";

// Project + Prove
const { v_obf } = await (await fetch(`${HUS}/api/v1/project`, {
  method: "POST",
  body: JSON.stringify({ seed, embedding }),
  headers: { "Content-Type": "application/json" },
})).json();

const { proof, commitment } = await (await fetch(`${HUS}/api/v1/prove`, {
  method: "POST",
  body: JSON.stringify({ v_obf }),
  headers: { "Content-Type": "application/json" },
})).json();
```

## Two-Tier Architecture

| Step | Where | What | Latency |
|------|-------|------|---------|
| Capture + extract | User device | Raw biometric → embedding | ~1s |
| Project | User device or gateway | Embedding → V_obf | ~15 µs |
| **Prove** | Gateway or device | V_obf → Groth16 proof | 1–5s |
| **Verify** | Gateway (off-chain) | Check proof | ~2 ms |
| Submit | Gateway → blockchain | `submitVerified()`, signed by the gateway | ~30s |

## Notes

- **Auth**: If `--api-key` is set, all endpoints except status require `Authorization: Bearer <api-key>`
- **V_obf format**: `/api/v1/project` returns `float32[]`; `/api/v1/submit` requires `int64[]` in the canonical encoding (`v_obf_to_contract`: ×10⁶, padded to 128)
- **CORS**: Permissive (any origin, any method, any header) for browser apps
- **No `--vk-hex`**: VK and PK are fetched from the registry contract automatically
