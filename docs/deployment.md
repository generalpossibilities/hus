# HUS Deployment Guide (v2.5.0)

## Prerequisites
- `sold` (gosh-solidity compiler, v0.79.3+)
- A wallet with SHELL/VMSHELL for gas
- Groth16 proving key + verifying key (generated via `cargo run --example keygen`)
- Acki Nacki Shellnet GraphQL endpoint

## Contracts

| Contract | File | Version | Description |
|----------|------|---------|-------------|
| HusRegistry | `contracts/onchain/HusRegistry.sol` | 2.4.2 | Factory — stores VK, PK, app code, deploys HusApp |
| HusApp | `contracts/onchain/HusApp.sol` | 2.5.0 | Per-app immutable verification contract |

## Deploy Script (Recommended)

```bash
./scripts/deploy.sh https://shellnet.ackinacki.org/graphql /path/to/wallet.keys.json
```

The script:
1. Compiles `HusRegistry.sol` and `HusApp.sol` with `sold` (two-pass: first for `.tvc`, then with `--abi-json` for `.abi.json`)
2. Extracts the `HusApp` code cell (base64) for the registry's constructor
3. Funds the deployer wallet via GiverV3 (0.3 VMSHELL)
4. Deploys HusRegistry with the HusApp code template

## Manual Deployment (Alternative)

```bash
# 1. Compile Solidity (two-pass for .tvc + .abi.json)
sold --tvm-version gosh contracts/onchain/HusRegistry.sol --output-dir contracts/onchain/
sold --tvm-version gosh contracts/onchain/HusRegistry.sol --output-dir contracts/onchain/ --abi-json

sold --tvm-version gosh contracts/onchain/HusApp.sol --output-dir contracts/onchain/
sold --tvm-version gosh contracts/onchain/HusApp.sol --output-dir contracts/onchain/ --abi-json

# 2. Encode HusApp.tvc as base64 for constructor
HUS_APP_CODE=$(base64 -w0 contracts/onchain/HusApp.tvc)

# 3. Compute target address, fund, and deploy
tvm-cli deployx \
  -u "https://shellnet.ackinacki.org/graphql" \
  --abi contracts/onchain/build/HusRegistry.abi.json \
  --keys /path/to/wallet.keys.json \
  contracts/onchain/HusRegistry.tvc \
  '{"appCode":"'$HUS_APP_CODE'"}'
```

## Post-Deploy Setup

After deployment, the owner must:

```bash
# 1. Set verifying key (VK)
tvm-cli call "<registry_address>" setVk \
  '{"vk":"<hex-encoded-vk>"}' \
  --abi contracts/onchain/build/HusRegistry.abi.json \
  --sign /path/to/wallet.keys.json \
  --endpoint "https://shellnet.ackinacki.org/graphql"

# 2. Upload proving key in 32KB chunks (~544 transactions for 17MB PK)
#    Use the Rust client: cargo run --example set_pk
#    Or manually:
for i in $(seq 0 543); do
  tvm-cli call "<registry_address>" setProvingKeyChunk \
    '{"index":'$i',"chunk":"<base64-32kb-chunk>"}' \
    --abi contracts/onchain/build/HusRegistry.abi.json \
    --sign /path/to/wallet.keys.json \
    --endpoint "https://shellnet.ackinacki.org/graphql"
done

# 3. Set PK integrity hash
tvm-cli call "<registry_address>" setProvingKeyHash \
  '{"hash":"<uint256-hex>"}' \
  --abi contracts/onchain/build/HusRegistry.abi.json \
  --sign /path/to/wallet.keys.json \
  --endpoint "https://shellnet.ackinacki.org/graphql"
```

## Register an App

```bash
tvm-cli call "<registry_address>" registerApp \
  '{"appName":"my-app","modalityIds":[0,4,6]}' \
  --abi contracts/onchain/build/HusRegistry.abi.json \
  --sign /path/to/wallet.keys.json \
  --endpoint "https://shellnet.ackinacki.org/graphql"
```

Passes `modalityIds` as `uint8[]` (e.g., 0=Face, 4=Keystroke, 6=Gait). The contract uses hardcoded `PROJ_DIM=128` and `MIN_SCORE=80`.

## Deposit + Submit

```bash
# Deposit SHELL to fund HusApp's VMSHELL balance
tvm-cli call "$APP_ADDR" deposit '{"paymentId":"0x01"}' \
  --abi contracts/onchain/build/HusApp.abi.json \
  --sign /path/to/wallet.keys.json \
  --endpoint "https://shellnet.ackinacki.org/graphql"

# Submit proof-verified commitment (working path)
tvm-cli call "$APP_ADDR" submitCommitment \
  '{"commitmentHash":"<hex-32>","vObf":[<int64 values>],"modalityId":0}' \
  --abi contracts/onchain/build/HusApp.abi.json \
  --sign /path/to/wallet.keys.json \
  --endpoint "https://shellnet.ackinacki.org/graphql"

# Submit with on-chain proof (blocked on Shellnet — gosh.vergrth16 uses ZkLogin VKs)
tvm-cli call "$APP_ADDR" submitWithProof \
  '{"vObf":[<int64 values>],"proof":"<base64>","commitment":"<hex256>","modalityId":0}' \
  --abi contracts/onchain/build/HusApp.abi.json \
  --sign /path/to/wallet.keys.json \
  --endpoint "https://shellnet.ackinacki.org/graphql"
```

## Gas Estimates

| Action | Contract | VMSHELL |
|--------|----------|---------|
| Deploy HusRegistry | HusRegistry | ~0.020 |
| `registerApp` (deploys HusApp) | HusRegistry | ~0.030 |
| `deposit` | HusApp | ~0.010 |
| `submitCommitment` | HusApp | ~0.300 |
| `submitWithProof` (if unblocked) | HusApp | ~0.022 |
| `checkDuplicate` | HusApp | ~0.001 |
| `getVerificationFee()` | HusApp | 0.3 (estimate) |

Gas is deducted from the HusApp's VMSHELL balance (funded via `deposit`).

## Rust Integration

```rust
use hus_onchain::hus_registry::HusRegistry;
use hus_onchain::hus_app::HusApp;

// Register app with modality IDs
let app_address = registry.register_app("my-app", &[0u8, 4u8, 6u8]).await?;

// Interact with HusApp
let app = HusApp::new(ctx, app_address);
app.deposit("payment-1", signer.clone()).await?;

// Submit commitment (working path)
let (is_unique, score) = app.submit_commitment(
    commitment_hash,
    &v_obf,
    modality_id,
    signer.clone(),
).await?;
```
