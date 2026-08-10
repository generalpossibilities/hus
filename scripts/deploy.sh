#!/usr/bin/env bash
set -euo pipefail

# HUS Deploy Script — Shellnet (or any TVM v3 network)
# Usage:
#   ./scripts/deploy.sh <endpoint> <keys.json>
#
# Example:
#   ./scripts/deploy.sh https://shellnet.ackinacki.org/graphql /tmp/hus-testnet/wallet/wallet.keys.json

ENDPOINT="${1:?Usage: $0 <endpoint> <keys.json>}"
KEYS="${2:?Usage: $0 <endpoint> <keys.json>}"
GIVER_ADDR="0000000000000000000000000000000000000000000000000000000000000000::1111111111111111111111111111111111111111111111111111111111111111"
GIVER_ABI="onchain/abi/GiverV3.abi.json"
KEY_DIR=$(dirname "$KEYS")
BUILD_DIR="/tmp/hus-build"
CONTRACT_TVC_SRC="${BUILD_DIR}/HusRegistry.tvc"
CONTRACT_TVC="/tmp/hus-registry-deploy.tvc"
CONTRACT_ABI="${BUILD_DIR}/HusRegistry.abi.json"
HUSAPP_TVC="${BUILD_DIR}/HusApp.tvc"
HUSAPP_ABI="${BUILD_DIR}/HusApp.abi.json"

echo "=== HUS Deploy ==="
echo "Endpoint: $ENDPOINT"
echo "Keys:     $KEYS"

# 1. Compile Solidity contracts to /tmp/build-out (outside source tree)
# NOTE: sold only generates .tvc / .code files in the CWD, not --output-dir.
# So we run sold from the build directory.
echo ""
mkdir -p "$BUILD_DIR"
echo ">>> Compiling HusApp.sol..."
cp contracts/onchain/HusApp.sol "$BUILD_DIR/"
cp contracts/onchain/HusRegistry.sol "$BUILD_DIR/"
# Remove stale artifacts so compilation regenerates
rm -f "$BUILD_DIR"/HusApp.tvc "$BUILD_DIR"/HusRegistry.tvc "$BUILD_DIR"/HusApp.code "$BUILD_DIR"/HusRegistry.code
# First pass: generate .tvc, .code, .debug.json
(cd "$BUILD_DIR" && sold --tvm-version gosh HusApp.sol)
(cd "$BUILD_DIR" && sold --tvm-version gosh HusRegistry.sol)
# Second pass: generate .abi.json (sold only generates ABI when --abi-json is used)
(cd "$BUILD_DIR" && sold --tvm-version gosh HusApp.sol --abi-json 2>/dev/null)
(cd "$BUILD_DIR" && sold --tvm-version gosh HusRegistry.sol --abi-json 2>/dev/null)

# 2. Copy TVC and embed pubkey with --save so deployx computes the same account_id
echo ""
echo ">>> Preparing TVC with embedded pubkey..."
cp "$CONTRACT_TVC_SRC" "$CONTRACT_TVC"
DEPLOYED=$(tvm-cli genaddr "$CONTRACT_TVC" \
    --abi "$CONTRACT_ABI" \
    --setkey "$KEYS" \
    --save \
    | grep "Raw address" | awk '{print $3}')
ACCOUNT_ID=$(echo "$DEPLOYED" | cut -d: -f2)
DAPP_ID="$ACCOUNT_ID"
echo "Target: ${DAPP_ID}::${ACCOUNT_ID}"

# 3. Fund target via GiverV3 (creates Uninit account)
echo ""
echo ">>> Funding target address via GiverV3..."
echo "{\"dest\":\"0:${ACCOUNT_ID}\",\"value\":10000000000,\"ecc\":{\"2\":500000000000},\"flag\":16}" > /tmp/giver_fund.json
tvm-cli call \
    --abi "$GIVER_ABI" \
    "$GIVER_ADDR" \
    sendCurrencyWithFlag \
    /tmp/giver_fund.json

echo "Waiting for account creation..."
sleep 5

# 4. Extract CODE CELL from HusApp TVC (not the full StateInit)
#    abi.encodeStateInit({code: codeCell, ...}) needs the raw code cell,
#    not the full StateInit BOC which includes initial data.
echo ""
echo ">>> Extracting code cell from HusApp.tvc..."
HUSAPP_CODE=$(tvm-cli decode stateinit --tvc "$HUSAPP_TVC" 2>/dev/null | sed -n '/^{/,$ p' | jq -r '.code')
echo "Code cell length: $(echo "$HUSAPP_CODE" | wc -c) chars"

# 5. Deploy HusRegistry (passing HusApp code in constructor)
echo ""
echo ">>> Deploying HusRegistry..."
tvm-cli deployx \
    --abi "$CONTRACT_ABI" \
    --keys "$KEYS" \
    --dst-dapp-id "$DAPP_ID" \
    "$CONTRACT_TVC" \
    "{\"appCode\":\"$HUSAPP_CODE\"}"

echo "Waiting for deploy to finalize..."
sleep 5

# 7. Verify deployment via view call
echo ""
echo ">>> Verifying deployment..."
ADDR="${DAPP_ID}::${ACCOUNT_ID}"
echo '{}' > /tmp/params_empty.json
tvm-cli call --abi "$CONTRACT_ABI" \
    "$ADDR" getVersion /tmp/params_empty.json

echo ""
echo "=== Deploy complete ==="
echo "HusRegistry address: $ADDR"
echo "Admin pubkey:        0x$ADMIN_PUBKEY"
echo ""
echo "Next steps:"
echo "  1. Set VK (584-byte hex — fits CLI):"
echo "     tvm-cli call --abi $CONTRACT_ABI --sign $KEYS $ADDR setVk /tmp/vk_params.json"
echo "  2. Set PK (17MB — use Rust binary):"
echo "     cargo run --example set_pk -p hus-onchain"
echo "  3. Register an app (deploys a HusApp with modality IDs):"
echo "     tvm-cli call --abi $CONTRACT_ABI --sign $KEYS $ADDR registerApp /tmp/register_params.json"
echo "     where register_params.json = {\"appName\":\"my-app\",\"modalityIds\":[0,4]}"
echo "  4. Fund the HusApp (deposit):"
echo "     tvm-cli call --abi $HUSAPP_ABI --sign $KEYS <husapp_addr> deposit /tmp/deposit_params.json"
echo "     where deposit_params.json = {\"paymentId\":\"0x01\"}"
echo "  5. Submit via Rust E2E (off-chain proof verify + on-chain submitCommitment):"
echo "     cargo run --example verify_and_submit -p hus-onchain"
echo "  6. Upgrade a HusApp (timelocked):"
echo "     # Propose upgrade (owner only):"
echo "     tvm-cli call --abi $CONTRACT_ABI --sign $KEYS $ADDR proposeAppUpgrade /tmp/upgrade_params.json"
echo "     # where upgrade_params.json = {\"appId\":\"0x<id>\",\"newCode\":\"<base64>\",\"newVk\":\"0x<hex>\"}"
echo "     # Cancel pending upgrade (owner only):"
echo "     tvm-cli call --abi $CONTRACT_ABI --sign $KEYS $ADDR cancelAppUpgrade /tmp/cancel_params.json"
echo "     # Execute upgrade after 7-day delay (anyone):"
echo "     tvm-cli call --abi $CONTRACT_ABI --sign $KEYS $ADDR executeAppUpgrade /tmp/execute_params.json"
echo "  7. Run on-chain integration tests:"
echo "     cargo test -p hus-onchain --test integration_test -- --ignored --nocapture"
