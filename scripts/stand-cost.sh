#!/bin/bash
# What registrations cost: the charge for N consecutive registrations with a
# 1-SHELL reserve (unused reserve is burned without a callback), then the
# storage rent collected after gaps of 1 minute, 1 hour and 1 day.
# Usage: scripts/stand-cost.sh [N]
set -u
N=${1:-20}
export AVM_SDK_HOME="${AVM_SDK_HOME:-$HOME/.local/share/avm-sdk}"
P="$AVM_SDK_HOME/current/profiles/wasmtime-release-profile.v1"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; A="$ROOT/examples/hus-registry/target/avm"
GEN="$ROOT/examples/hus-registry/target/release/examples/gen"
R="$ROOT/run/cost"; rm -rf "$R"; mkdir -p "$R"; cd "$R"; S="--state $R/s --wasmtime-profile $P"
avm-local-stand init $S --dapp-id 1111111111111111111111111111111111111111111111111111111111111111 > init.json
D=(--wasm "$A/contract.wasm" --acab "$A/contract.acab" --descriptor "$A/contract.descriptor" --salt-hex 636f7374
   --init-json "\"0x$($GEN config)\"" --block-time 1800000000 --created-at 1800000000 --expire-at 1800003600 --fuel-fee-shells 100000)
ADDR=$(avm-local-stand deploy $S "${D[@]}" 2>/dev/null | jq -r .address)  # funding_required
avm-local-stand fund-user $S --address "$ADDR" --shells 1000000000 > /dev/null
avm-local-stand deploy $S "${D[@]}" > deploy.json
T=1800000010
reg() { # args-hex reserve -> prints status or VM error; charged shells
  T=$((T + 10))
  local o; o=$(avm-local-stand call $S --address "$ADDR" --method hus.register --args-json "\"0x$1\"" --identity user --value-main 0 \
    --extra-currencies '' --block-time $T --created-at $((T - 1)) --expire-at $((T + 3600)) --fuel-fee-shells $2 2>/dev/null)
  local raw; raw=$(jq -r '.raw_executor_output // empty' <<<"$o")
  [ -n "$raw" ] && echo "$(( 16#${raw:14:2}${raw:12:2}${raw:10:2}${raw:8:2} )) $(jq -r .receipt.charged_shells <<<"$o")" || echo "ERR $(jq -r .error <<<"$o" | cut -c1-100)"
}
echo "== charge per registration (reserve 1); block time +10 s per call"
for i in $(seq 1 $N); do out=$(reg "$($GEN person $i)" 1); [ $i -le 5 ] || [ $((i % 5)) -eq 0 ] && echo "registration $i: $out"; done
echo "== storage rent: the next registration after 1 day and after 7 days of block time"
SZ=$(avm-local-stand inspect $S | jq -r '.accounts[] | select(.address == "'"$ADDR"'") | .canonical_byte_length')
BAL() { avm-local-stand inspect $S | jq -c '.accounts[] | select(.address == "'"$ADDR"'") | {canonical_byte_length, storage_due_payment, storage_last_paid}'; }
echo "before: $(BAL)"
for gap in 60 3600 86400; do
  T=$((T + gap)); o=$(avm-local-stand call $S --address "$ADDR" --method hus.register --args-json "\"0x$($GEN person $((60000 + gap)))\"" --identity user --value-main 0 \
    --extra-currencies '' --block-time $T --created-at $((T - 1)) --expire-at $((T + 3600)) --fuel-fee-shells 1 2>/dev/null)
  echo "after +$gap s: $(jq -c '{status, error, charged: .receipt.charged_shells}' <<<"$o") account: $(BAL)"
done
exit 0
