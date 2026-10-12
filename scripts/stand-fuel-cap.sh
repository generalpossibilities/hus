#!/bin/bash
# Bisect the per-message FUEL cap with bn254-ops: one G1 multiplication by an
# all-ones b-bit scalar costs a known, nearly linear amount of FUEL (metered
# with Wasmtime, ~94.5k per bit). Prints the longest scalar that passes.
# Run after stand-bn254.sh (reuses its deployed contract).
set -u
export AVM_SDK_HOME="${AVM_SDK_HOME:-$HOME/.local/share/avm-sdk}"
P="$AVM_SDK_HOME/current/profiles/wasmtime-release-profile.v1"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; R="$ROOT/run/bn254"; S="--state $R/s --wasmtime-profile $P"
ADDR=$(avm-local-stand inspect $S | jq -r '.accounts[0].address')
G=$(printf "%064x%064x" 1 2); T=1800100000
passes() { T=$((T + 10))
  local s; s=$(python3 -c "print('%064x' % ((1 << $1) - 1))")
  avm-local-stand call $S --address "$ADDR" --method bn254.call --args-json "\"0x01$G$s\"" --identity user --value-main 0 \
    --extra-currencies '' --block-time $T --created-at $((T - 1)) --expire-at $((T + 3600)) --fuel-fee-shells 100000 2>/dev/null \
    | jq -e '.raw_executor_output' > /dev/null
}
lo=${1:-64}; hi=${2:-128}
passes $lo || { echo "$lo bits already fails"; exit 1; }
passes $hi && { echo "$hi bits passes"; exit 1; }
while [ $((hi - lo)) -gt 1 ]; do mid=$(( (lo + hi) / 2 )); if passes $mid; then lo=$mid; else hi=$mid; fi; done
echo "longest passing all-ones scalar: $lo bits (fails at $hi)"
