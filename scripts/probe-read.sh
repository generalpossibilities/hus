#!/bin/bash
P="$HOME/.local/share/avm-sdk/current/profiles/wasmtime-release-profile.v1"; cd "$(dirname "$0")/.."
ADDR=$(jq -r '.accounts[0].address' <(avm-local-stand inspect --state run/d/s --wasmtime-profile $P))
out=""; T=1800000100
for i in $(seq 0 ${1:-24}); do T=$((T+10))
  st=$(avm-local-stand call --state run/d/s --wasmtime-profile $P --address $ADDR --method hus.register --args-json "\"0x$(printf %02x $i)\"" --identity user --value-main 0 --extra-currencies '' --block-time $T --created-at $((T-1)) --expire-at $((T+3600)) --fuel-fee-shells 100000 | jq -r '[.. | objects | .status_code? // empty] | first')
  out="$out$(printf %02x $(( (st - 10000) % 256 )))"
done; echo "$out"
