#!/bin/bash
# Load test: register N distinct people into one registry, then check rescans.
# Usage: scripts/stand-load.sh N [reserve_shells]   (after stand-e2e.sh built everything)
set -u
N=${1:-200}; RES=${2:-100000}
export AVM_SDK_HOME="${AVM_SDK_HOME:-$HOME/.local/share/avm-sdk}"
PROFILE="$AVM_SDK_HOME/current/profiles/wasmtime-release-profile.v1"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; A="$ROOT/examples/hus-registry/target/avm"
GEN="$ROOT/examples/hus-registry/target/release/examples/gen"
RUN="$ROOT/run/load"; rm -rf "$RUN"; mkdir -p "$RUN"; cd "$RUN"
S="--state $RUN/s --wasmtime-profile $PROFILE"
avm-local-stand init $S --dapp-id 1111111111111111111111111111111111111111111111111111111111111111 > init.json
D=(--wasm "$A/contract.wasm" --acab "$A/contract.acab" --descriptor "$A/contract.descriptor" --salt-hex 6c6f6164
   --init-json "\"0x$($GEN config)\"" --block-time 1800000000 --created-at 1800000000 --expire-at 1800003600 --fuel-fee-shells 100000)
ADDR=$(avm-local-stand deploy $S "${D[@]}" 2>/dev/null | jq -r .address)  # funding_required
avm-local-stand fund-user $S --address "$ADDR" --shells 1000000000 > /dev/null
avm-local-stand deploy $S "${D[@]}" > deploy.json
T=1800000010
call() { T=$((T + 10))
  local r; r=$(avm-local-stand call $S --address "$ADDR" --method hus.register --args-json "\"0x$1\"" --identity user \
    --value-main 0 --extra-currencies '' --block-time $T --created-at $((T - 1)) --expire-at $((T + 3600)) --fuel-fee-shells $RES)
  local raw; raw=$(jq -r '.raw_executor_output // empty' <<<"$r")
  if [ ${#raw} -ge 16 ]; then echo $(( 16#${raw:14:2}${raw:12:2}${raw:10:2}${raw:8:2} )) "$(jq -r '.receipt.charged_shells' <<<"$r")"
  else echo "ERR $(jq -c '{status,error}' <<<"$r" | cut -c1-200)"; fi
}
t0=$(date +%s); fails=0
for i in $(seq 1 $N); do
  out=$(call "$($GEN person $i)")
  case "$out" in 0\ *) ;; *) fails=$((fails+1)); echo "person $i: $out";; esac
  if [ $((i % 100)) -eq 0 ]; then echo "registered $i ($(( $(date +%s) - t0 )) s), last: $out"; fi
done
echo "== rescans of 20 registered people (expect 3003)"
caught=0; for j in $(seq 1 20); do p=$(( (j * 37) % N + 1 )); out=$(call "$($GEN person $p 0.1 $((900000 + j)))"); [ "${out%% *}" = 3003 ] && caught=$((caught+1)); done
echo "caught $caught/20; registration failures: $fails"
