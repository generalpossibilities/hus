#!/bin/bash
# End-to-end test of hus-registry on avm-local-stand. Run from the repo root
# after: avm-contract-build build --manifest-path examples/hus-registry/Cargo.toml
set -u
export AVM_SDK_HOME="${AVM_SDK_HOME:-$HOME/.local/share/avm-sdk}"
PROFILE="$AVM_SDK_HOME/current/profiles/wasmtime-release-profile.v1"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
A="$ROOT/examples/hus-registry/target/avm"
GEN="$ROOT/examples/hus-registry/target/release/examples/gen"
RUN="$ROOT/run"; mkdir -p "$RUN"; cd "$RUN"
STATE="$RUN/registry.state"; rm -rf "$STATE"
S="--state $STATE --wasmtime-profile $PROFILE"
DAPP=1111111111111111111111111111111111111111111111111111111111111111
FAIL=0
avm-local-stand init $S --dapp-id $DAPP > init.json || { echo "init failed"; exit 1; }
CFG=$($GEN config)
D=(--wasm "$A/contract.wasm" --acab "$A/contract.acab" --descriptor "$A/contract.descriptor" --salt-hex 6170702d64656d6f
   --init-json "\"0x$CFG\"" --block-time 1800000000 --created-at 1800000000 --expire-at 1800003600 --fuel-fee-shells 100000)
avm-local-stand deploy $S "${D[@]}" > need.json
ADDR=$(jq -r '.address // empty' need.json); [ -n "$ADDR" ] || { echo "no address"; cat need.json; exit 1; }
avm-local-stand fund-user $S --address "$ADDR" --shells 1000000000 > fund.json
avm-local-stand deploy $S "${D[@]}" > deploy.json || { echo "deploy failed"; cat deploy.json; exit 1; }
echo "deployed $ADDR"
T=1800000010
register() { # label expect-status args-hex
  T=$((T + 10))
  avm-local-stand call $S --address "$ADDR" --method hus.register --args-json "\"0x$3\"" --identity user \
    --value-main 0 --extra-currencies '' --block-time $T --created-at $((T - 1)) --expire-at $((T + 3600)) \
    --fuel-fee-shells 100000 > "call-$1.json" 2> "call-$1.err"
  # raw_executor_output = "ACMO" | status u32 LE | ...
  local raw; raw=$(jq -r '.raw_executor_output // empty' "call-$1.json" 2>/dev/null)
  local got="?"; [ ${#raw} -ge 16 ] && got=$(( 16#${raw:14:2}${raw:12:2}${raw:10:2}${raw:8:2} ))
  local fuel; fuel=$(jq -r '.receipt.charged_shells // "?"' "call-$1.json" 2>/dev/null)
  local ok=PASS; [ "$got" = "$2" ] || { ok=FAIL; FAIL=1; }
  printf "%-28s expect %-5s got %-5s shells %-10s %s\n" "$1" "$2" "$got" "$fuel" "$ok"
}
register "person 1"              0    "$($GEN person 1)"
register "person 1 rescan"       3003 "$($GEN person 1 0.1 1001)"
register "person 1 replay"       3004 "$($GEN person 2 0 1)"
register "person 2"              0    "$($GEN person 2)"
register "person 2 rescan"       3003 "$($GEN person 2 0.1 1002)"
exit $FAIL
