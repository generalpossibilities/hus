#!/bin/bash
# Deploy hus-registry once on a fresh stand and print the result (diagnostics).
export AVM_SDK_HOME="${AVM_SDK_HOME:-$HOME/.local/share/avm-sdk}"
P="$AVM_SDK_HOME/current/profiles/wasmtime-release-profile.v1"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; A="$ROOT/examples/hus-registry/target/avm"
R="$ROOT/run/d"; rm -rf "$R"; mkdir -p "$R"; S="--state $R/s --wasmtime-profile $P"
CFG=$("$ROOT/examples/hus-registry/target/release/examples/gen" config)
D=(--wasm "$A/contract.wasm" --acab "$A/contract.acab" --descriptor "$A/contract.descriptor" --salt-hex 6170
   --init-json "${INIT_JSON:-\"0x$CFG\"}" --block-time 1800000000 --created-at 1800000000 --expire-at 1800003600 --fuel-fee-shells 100000)
avm-local-stand init $S --dapp-id 1111111111111111111111111111111111111111111111111111111111111111 > "$R/init.json"
ADDR=$(avm-local-stand deploy $S "${D[@]}" | jq -r .address)
avm-local-stand fund-user $S --address "$ADDR" --shells 1000000000 > "$R/fund.json"
avm-local-stand deploy $S "${D[@]}" | jq -c '{status, error, address}'
