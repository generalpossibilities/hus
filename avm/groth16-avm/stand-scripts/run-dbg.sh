#!/bin/bash
# Deploy the HUS Groth16 contract in the AVM local stand and call it.
set -u
export PATH=$HOME/.local/bin:$HOME/.cargo/bin:$PATH
export AVM_SDK_HOME="$HOME/.local/share/avm-sdk"
W=/home/ubuntu/hus-avm-test; cd $W
export AVM_STATE="$W/hus.state"
export AVM_PROFILE="$AVM_SDK_HOME/current/profiles/wasmtime-release-profile.v1"
DAPP=1111111111111111111111111111111111111111111111111111111111111111
A=/home/ubuntu/avm-sdk/examples/hus-g16-dbg/target/avm
rm -rf "$AVM_STATE"
S="--state $AVM_STATE --wasmtime-profile $AVM_PROFILE"
avm-local-stand init $S --dapp-id $DAPP > init.json || { echo "init failed"; cat init.json; exit 1; }
echo "== init config:"; jq -c '.' init.json | cut -c1-600
D="--wasm $A/contract.wasm --acab $A/contract.acab --descriptor $A/contract.descriptor --salt-hex 6875732d677231 --init-json null --block-time 1800000000 --created-at 1800000000 --expire-at 1800003600 --fuel-fee-shells 1000"
avm-local-stand deploy $S $D > need.json; echo "first deploy exit $? : $(jq -c . need.json | cut -c1-200)"
ADDR=$(jq -r ".address // empty" need.json); [ -n "$ADDR" ] || { echo "no address: stop"; exit 1; }
avm-local-stand fund-user $S --address "$ADDR" --shells 1000000000000 > fund.json; echo "fund exit $?"
avm-local-stand deploy $S $D > deploy.json; echo "deploy exit $? : $(jq -c . deploy.json | cut -c1-400)"
call() { # $1 label, $2 args-json, $3 fuel reserve
  avm-local-stand call $S --address "$ADDR" --method hus.verify --args-json "$2" --identity user --value-main 0 --extra-currencies '' \
    --block-time $4 --created-at $(( $4 - 1 )) --expire-at $(( $4 + 3600 )) --fuel-fee-shells $3 > "call-$1.json" 2> "call-$1.err"
  echo "== $1: exit $? | state $(jq -r .raw_state call-$1.json) | status $(jq -r .raw_executor_output call-$1.json | cut -c1-24) | stderr: $(head -c 400 call-$1.err)"
}
GOOD=$(xxd -p -c 100000 good_raw.bin); BAD=$(xxd -p -c 100000 bad_raw.bin)
for ST in 18 19; do
  call stage$ST "\"0x$GOOD$ST\"" 1000000000 $(( 1800000200 + 16#$ST ))
  avm-local-stand fund-user $S --address "$ADDR" --shells 1000000000000 >/dev/null 2>&1
  echo "   stage $ST -> state $(jq -r '.raw_state // empty' call-stage$ST.json)  error: $(jq -r '.error // "none"' call-stage$ST.json)"
done
