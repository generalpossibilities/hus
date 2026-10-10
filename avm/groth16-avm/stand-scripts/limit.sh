#!/bin/bash
# Find the deploy body-size limit: example contract-b padded to several sizes.
set -u
export PATH=$HOME/.local/bin:$HOME/.cargo/bin:$PATH
export AVM_SDK_HOME="$HOME/.local/share/avm-sdk"
P="$AVM_SDK_HOME/current/profiles/wasmtime-release-profile.v1"
cd /home/ubuntu/avm-sdk/examples
for KB in 56 64 72 80 96; do
  D=pad-$KB; rm -rf $D; cp -R contract-b $D
  base=$(stat -c %s contract-b/target/avm/contract.wasm)
  need=$(( KB * 1024 - base )); [ $need -lt 0 ] && need=0
  head -c $need /dev/urandom > $D/src/pad.bin
  cat >> $D/src/lib.rs <<'RS'

static PAD: [u8; include_bytes!("pad.bin").len()] = *include_bytes!("pad.bin");
RS
  python3 /home/ubuntu/hus-avm-test/pad_insert.py $D/src/lib.rs
  sed -i "s/^name = .*/name = \"pad-$KB\"/" $D/Cargo.toml
  avm-contract-build build --manifest-path $D/Cargo.toml >/dev/null 2>$D.err || { echo "$KB KB: build failed: $(tail -2 $D.err)"; continue; }
  sz=$(stat -c %s $D/target/avm/contract.wasm)
  st=$(mktemp -d)/s
  avm-local-stand init --state $st --wasmtime-profile $P --dapp-id 1111111111111111111111111111111111111111111111111111111111111111 >/dev/null
  r=$(avm-local-stand deploy --state $st --wasmtime-profile $P --wasm $D/target/avm/contract.wasm --acab $D/target/avm/contract.acab --descriptor $D/target/avm/contract.descriptor --salt-hex 00 --init-json null --block-time 1800000000 --created-at 1800000000 --expire-at 1800003600 --fuel-fee-shells 1000 2>/dev/null)
  echo "$KB KB target -> wasm $sz B : $(echo "$r" | jq -r '.error // .status' | cut -c1-110)"
done
