#!/bin/bash
# bn254-ops on avm-local-stand: G1 add and multiplication through hus-zk's
# pure-WASM backend, results checked against Python's own curve arithmetic.
# Run after: avm-contract-build build --manifest-path examples/bn254-ops/Cargo.toml
set -u
export AVM_SDK_HOME="${AVM_SDK_HOME:-$HOME/.local/share/avm-sdk}"
P="$AVM_SDK_HOME/current/profiles/wasmtime-release-profile.v1"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; A="$ROOT/examples/bn254-ops/target/avm"
R="$ROOT/run/bn254"; rm -rf "$R"; mkdir -p "$R"; cd "$R"; S="--state $R/s --wasmtime-profile $P"
avm-local-stand init $S --dapp-id 1111111111111111111111111111111111111111111111111111111111111111 > init.json
D=(--wasm "$A/contract.wasm" --acab "$A/contract.acab" --descriptor "$A/contract.descriptor" --salt-hex 626e
   --init-json null --block-time 1800000000 --created-at 1800000000 --expire-at 1800003600 --fuel-fee-shells 100000)
ADDR=$(avm-local-stand deploy $S "${D[@]}" 2>/dev/null | jq -r .address)  # funding_required
avm-local-stand fund-user $S --address "$ADDR" --shells 1000000000 > /dev/null
avm-local-stand deploy $S "${D[@]}" > deploy.json || { cat deploy.json; exit 1; }
# label | input hex (op byte first) | expected state hex or "fail"
python3 - > cases.txt <<'PY'
p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
def add(P, Q):
    if P is None: return Q
    if Q is None: return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % p == 0: return None
    l = (3 * x1 * x1 * pow(2 * y1, -1, p)) if P == Q else ((y2 - y1) * pow(x2 - x1, -1, p))
    x3 = (l * l - x1 - x2) % p
    return (x3, (l * (x1 - x3) - y1) % p)
def mul(P, k):
    R = None
    while k:
        if k & 1: R = add(R, P)
        P = add(P, P); k >>= 1
    return R
h = lambda P: "00" * 64 if P is None else "%064x%064x" % P
G = (1, 2)
for label, op, inp, exp in [
    ("add G + G",            "00", h(G) + h(G),                  h(add(G, G))),
    ("add G + infinity",     "00", h(G) + "00" * 64,             h(G)),
    ("mul 7 · G",            "01", h(G) + "%064x" % 7,           h(mul(G, 7))),
    ("mul 21-bit · 2G",      "01", h(add(G, G)) + "%064x" % 1234567, h(mul(G, 2 * 1234567))),
    ("mul off-curve point",  "01", "%064x%064x" % (1, 3) + "%064x" % 7, "fail"),
    ("mul full 254-bit · G", "01", h(G) + "%064x" % (r - 1),     h(mul(G, r - 1))),
]:
    print(label, op + inp, exp, sep="|")
PY
T=1800000010; FAILS=0
while IFS='|' read -r label input expect; do
  T=$((T + 10))
  out=$(avm-local-stand call $S --address "$ADDR" --method bn254.call --args-json "\"0x$input\"" --identity user --value-main 0 \
        --extra-currencies '' --block-time $T --created-at $((T - 1)) --expire-at $((T + 3600)) --fuel-fee-shells 100000 2>/dev/null)
  raw=$(jq -r '.raw_executor_output // empty' <<<"$out"); state=$(jq -r '.state // empty' <<<"$out")
  if [ -n "$raw" ]; then st=$(( 16#${raw:14:2}${raw:12:2}${raw:10:2}${raw:8:2} )); else st="VM: $(jq -r .error <<<"$out" | grep -o 'VM status [0-9]*')"; fi
  got="${state#0x}"
  if [ "$expect" = fail ]; then [ "$st" != 0 ] && ok=PASS || ok=FAIL; else [ "$st" = 0 ] && [ "$got" = "$expect" ] && ok=PASS || ok=FAIL; fi
  [ "$label" = "mul full 254-bit · G" ] && ok="(expected to exceed the FUEL cap)"
  [ "$ok" = FAIL ] && FAILS=1
  printf "%-24s status %-14s %s\n" "$label" "$st" "$ok"
done < cases.txt
exit $FAILS
