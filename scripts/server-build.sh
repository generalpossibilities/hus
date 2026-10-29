#!/usr/bin/env bash
# Run cargo for HUS on the build server instead of this laptop.
#
#   scripts/server-build.sh test -p hus-sdk --lib
#   scripts/server-build.sh build -p hus-gateway
#
# Copies the source (not keep/, which holds keys, and not build output) to
# ${HOST}:${REMOTE}/src, then runs cargo there in a Rust container capped at
# 2 CPUs and 6 GB with a low CPU weight, so the mining workers on the same
# machine keep priority. The cargo registry and target dir persist on the
# server between runs.
set -euo pipefail

HOST="${HUS_BUILD_HOST:-njd-node2}"
REMOTE="${HUS_BUILD_DIR:-/opt/njd-build/hus}"
IMAGE="${HUS_BUILD_IMAGE:-rust:1.95-bookworm}"

cd "$(dirname "$0")/.."
[[ $# -gt 0 ]] || { echo "usage: $0 <cargo args>" >&2; exit 2; }

ssh "$HOST" "mkdir -p ${REMOTE}/src ${REMOTE}/target ${REMOTE}/cargo"
rsync -a --delete \
  --exclude /target --exclude '/verifier/target' --exclude '/keep/*' \
  --exclude '/.git' --exclude 'node_modules' \
  ./ "${HOST}:${REMOTE}/src/"

args=$(printf '%q ' "$@")
ssh "$HOST" "docker run --rm --cpus=2 --memory=6g --cpu-shares=128 \
  -v ${REMOTE}/src:/src -v ${REMOTE}/target:/target -v ${REMOTE}/cargo:/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR=/target -w /src ${IMAGE} cargo ${args}"
