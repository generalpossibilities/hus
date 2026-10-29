#!/usr/bin/env bash
# Build libhus_sdk.so (with the face model runtime) for Android on the build
# server, and fetch it to target/android-libs/<abi>/libhus_sdk.so.
#
#   scripts/build-android.sh
#
# Like server-build.sh: copies the source (never keep/) to the server and
# builds in a container capped at 2 CPUs and 6 GB with a low CPU weight. The
# container is rust + cargo-ndk, using the Android NDK from the server's
# `njd-android-sdk` volume (mounted read-only).
#
# Apps load it with dart:ffi / System.loadLibrary("hus_sdk"); the C API is in
# sdk/src/ffi.rs (hus_face_session_*, hus_typing_session_*, hus_prover_key_*).
set -euo pipefail

HOST="${HUS_BUILD_HOST:-njd-node2}"
REMOTE="${HUS_BUILD_DIR:-/opt/njd-build/hus}"
IMAGE=hus-android-build:1.95
NDK_VOLUME="${HUS_NDK_VOLUME:-njd-android-sdk}"
NDK_VERSION="${HUS_NDK_VERSION:-27.0.12077973}"
ABIS=(arm64-v8a armeabi-v7a x86_64)

cd "$(dirname "$0")/.."
out=target/android-libs
mkdir -p "$out"

ssh "$HOST" "mkdir -p ${REMOTE}/src ${REMOTE}/target ${REMOTE}/cargo ${REMOTE}/android-out"
rsync -a --delete \
  --exclude /target --exclude '/verifier/target' --exclude '/keep/*' \
  --exclude '/.git' --exclude 'node_modules' \
  ./ "${HOST}:${REMOTE}/src/"

abi_args=""
for a in "${ABIS[@]}"; do abi_args+=" -t $a"; done

ssh "$HOST" bash -s <<REMOTE_SCRIPT
set -euo pipefail
if ! docker image inspect ${IMAGE} >/dev/null 2>&1; then
  docker build -q -t ${IMAGE} - <<'DOCKERFILE'
FROM rust:1.95-bookworm
RUN rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android \
 && cargo install cargo-ndk --version 3.5.4 --locked
DOCKERFILE
fi
rm -rf ${REMOTE}/android-out/*
docker run --rm --cpus=2 --memory=6g --cpu-shares=128 \
  -v ${REMOTE}/src:/src -v ${REMOTE}/target:/target -v ${REMOTE}/cargo:/usr/local/cargo/registry \
  -v ${NDK_VOLUME}:/android-sdk:ro -v ${REMOTE}/android-out:/out \
  -e CARGO_TARGET_DIR=/target -e ANDROID_NDK_HOME=/android-sdk/ndk/${NDK_VERSION} \
  -e CARGO_PROFILE_RELEASE_STRIP=true -e CARGO_PROFILE_RELEASE_LTO=thin \
  -w /src ${IMAGE} \
  bash -c 'rustup show active-toolchain >/dev/null && rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android >/dev/null 2>&1; \
           cargo ndk --platform 24 ${abi_args} -o /out build --release -p hus-sdk --features ml --lib'
REMOTE_SCRIPT

rsync -a "${HOST}:${REMOTE}/android-out/" "$out/"
find "$out" -name 'libhus_sdk.so' -exec ls -l {} \;
