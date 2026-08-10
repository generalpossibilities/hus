#!/usr/bin/env bash
set -euo pipefail

# Build hus-sdk as .so for Android targets using cargo-ndk.
#
# Prerequisites:
#   - Rust targets installed:
#       rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
#   - cargo-ndk installed:
#       cargo install cargo-ndk
#   - Android NDK installed and ANDROID_NDK_HOME set:
#       export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/<version>
#
# Usage:  ./scripts/android-build.sh [release|debug]

PROFILE="${1:-release}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$PROJECT_DIR/target/android"

ANDROID_TARGETS=(
  "aarch64-linux-android"       # arm64-v8a
  "armv7-linux-androideabi"     # armeabi-v7a
  "x86_64-linux-android"        # x86_64
)

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  echo "ERROR: ANDROID_NDK_HOME is not set"
  exit 1
fi

echo "==> Building hus-sdk for Android (profile=$PROFILE)"
cd "$PROJECT_DIR/sdk"

for target in "${ANDROID_TARGETS[@]}"; do
  echo "  -> $target"
  cargo ndk \
    --target "$target" \
    --platform 21 \
    build --lib --profile "$PROFILE" 2>&1 | tail -1
done

mkdir -p "$OUTPUT_DIR"

# Map Rust target → Android ABI directory and platform lib name
declare -A ABI_MAP=(
  [aarch64-linux-android]=arm64-v8a
  [armv7-linux-androideabi]=armeabi-v7a
  [x86_64-linux-android]=x86_64
)

for target in "${ANDROID_TARGETS[@]}"; do
  abi="${ABI_MAP[$target]}"
  src="$PROJECT_DIR/sdk/target/$target/$PROFILE/libhus_sdk.so"
  dst="$OUTPUT_DIR/$abi/libhus_sdk.so"
  mkdir -p "$(dirname "$dst")"
  cp "$src" "$dst"
  echo "  => $dst"
done

echo "==> Done. Check $OUTPUT_DIR"
ls -lh "$OUTPUT_DIR"/*/libhus_sdk.so
