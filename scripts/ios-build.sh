#!/usr/bin/env bash
set -euo pipefail

# Build hus-sdk as .a for iOS targets.
#
# Prerequisites:
#   - Rust targets installed:
#       rustup target add aarch64-apple-ios aarch64-apple-ios-sim
#   - Xcode command-line tools installed (xcode-select --install)
#
# Usage:  ./scripts/ios-build.sh [release|debug]

PROFILE="${1:-release}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$PROJECT_DIR/target/ios"

# If $PROFILE is "release", map to Cargo's "release" directory
if [ "$PROFILE" = "release" ]; then
  CARGO_PROFILE="release"
  RUSTFLAGS="-C opt-level=3 -C lto=on"
else
  CARGO_PROFILE="debug"
  RUSTFLAGS=""
fi

IOS_TARGETS=(
  "aarch64-apple-ios"       # physical device
  "aarch64-apple-ios-sim"   # simulator (Apple Silicon)
)

echo "==> Building hus-sdk for iOS (profile=$PROFILE)"
cd "$PROJECT_DIR/sdk"

for target in "${IOS_TARGETS[@]}"; do
  echo "  -> $target"
  CARGO_TARGET_DIR="$PROJECT_DIR/sdk/target" \
    RUSTFLAGS="$RUSTFLAGS" \
    cargo build --lib --target "$target" --profile "$CARGO_PROFILE" 2>&1 | tail -1
done

mkdir -p "$OUTPUT_DIR"

# Copy static libraries
for target in "${IOS_TARGETS[@]}"; do
  variant="${target/aarch64-apple-ios/device}"
  variant="${variant/aarch64-apple-ios-sim/sim}"
  src="$PROJECT_DIR/sdk/target/$target/$CARGO_PROFILE/libhus_sdk.a"
  dst="$OUTPUT_DIR/libhus_sdk-$variant.a"
  cp "$src" "$dst"
  echo "  => $dst"
done

# Create a universal XCFramework if both targets built
DEVICE_A="$OUTPUT_DIR/libhus_sdk-device.a"
SIM_A="$OUTPUT_DIR/libhus_sdk-sim.a"
XCFRAMEWORK="$OUTPUT_DIR/HusSdk.xcframework"

if [ -f "$DEVICE_A" ] && [ -f "$SIM_A" ]; then
  echo "==> Creating XCFramework..."
  rm -rf "$XCFRAMEWORK"

  xcodebuild -create-xcframework \
    -library "$DEVICE_A" \
    -library "$SIM_A" \
    -output "$XCFRAMEWORK" 2>&1 | tail -1

  echo "  => $XCFRAMEWORK"
fi

echo "==> Done."
