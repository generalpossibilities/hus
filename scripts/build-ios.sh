#!/usr/bin/env bash
# Build HusSdk.xcframework (static libhus_sdk.a, with the face model
# runtime) for iOS devices and simulators. Needs a Mac with Xcode.
#
#   scripts/build-ios.sh            # → target/HusSdk.xcframework
#
# Link it into the app (Runner target › Frameworks, "Do Not Embed") and keep
# its symbols: the C API is only called through dart:ffi, so add
# `-force_load $(PROJECT_DIR)/.../libhus_sdk.a` or `-Wl,-u,_hus_face_session_new`
# style flags to Other Linker Flags. Dart opens it with DynamicLibrary.process().
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(uname)" == Darwin ]] || { echo "build-ios.sh needs macOS with Xcode" >&2; exit 1; }

targets=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios)
rustup target add "${targets[@]}"
export IPHONEOS_DEPLOYMENT_TARGET=15.5
for t in "${targets[@]}"; do
  CARGO_PROFILE_RELEASE_STRIP=true cargo build --release -p hus-sdk --features ml --lib --target "$t"
done

out=target/HusSdk.xcframework
rm -rf "$out" target/ios-sim
mkdir -p target/ios-sim
lipo -create target/aarch64-apple-ios-sim/release/libhus_sdk.a target/x86_64-apple-ios/release/libhus_sdk.a \
  -output target/ios-sim/libhus_sdk.a
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libhus_sdk.a \
  -library target/ios-sim/libhus_sdk.a \
  -output "$out"
echo "built $out"
