#!/usr/bin/env bash
set -euo pipefail

# Pre-download ONNX models from Hugging Face Hub for offline development/testing.
# Models are placed in sdk/../models/ (next to sdk/) so tract-onnx integration
# tests can find them without network access during cargo test.
#
# Usage:
#   ./scripts/download_models.sh                   # download all
#   ./scripts/download_models.sh --verify-only      # verify already-downloaded files
#   MODELS_DIR=/custom/path ./scripts/download_models.sh

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODELS_DIR="${MODELS_DIR:-$REPO_ROOT/models}"

BASE_URL="https://huggingface.co/hus-sdk/onnx-models/resolve/main"

# Format: name|expected_size
MODELS=(
    "arcface.onnx|131000000"
    "ResNet50_Iris.onnx|99000000"
    "voxceleb_ECAPA512_LM.onnx|24000000"
    "fingerprint_mini.onnx|4000000"
)

mkdir -p "$MODELS_DIR"

download() {
    local name="$1"
    local expected="$2"
    local path="$MODELS_DIR/$name"

    if [[ -f "$path" ]]; then
        local actual
        actual=$(stat --format=%s "$path" 2>/dev/null || stat -f%z "$path" 2>/dev/null)
        local tolerance=$(( expected / 20 ))  # 5% tolerance
        local diff=$(( actual - expected ))
        diff=${diff#-}  # abs
        if [[ "$diff" -le "$tolerance" ]]; then
            echo "  ✓ $name (${actual} bytes, cached)"
            return 0
        else
            echo "  ! $name size mismatch (expected ~${expected}, got ${actual}), re-downloading..."
        fi
    fi

    echo "  ↓ $name (~$(( expected / 1000000 )) MB)..."

    # Show download progress if curl is available
    if command -v curl &>/dev/null; then
        curl -fL# "$BASE_URL/$name" -o "$path"
    elif command -v wget &>/dev/null; then
        wget --progress=dot:giga -O "$path" "$BASE_URL/$name"
    else
        echo "  ✗ need curl or wget"
        return 1
    fi

    local actual
    actual=$(stat --format=%s "$path" 2>/dev/null || stat -f%z "$path" 2>/dev/null)
    echo "  ✓ $name (${actual} bytes)"
}

main() {
    echo "HUS — Downloading ONNX models to $MODELS_DIR"

    local verify_only=false
    for arg in "$@"; do
        [[ "$arg" == "--verify-only" ]] && verify_only=true
    done

    for entry in "${MODELS[@]}"; do
        IFS='|' read -r name expected <<< "$entry"
        if [[ "$verify_only" == "true" ]]; then
            if [[ -f "$MODELS_DIR/$name" ]]; then
                echo "  ✓ $name (present)"
            else
                echo "  ✗ $name (missing)"
            fi
        else
            download "$name" "$expected"
        fi
    done

    echo ""
    echo "Done. Models are in $MODELS_DIR"
    echo "Run: MODEL_DIR=$MODELS_DIR cargo test --lib -p hus-sdk --features ml,std -- --nocapture"
}

main "$@"
