#!/usr/bin/env bash
# ci/android-build.sh — Cross-compile for Android (aarch64-linux-android).
#
# Prerequisites (on Ubuntu runner):
#   rustup target add aarch64-linux-android
#   sudo apt install -y clang lld libssl-dev
#
# Usage:
#   scripts/android-build.sh <output-dir>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET="aarch64-linux-android"
OUT="${1:-$REPO_ROOT/build/android}"

mkdir -p "$OUT"

echo "=== Building for $TARGET ==="
cd "$REPO_ROOT"

export CC_aarch64_linux_android="aarch64-linux-android21-clang"
export AR_aarch64_linux_android="llvm-ar"

cargo build --release \
  --target "$TARGET" \
  --locked \
  --workspace

echo "=== Android build complete: $OUT ==="

# List built artifacts for verification.
echo "=== Artifacts ==="
find target/$TARGET/release -type f -name "*.rlib" -o -name "*.so" | sort
