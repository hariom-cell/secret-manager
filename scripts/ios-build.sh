#!/usr/bin/env bash
# ci/ios-build.sh — Cross-compile for iOS (aarch64-apple-ios).
#
# Prerequisites (on macOS runner):
#   rustup target add aarch64-apple-ios
#   xcode-select --install
#
# Usage:
#   scripts/ios-build.sh <output-dir>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET="aarch64-apple-ios"
OUT="${1:-$REPO_ROOT/build/ios}"

mkdir -p "$OUT"

echo "=== Building for $TARGET ==="
cd "$REPO_ROOT"

cargo build --release \
  --target "$TARGET" \
  --locked \
  --workspace

mkdir -p "$OUT/lib"
cp target/$TARGET/release/lib*.a "$OUT/lib/" 2>/dev/null || true

echo "=== iOS build complete: $OUT ==="
