#!/usr/bin/env bash
# Build release binaries for all platforms.
# Requires: rustup target add for each target
#   rustup target add aarch64-apple-darwin
#   rustup target add x86_64-apple-darwin
#   rustup target add x86_64-unknown-linux-musl
#
# Outputs to dist/

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
mkdir -p "$DIST_DIR"

echo "Building release binaries..."

build_target() {
  local target=$1
  local name=$2
  echo "  → $name ($target)..."

  cargo build --release --bin vault-cli --target "$target" 2>&1 | tail -3

  local bin_src="$ROOT_DIR/target/$target/release/vault-cli"
  local tar_name="secret-manager-$name.tar.gz"

  # Package: binary + LICENSE + README
  local staging
  staging=$(mktemp -d)
  cp "$bin_src" "$staging/secret-manager"
  cp "$ROOT_DIR/LICENSE" "$staging/LICENSE" 2>/dev/null || true

  tar -czf "$DIST_DIR/$tar_name" -C "$staging" secret-manager LICENSE
  rm -rf "$staging"

  echo "    ✓ $DIST_DIR/$tar_name ($(du -h "$DIST_DIR/$tar_name" | cut -f1))"
}

# macOS ARM (Apple Silicon)
build_target "aarch64-apple-darwin" "aarch64-apple-darwin"

# macOS x86_64 (Intel)
build_target "x86_64-apple-darwin" "x86_64-apple-darwin"

# Linux x86_64 (static musl)
build_target "x86_64-unknown-linux-musl" "x86_64-unknown-linux-musl"

echo ""
echo "All binaries built in $DIST_DIR:"
ls -lh "$DIST_DIR"/*.tar.gz 2>/dev/null || echo "  (none — check for errors above)"
