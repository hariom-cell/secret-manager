#!/usr/bin/env bash
# build_repro.sh — Verify that `cargo build --release` produces deterministic
#                  output across two builds.
#
# Usage:
#   ./scripts/build_repro.sh [target-dir] [package]
#
# This script builds the workspace twice and compares the resulting
# binary hashes.  If they match, the build is reproducible.
#
# For truly deterministic Rust builds, the following environment variables
# are set:
#   SOURCE_DATE_EPOCH — pins the build timestamp (Unix epoch)
#   CARGO_BUILD_RUSTFLAGS — strips debuginfo and disables incremental
#
# Exit codes:
#   0  — reproducible (hashes match)
#   1  — not reproducible (hashes differ)
#   2  — build failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CARGO="$HOME/.cargo/bin/cargo"
TARGET_DIR="${1:-$REPO_ROOT/target/repro}"
PACKAGE="${2:-}"   # optional, e.g. "vault-cli"
export CARGO_TARGET_DIR="$TARGET_DIR"

# Deterministic build flags.
export SOURCE_DATE_EPOCH=0
export CARGO_BUILD_JOBS=1
export RUSTFLAGS="-C strip=symbols -C link-arg=-s"

mkdir -p "$TARGET_DIR"

build() {
    local label="$1"
    echo "=== Build $label ==="
    rm -rf "$TARGET_DIR/$label"
    mkdir -p "$TARGET_DIR/$label"

    if [[ -n "$PACKAGE" ]]; then
        "$CARGO" build --release --locked -p "$PACKAGE"
    else
        "$CARGO" build --release --locked --workspace
    fi

    # Copy release artifacts (binaries, static libs) into the label dir.
    if [[ -d "$TARGET_DIR/release" ]]; then
        cp -r "$TARGET_DIR/release"/* "$TARGET_DIR/$label/" 2>/dev/null || true
    fi
    echo "=== Build $label complete ==="
}

hash_dir() {
    local dir="$1"
    find "$dir" -type f -executable -not -name "*.d" \
        -exec sha256sum {} \; | sort
}

echo "Reproducible build check"
echo "  target dir:  $TARGET_DIR"
echo "  package:     ${PACKAGE:-workspace}"
echo

build "A"
build "B"

echo
echo "=== Comparing hashes ==="
HASHES_A=$(mktemp)
HASHES_B=$(mktemp)
hash_dir "$TARGET_DIR/A" > "$HASHES_A"
hash_dir "$TARGET_DIR/B" > "$HASHES_B"

if diff -q "$HASHES_A" "$HASHES_B" > /dev/null 2>&1; then
    echo "PASS: Builds are reproducible."
    echo
    cat "$HASHES_A"
    rm -f "$HASHES_A" "$HASHES_B"
    exit 0
else
    echo "FAIL: Builds differ."
    diff "$HASHES_A" "$HASHES_B" || true
    rm -f "$HASHES_A" "$HASHES_B"
    exit 1
fi
