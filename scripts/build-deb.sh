#!/usr/bin/env bash
# Build the .deb package from the staging directory.
# Usage: ./scripts/build-deb.sh [version]

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION="${1:-0.1.0}"
ARCH="amd64"

cd "$ROOT_DIR"

# Ensure binary is built
if [ ! -f "target/x86_64-unknown-linux-musl/release/vault-cli" ]; then
  echo "Building musl release binary..."
  cargo build --release --bin vault-cli --target x86_64-unknown-linux-musl
fi

# Stage the binary
mkdir -p deb/usr/bin
cp target/x86_64-unknown-linux-musl/release/vault-cli deb/usr/bin/secret-manager
chmod 755 deb/usr/bin/secret-manager

# Update control file with version
sed -i "s/^Version:.*/Version: $VERSION/" deb/DEBIAN/control

# Make scripts executable
chmod 755 deb/DEBIAN/postinst

# Build the .deb
mkdir -p dist
DEB_NAME="secret-manager_${VERSION}_${ARCH}.deb"
dpkg-deb --build deb "dist/$DEB_NAME"

echo ""
echo "✓ Built: dist/$DEB_NAME ($(du -h "dist/$DEB_NAME" | cut -f1))"
echo ""
echo "Install locally: sudo dpkg -i dist/$DEB_NAME"