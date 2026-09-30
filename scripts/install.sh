#!/usr/bin/env bash
# Secret Manager — One-Click Install
#
# Usage:
#   curl -fsSL https://install.secret-manager.dev | bash
#   curl -fsSL https://install.secret-manager.dev | bash -s -- v0.2.0
#
# Detects OS/arch and installs the right binary.

set -euo pipefail

VERSION="${1:-latest}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="$HOME/.config/secret-manager"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }

# ─── Detect Platform ───────────────────────────────────────────────────

detect_platform() {
  local os arch
  os=$(uname -s)
  arch=$(uname -m)

  case "$os" in
    Darwin)
      case "$arch" in
        arm64)  PLATFORM="aarch64-apple-darwin" ;;
        x86_64) PLATFORM="x86_64-apple-darwin" ;;
        *) error "Unsupported Mac architecture: $arch" ;;
      esac
      BIN_NAME="secret-manager-macos"
      ;;
    Linux)
      case "$arch" in
        x86_64) PLATFORM="x86_64-unknown-linux-musl" ;;
        aarch64|arm64) PLATFORM="aarch64-unknown-linux-musl" ;;
        *) error "Unsupported Linux architecture: $arch" ;;
      esac
      BIN_NAME="secret-manager-linux"
      ;;
    MINGW*|MSYS*|CYGWIN*)
      error "Windows: use the .msi installer from GitHub Releases or scoop: scoop install secret-manager"
      ;;
    *)
      error "Unsupported OS: $os"
      ;;
  esac

  info "Detected: $os $arch → $PLATFORM"
}

# ─── Check Prerequisites ──────────────────────────────────────────────

check_deps() {
  if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
    error "Need curl or wget. Install one and retry."
  fi
  if ! command -v tar &>/dev/null; then
    error "Need tar. Install it and retry."
  fi
  info "Dependencies OK"
}

# ─── Download ──────────────────────────────────────────────────────────

download() {
  local version="$1"
  local platform="$2"
  local url

  if [ "$version" = "latest" ]; then
    url="https://github.com/hariomsehgal/secret-manager/releases/latest/download/secret-manager-${platform}.tar.gz"
  else
    url="https://github.com/hariomsehgal/secret-manager/releases/download/${version}/secret-manager-${platform}.tar.gz"
  fi

  info "Downloading $version for $platform..."

  if command -v curl &>/dev/null; then
    curl -fsSL "$url" -o "/tmp/secret-manager.tar.gz" || error "Download failed. Check the URL or network."
  else
    wget -q "$url" -O "/tmp/secret-manager.tar.gz" || error "Download failed."
  fi

  info "Downloaded $(du -h /tmp/secret-manager.tar.gz | cut -f1)"
}

# ─── Install ───────────────────────────────────────────────────────────

install_binary() {
  local binary_name="secret-manager"
  local dest="$INSTALL_DIR/$binary_name"

  # Extract
  tar -xzf /tmp/secret-manager.tar.gz -C /tmp/

  # Find the binary in the extracted files
  local extracted
  extracted=$(find /tmp -name "$binary_name" -type f | head -1)

  if [ -z "$extracted" ]; then
    error "Binary not found in archive. Archive contents:"
    tar -tzf /tmp/secret-manager.tar.gz
    exit 1
  fi

  # Check if we need sudo
  if [ -w "$INSTALL_DIR" ]; then
    cp "$extracted" "$dest"
  else
    info "Need sudo to write to $INSTALL_DIR"
    sudo cp "$extracted" "$dest"
  fi

  chmod +x "$dest"
  info "Installed to $dest"

  # Verify
  if "$dest" --version &>/dev/null || "$dest" --help &>/dev/null; then
    info "Installation verified"
  else
    warn "Could not verify binary (try running: $dest --help)"
  fi

  # Cleanup
  rm -rf /tmp/secret-manager.tar.gz /tmp/$binary_name 2>/dev/null || true
}

# ─── Setup Config ──────────────────────────────────────────────────────

setup_config() {
  mkdir -p "$CONFIG_DIR"
  chmod 700 "$CONFIG_DIR"
  info "Config directory ready: $CONFIG_DIR"
}

# ─── Main ──────────────────────────────────────────────────────────────

main() {
  echo ""
  echo "╔══════════════════════════════════════════╗"
  echo "║     🔐 Secret Manager Installer         ║"
  echo "╚══════════════════════════════════════════╝"
  echo ""

  detect_platform
  check_deps
  download "$VERSION" "$PLATFORM"
  install_binary
  setup_config

  echo ""
  info "Installation complete!"
  echo ""
  echo "  Next steps:"
  echo "    secret-manager create    # Create a new vault"
  echo "    secret-manager unlock    # Unlock your vault"
  echo "    secret-manager list      # List your secrets"
  echo ""
  echo "  Vault stored at: $CONFIG_DIR/vault.enc"
  echo ""

  if ! command -v secret-manager &>/dev/null; then
    warn "The binary was installed to $INSTALL_DIR but it's not in your PATH."
    echo "  Add this to your shell config:"
    echo "    export PATH=\"$INSTALL_DIR:\$PATH\""
  fi
}

main "$@"
