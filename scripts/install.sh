#!/usr/bin/env bash
# Secret Manager — One-Click Install
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/hariom-cell/secret-manager/main/scripts/install.sh | bash
#   curl -fsSL ... | bash -s -- v0.2.0
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

info() { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[X]${NC} $*"; exit 1; }

REPO="hariom-cell/secret-manager"

# ─── Detect Platform ──────────────────────────────────────────────

detect_platform() {
  local os arch
  os=$(uname -s)
  arch=$(uname -m)

  case "$os" in
    Darwin)
      case "$arch" in
        arm64)  PLATFORM="mac-arm"; ASSET="vault-cli-mac-arm.tar.gz"; BIN_NAME="secret-manager-arm" ;;
        x86_64) PLATFORM="mac-intel"; ASSET="vault-cli-mac-intel.tar.gz"; BIN_NAME="secret-manager-intel" ;;
        *) error "Unsupported Mac architecture: $arch" ;;
      esac
      ;;
    Linux)
      case "$arch" in
        x86_64)
          warn "Linux binary not yet published. Building from source..."
          build_from_source
          exit 0
          ;;
        aarch64|arm64)
          warn "Linux ARM binary not yet published. Building from source..."
          build_from_source
          exit 0
          ;;
        *) error "Unsupported Linux architecture: $arch" ;;
      esac
      ;;
    MINGW*|MSYS*|CYGWIN*)
      error "Windows: download the .exe from GitHub Releases or: scoop install secret-manager"
      ;;
    *)
      error "Unsupported OS: $os"
      ;;
  esac

  info "Detected: $os $arch -> $PLATFORM"
}

# ─── Build from source (fallback) ────────────────────────────────

build_from_source() {
  if ! command -v cargo &>/dev/null; then
    error "Need Rust to build from source. Install: https://rustup.rs/"
  fi

  local tmpdir
  tmpdir=$(mktemp -d)
  info "Cloning repository..."
  git clone "https://github.com/${REPO}.git" "$tmpdir/secret-manager" --depth 1

  cd "$tmpdir/secret-manager"
  cargo build --release --bin vault-cli

  local extracted="$tmpdir/secret-manager/target/release/vault-cli"
  local dest="$INSTALL_DIR/secret-manager"

  if [ -w "$INSTALL_DIR" ]; then
    cp "$extracted" "$dest"
  else
    info "Need sudo to write to $INSTALL_DIR"
    sudo cp "$extracted" "$dest"
  fi
  chmod +x "$dest"

  mkdir -p "$CONFIG_DIR"
  chmod 700 "$CONFIG_DIR"

  info "Built and installed to $dest"
  rm -rf "$tmpdir"
}

# ─── Check Prerequisites ────────────────────────────────────────

check_deps() {
  if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
    error "Need curl or wget. Install one and retry."
  fi
  if ! command -v tar &>/dev/null; then
    error "Need tar. Install it and retry."
  fi
  info "Dependencies OK"
}

# ─── Download ────────────────────────────────────────────────────

download() {
  local version="$1"
  local url

  if [ "$version" = "latest" ]; then
    url="https://github.com/${REPO}/releases/latest/download/${ASSET}"
  else
    url="https://github.com/${REPO}/releases/download/${version}/${ASSET}"
  fi

  info "Downloading $ASSET..."

  if command -v curl &>/dev/null; then
    curl -fsSL "$url" -o "/tmp/$ASSET" || error "Download failed from: $url"
  else
    wget -q "$url" -O "/tmp/$ASSET" || error "Download failed."
  fi

  info "Downloaded $(du -h "/tmp/$ASSET" | cut -f1)"
}

# ─── Install ─────────────────────────────────────────────────────

install_binary() {
  local dest="$INSTALL_DIR/secret-manager"

  # Extract
  tar -xzf "/tmp/$ASSET" -C /tmp/

  local extracted="/tmp/$BIN_NAME"
  if [ ! -f "$extracted" ]; then
    error "Binary '$BIN_NAME' not found in archive. Contents:"
    tar -tzf "/tmp/$ASSET"
    exit 1
  fi

  # Install (with sudo if needed)
  if [ -w "$INSTALL_DIR" ]; then
    cp "$extracted" "$dest"
  else
    info "Need sudo to write to $INSTALL_DIR"
    sudo cp "$extracted" "$dest"
  fi

  chmod +x "$dest"
  info "Installed to $dest"

  # Verify
  if "$dest" --help &>/dev/null; then
    info "Installation verified"
  else
    warn "Could not verify binary (try running: $dest --help)"
  fi

  # Cleanup
  rm -f "/tmp/$ASSET" "/tmp/$BIN_NAME"
}

# ─── Setup Config ────────────────────────────────────────────────

setup_config() {
  mkdir -p "$CONFIG_DIR"
  chmod 700 "$CONFIG_DIR"
  info "Config directory ready: $CONFIG_DIR"
}

# ─── Main ─────────────────────────────────────────────────────────

main() {
  echo ""
  echo "============================================"
  echo "  Secret Manager Installer"
  echo "============================================"
  echo ""

  detect_platform
  check_deps
  download "$VERSION"
  install_binary
  setup_config

  echo ""
  info "Installation complete!"
  echo ""
  echo "  Next steps:"
  echo "    secret-manager create    # Create a new vault"
  echo "    secret-manager list      # List your secrets"
  echo "    secret-manager gen-pass  # Generate a password"
  echo ""
  echo "  Vault stored at: $CONFIG_DIR/vault.enc"
  echo ""

  if ! command -v secret-manager &>/dev/null; then
    warn "Installed to $INSTALL_DIR but it's not in your PATH."
    echo "  Add to your shell config:"
    echo "    export PATH=\"$INSTALL_DIR:\$PATH\""
  fi
}

main "$@"