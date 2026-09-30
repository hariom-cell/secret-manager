#!/usr/bin/env bash
# Secret Manager — APT Repository Setup
#
# One-time setup to add the Secret Manager APT repository:
#   curl -fsSL https://apt.secret-manager.dev/setup.sh | sudo bash
#
# Then install/upgrade:
#   sudo apt install secret-manager
#   sudo apt upgrade secret-manager

set -euo pipefail

DISTRO=$(lsb_release -is | tr '[:upper:]' '[:lower:]')
CODENAME=$(lsb_release -cs)
ARCH=$(dpkg --print-architecture)

info() { echo -e "\033[0;32m[✓]\033[0m $*"; }
error() { echo -e "\033[0;31m[✗]\033[0m $*"; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
  error "Run with sudo: curl -fsSL https://apt.secret-manager.dev/setup.sh | sudo bash"
fi

info "Setting up Secret Manager APT repository for $DISTRO $CODENAME ($ARCH)"

# Install prerequisites
if ! command -v gnupg &>/dev/null; then
  apt-get update -qq
  apt-get install -y -qq gnupg ca-certificates curl > /dev/null 2>&1
  info "Installed gnupg, ca-certificates"
fi

# Add GPG key
KEYRING_DIR="/etc/apt/keyrings"
mkdir -p "$KEYRING_DIR"

if command -v gpg &>/dev/null; then
  curl -fsSL "https://apt.secret-manager.dev/key.gpg" | gpg --dearmor -o "$KEYRING_DIR/secret-manager.gpg"
else
  curl -fsSL "https://apt.secret-manager.dev/key.gpg" -o "$KEYRING_DIR/secret-manager.gpg"
fi

info "GPG key added"

# Add repository
REPO_FILE="/etc/apt/sources.list.d/secret-manager.list"
echo "deb [arch=${ARCH} signed-by=${KEYRING_DIR}/secret-manager.gpg] https://apt.secret-manager.dev ${CODENAME} main" > "$REPO_FILE"

info "Repository added: $REPO_FILE"

# Update and install
apt-get update -qq
apt-get install -y -qq secret-manager

info "Secret Manager installed!"
echo ""
echo "  secret-manager create    # Create a new vault"
echo "  secret-manager unlock    # Unlock your vault"
echo "  secret-manager list      # List your secrets"
