class SecretManager < Formula
  desc "End-to-end encrypted secret manager (XChaCha20-Poly1305 + Argon2id)"
  homepage "https://github.com/hariomsehgal/secret-manager"
  license "AGPL-3.0-or-later"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/hariomsehgal/secret-manager/releases/download/v0.1.0/secret-manager-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_ARM64"
    else
      url "https://github.com/hariomsehgal/secret-manager/releases/download/v0.1.0/secret-manager-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_X86_64"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/hariomsehgal/secret-manager/releases/download/v0.1.0/secret-manager-aarch64-unknown-linux-musl.tar.gz"
      sha256 "PLACEHOLDER_LINUX_ARM"
    else
      url "https://github.com/hariomsehgal/secret-manager/releases/download/v0.1.0/secret-manager-x86_64-unknown-linux-musl.tar.gz"
      sha256 "PLACEHOLDER_LINUX"
    end
  end

  def install
    bin.install "secret-manager"
  end

  test do
    system "#{bin}/secret-manager", "--help"
  end
end
