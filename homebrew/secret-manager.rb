class SecretManager < Formula
  desc "Privacy-first cryptographic vault for secrets management"
  homepage "https://github.com/hariom-cell/secret-manager"
  url "https://github.com/hariom-cell/secret-manager/archive/refs/tags/v0.1.0.tar.gz"
  sha256 ""  # Updated after each release with: shasum -a 256 <tarball>
  license "AGPL-3.0-or-later"
  version "0.1.0"

  depends_on "rust" => :build

  def install
    system "cargo", "install", "--locked", "--root", prefix, "--path", "."
  end

  test do
    system "#{bin}/secret-manager", "help"
  end
end
