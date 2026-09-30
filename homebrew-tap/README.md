# Secret Manager — Homebrew Tap

Personal Homebrew tap for the Secret Manager CLI.

## Install

```bash
brew install hariomsehgal/secret-manager/secret-manager
```

## How it works

`brew install hariomsehgal/secret-manager/secret-manager` does three things:
1. Clones this tap repo to a temp location
2. Reads `Formula/secret-manager.rb`
3. Downloads the matching release binary from GitHub Releases
4. Installs it to `/opt/homebrew/bin/secret-manager` (macOS ARM) or `/usr/local/bin/secret-manager`

## Setting up your own tap

1. Create a new GitHub repo: `hariomsehgal/homebrew-secret-manager`
2. Copy `Formula/secret-manager.rb` there
3. Tag a release on the main repo: `git tag v0.1.0 && git push origin v0.1.0`
4. Upload `dist/*.tar.gz` to the GitHub release
5. Run `brew audit --new secret-manager` to verify
6. Update SHA256 hashes in the formula

## Generate SHA256 for your release

```bash
shasum -a 256 dist/secret-manager-aarch64-apple-darwin.tar.gz
# or
sha256sum dist/secret-manager-x86_64-unknown-linux-musl.tar.gz
```

Then replace the `PLACEHOLDER_*` strings in `Formula/secret-manager.rb`.