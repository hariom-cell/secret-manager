# Secret Manager — Where It's Useful

## Who Benefits Most

### 1. Developers
- **API keys & tokens** — GitHub, AWS, Stripe, OpenAI, internal services. Stops them leaking in shell history, `.env` files, Slack, or screenshots.
- **Database credentials** — production, staging, dev database passwords.
- **SSH passphrases & GPG keys** — when you need them without a key agent.
- **Webhook signing secrets** — used in CI/CD, often shared in team chats (terrible practice, but common).

### 3. Self-hosters & homelab admins
- **Server passwords** — root/admin passwords for your home servers, NAS, routers.
- **WireGuard / VPN keys** — symmetric secrets used in WireGuard configs.
- **TLS private keys** — for self-hosted services that don't use a managed CA.
- **Home Assistant tokens, Pi-hole credentials, Plex tokens.**

### 4. Security-conscious individuals
- **Master passwords for other tools** — if you don't fully trust your browser's built-in password manager.
- **Banking PINs, account recovery codes** — the 2FA backup codes your bank emails you and then tells you to "save somewhere safe."
- **Crypto wallet seeds** — your seed phrase, stored offline on your own machine instead of on a phone that gets lost.
- **Document scans reference** — passport numbers, tax IDs, insurance policy numbers.

### 5. Privacy-first / regulated users
- **Healthcare workers** with access to patient systems.
- **Lawyers / accountants** with client credentials.
- **Journalists** protecting source identities.
- **Researchers** with IRB-controlled data access credentials.
- Anyone in a jurisdiction where cloud sync of secrets is a compliance issue (GDPR, HIPAA, SOC 2).

---

## Where It Shines vs. Where It Doesn't

### Strong fit
| Situation | Why |
|-----------|-----|
| **Local development on a single machine** | No network, no sync latency, instant |
| **Sensitive credentials you can't put in a cloud manager** | Zero-knowledge, file stays on disk |
| **Air-gapped or low-connectivity environments** | CLI works offline forever |
| **Automating credential access in scripts** | Pipe values via stdin |
| **Embedded in larger Rust applications** | `vault-core` is a library — embed the vault inside your app |

### Weak fit
| Situation | Why this isn't the tool |
|-----------|------------------------|
| **Team-shared credentials** | No multi-user vault; you'd need to share the master password (defeats the point) |
| **Daily browser autofill across devices** | No browser extension yet, no cloud sync |
| **"Forgot my password" recovery** | No recovery by design — you'd lose everything |
| **Mobile-first workflows** | CLI-first; web/PWA scaffolded but not complete |
| **Enterprise SSO integration** | No SAML, OIDC, or SCIM |

---

## Real-World Scenarios

### "I want to rotate my AWS access keys every 90 days without pain"
```bash
# Generate new key in AWS, then:
echo "AKIA_NEW_KEY" | vault-cli set ~/.config/secret-manager/vault.enc $(uuidgen | tr -d -) -p

# Or use it in a script:
export AWS_ACCESS_KEY_ID=$(vault-cli get ~/.config/secret-manager/vault.enc $(cat ~/.aws/.vault-id) -p)
```
No more grep'ing through bash_history or 1Password.

### "I want to share a single vault between my Mac and Linux server"
- Generate a vault on one machine, run `vault-cli export` to make a backup
- Copy the backup file to the other machine
- Run `vault-cli import` on the destination — KDF params preserved, full vault restored

### "I want to bake my own password manager into my product"
The whole thing is a library:
```toml
vault-core = { path = "crates/vault-core" }
vault-db = { path = "crates/vault-db" }
vault-sdk = { path = "crates/vault-sdk" }
```
Build your own UI on top — desktop app, web app, mobile app, CLI — all reading the same `.enc` format.

### "I want to stop typing the same SSH passphrase for git push"
```bash
GIT_ASKPASS=vault-cli ... # (with the right flag)
```
Wrap `vault-cli get` in an `askpass` script and you never re-type the passphrase.

---

## Adjacent Use Cases Worth Knowing

- **Encrypted local backups** — `vault-cli export` writes a portable backup that includes KDF params. Drop it on a USB drive.
- **One-time secret sharing** — the `sharing` module in `vault-core` lets you encrypt a DEK for a specific recipient's public key. Two-party secret handoff without revealing the master password.
- **TOTP tokens** — `vault-sdk` has RFC 6238 TOTP generation built in. Store the seed in a record, generate codes on demand.
- **Recovery phrases** — `vault-sdk` has BIP-39-style mnemonic phrases for backup. Generate → write down → store offline.

---

## Bottom Line

**Use this when you want:**
- Local-first encrypted secret storage
- A library you can embed in your own Rust product
- Zero trust in cloud password managers
- Full control over your secret storage format
- A CLI that pipes into scripts and pipes cleanly out

**Don't use this when:**
- You need daily cross-device browser autofill (use Bitwarden, 1Password)
- You need password recovery (any cloud manager)
- You're managing credentials for a whole org