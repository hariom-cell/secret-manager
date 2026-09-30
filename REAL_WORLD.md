# Secret Manager — Real-World Scenarios

## Scenario 1: The Developer Who Leaked Their AWS Key

### The Situation
Rahul is a backend developer. He spins up a new AWS EC2 instance for testing. The
access key gets generated. He pastes it into his terminal, runs `aws s3 ls`, then
closes the terminal. The key is now in `~/.zsh_history`. A month later someone
scrapes his dotfiles from a public GitHub repo and finds it. The bill: $4,700 in
cryptomining charges before he notices.

### With Secret Manager
```bash
# Create the vault (one time)
vault-cli create ~/.vault/aws.enc
Master password: ********

# Store each AWS credential
vault-cli set ~/.vault/aws.enc 00112233445566778899aabbcceeff00 "AKIAIOSFODNN7EXAMPLE"
vault-cli set ~/.vault/aws.enc 11223344556677889900aabbcceeff01 "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Use it in a script — never touches disk as plaintext
export AWS_ACCESS_KEY_ID=$(vault-cli get ~/.vault/aws.enc 00112233445566778899aabbcceeff00)
export AWS_SECRET_ACCESS_KEY=$(vault-cli get ~/.vault/aws.enc 11223344556677889900aabbcceeff01)
aws s3 ls

# Zeroize from memory
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
```

The key is never in shell history, never in an `.env` file, never in a Slack message.
If the vault file is stolen, the attacker gets XChaCha20-Poly1305 ciphertext — useless
without the master password.

---

## Scenario 2: The Freelancer With 30 Client Passwords

### The Situation
Priya does contract work for 8 different companies. Each has a different Jira, Figma,
GitHub org, AWS account, and staging environment. She currently keeps them in a
Chrome-saved passwords file tied to her personal Google account. Her Google account
is compromised once (phishing link). The attacker now has access to every client's
Figma board and GitHub repo.

### With Secret Manager
```bash
# One vault for all clients
vault-cli create ~/vault/clients.enc

# Store each client's credentials by domain
vault-cli set ~/vault/clients.enc client-a-jira-url "https://a-corp.atlassian.net"
vault-cli set ~/vault/clients.enc client-a-jira-user "priya@personal.email"
vault-cli set ~/vault/clients.enc client-a-jira-pass "JiraAccess2024!"
vault-cli set ~/vault/clients.enc client-b-aws-key "AKIA..."
vault-cli set ~/vault/clients.enc client-b-aws-secret "..."

# List all client records
vault-cli list ~/vault/clients.enc
# Shows: client-a-jira-url, client-a-jira-user, client-a-jira-pass, ...

# Backup to encrypted USB drive
vault-cli export ~/vault/clients.enc /Volumes/USB/backup-2024-12.enc
```

If her laptop is stolen: the vault file is on it, but it's encrypted. The USB backup
is also encrypted. The Google account compromise means nothing because none of the
client credentials are stored there.

---

## Scenario 3: The DevOps Engineer Rotating Credentials

### The Situation
Marcus runs a Kubernetes cluster with 12 microservices. Each has a database password,
a message queue token, and a third-party API key. He stores them in a shared 1Password
vault his whole team has access to. When someone leaves, he needs to rotate every
single credential. He doesn't. Six months later the ex-employee still has access to
the production database.

### With Secret Manager
```bash
# Marcus keeps his own vault for his service account credentials
vault-cli create ~/vault/infra.enc

# Store each service credential
vault-cli set ~/vault/infra.enc svc-pg-user "svc_app"
vault-cli set ~/vault/infra.enc svc-pg-pass "$(openssl rand -base64 32)"

# His pipeline pulls from the vault at runtime
# .gitlab-ci.yml:
#   - export DATABASE_URL="postgres://$(vault-cli get ~/vault/infra.enc svc-pg-user):$(vault-cli get ~/vault/infra.enc svc-pg-pass)@pg:5432/app"

# When someone leaves, Marcus rotates and re-saves:
NEW_PASS=$(openssl rand -base64 32)
vault-cli set ~/vault/infra.enc svc-pg-pass "$NEW_PASS"
# Updates in CI on next run — no team vault to worry about
```

The secret never lives in a shared password manager. Rotation is a single command.
No ex-employee has access because they never had the vault file or the master password.

---

## Scenario 4: The Security Researcher Handling Sensitive Data

### The Situation
Aisha is researching a zero-day vulnerability. She has PoC exploit code, a private
disclosure thread with the vendor, IRB-controlled data access credentials, and source
identities. She needs to store all of this. Her institution requires encrypted storage.
She can't use LastPass (vendor is US-based, subject to CLOUD Act). She can't use
Apple Notes (iCloud syncs to Apple's servers). She needs something local-only.

### With Secret Manager
```bash
# Research vault — on her encrypted disk, never transmitted
vault-cli create ~/research/vault-2024.enc

# Store PoC details, source identifiers, vendor comms
vault-cli set ~/research/vault-2024.enc vuln-id "CVE-2024-PENDING"
vault-cli set ~/research/vault-2024.enc source-alpha "identity details, contact"
vault-cli set ~/research/vault-2024.enc vendor-thread "email thread ID + access token"

# Export for her encrypted backup drive
vault-cli export ~/research/vault-2024.enc /Volumes/EncryptedBackup/q4-research.enc
```

No cloud. No third-party server. The vault file is on her machine only. The backup
is on an encrypted drive she controls. The institution's audit requirement is met
— the data is encrypted at rest with industry-standard cryptography.

---

## Scenario 5: The Freelancer Building a Client Project

### The Situation
Dan builds websites. Each client gives him a cPanel login, a domain registrar account,
an email hosting credential, and sometimes an API key for their email service provider.
He has 22 active clients. He currently keeps a `passwords.txt` file in Dropbox. His
Dropbox was once compromised in a credential-stuffing attack. He got lucky — the file
wasn't accessible because he had 2FA on Dropbox. But he knows it's a matter of time.

### With Secret Manager
```bash
# One vault, clear record IDs by client + service
vault-cli create ~/vault/clients.enc

# Client A — Acme Corp
vault-cli set ~/vault/clients.enc acme-cpanel "https://acme.com:2083"
vault-cli set ~/vault/clients.enc acme-cpanel-user "dan_admin"
vault-cli set ~/vault/clients.enc acme-cpanel-pass "$(vault-cli gen-pass 20)"
vault-cli set ~/vault/clients.enc acme-registrar "GoDaddy login: user / pass"
vault-cli set ~/vault/clients.enc acme-mailgun "key-..."

# Client B — Beta LLC
vault-cli set ~/vault/clients.enc beta-cpanel "..."

# Access in a script when deploying
vault-cli get ~/vault/clients.enc acme-cpanel-user
vault-cli get ~/vault/clients.enc acme-cpanel-pass | pbcopy  # paste to cPanel

# Never in Dropbox — vault.enc is a binary file that looks like random noise
# Dropbox syncs it, but without the password it's just 256 bytes of header + random ciphertext
```

Even if Dropbox is breached, the attacker gets encrypted blobs. The file structure
is opaque. Without the master password, there's no way to know which record belongs
to which client.

---

## Scenario 6: The Sysadmin Managing Home Infrastructure

### The Situation
Carl runs a home lab: Proxmox, Pi-hole, Home Assistant, a NAS, a Minecraft server,
and a WireGuard VPN. Every service has its own admin password. He wrote them in a
Notion page. Notion is convenient — accessible from his phone, his laptop, his tablet.
But Notion is also a single point of failure. If his Notion account is compromised,
every home service is exposed.

### With Secret Manager
```bash
# Home lab vault
vault-cli create ~/vault/homelab.enc

# Infrastructure credentials
vault-cli set ~/vault/homelab.enc proxmox-admin "root:$(vault-cli gen-pass 24)"
vault-cli set ~/vault/homelab.enc pihole-admin "$(vault-cli gen-pass 16)"
vault-cli set ~/vault/homelab.enc nas-admin "admin:$(vault-cli gen-pass 20)"
vault-cli set ~/vault/homelab.enc wireguard-peer1 "$(cat wg0.conf | grep PrivateKey)"
vault-cli set ~/vault/homelab.enc home-assistant-token "long-lived-access-token"

# View when needed
vault-cli get ~/vault/homelab.enc pihole-admin | pbcopy

# Offline backup on a USB stick
vault-cli export ~/vault/homelab.enc /mnt/usb/homelab-backup.enc
```

Notion is gone. The secrets are on his machines only. The USB backup is encrypted
with the same master password. If his laptop dies, he plugs in the USB and imports.

---

## Scenario 7: The Open-Source Maintainer

### The Situation
Nina maintains a popular Rust library. She has: the crate publish token, GitHub
personal access token, npm token, Docker Hub token, AWS S3 bucket for release assets,
and a Cloudflare API token for the project website. She stores the Cloudflare token
in a GitHub Actions secret. The others she keeps in a `.env` file in the repo. A
contributor opens a PR that accidentally includes the `.env` file. The token is
exposed in the git history permanently.

### With Secret Manager
```bash
# Maintainer vault — on her machine only
vault-cli create ~/vault/oss-tools.enc

# Store each publishing credential
vault-cli set ~/vault/oss-tools.enc crates-io-token "pk-abc123..."
vault-cli set ~/vault/oss-tools.enc gh-pat "ghp_abc123..."
vault-cli set ~/vault/oss-tools.enc npm-token "npm_abc123..."
vault-cli set ~/vault/oss-tools.enc dockerhub-token "abc123..."
vault-cli set ~/vault/oss-tools.enc cf-api-token "abc123..."
vault-cli set ~/vault/oss-tools.enc s3-access-key "AKIA..."
vault-cli set ~/vault/oss-tools.enc s3-secret "..."

# CI uses environment injection — never in repo
# .github/workflows/publish.yml:
#   env:
#     CARGO_REGISTRY_TOKEN: ${{ secrets.VAULT_CRATES_IO }}
#   secrets:
#     VAULT_CRATES_IO: ${{ secrets.VAULT_CRATES_IO }}

# Her local publish script:
#!/bin/bash
eval $(vault-cli get ~/vault/oss-tools.enc crates-io-token | sed 's/^/CARGO_REGISTRY_TOKEN=/')
cargo publish
```

The `.env` file is gone. The tokens are never committed. If her laptop is stolen,
the vault is encrypted. If she needs to hand off a credential, she shares a single
record — not the whole file.

---

## Scenario 8: The Person Who Wants a Privacy-First Password Manager

### The Situation
Alex used 1Password for 5 years. He paid $60/year. He trusts the product but doesn't
trust that a US-based company won't someday get a subpoena, or that their next
breach will expose his vault. He wants a local-only option but Bitwarden's self-hosted
setup requires a server, Docker, TLS certificates, and maintenance. He just wants
a file on his disk.

### With Secret Manager
```bash
# Personal vault — single file, no server, no account
vault-cli create ~/vault/personal.enc

# Organize by prefix convention
# Personal
vault-cli set ~/vault/personal.enc pers-gmail "my-gmail-password"
vault-cli set ~/vault/personal.enc pers-bank "bank-login-pass"
vault-cli set ~/vault/personal.enc pers-coinbase-seed "abandon ability ..."

# Work
vault-cli set ~/vault/personal.enc work-vpn "vpn-pass"
vault-cli set ~/vault/personal.enc work-slack-token "xoxb-..."

# Notes (hex IDs you can map to a paper notebook)
vault-cli set ~/vault/personal.enc note-001 "Passport #: X1234567"
vault-cli set ~/vault/personal.enc note-002 "SSN last 4: 1234"
vault-cli set ~/vault/personal.enc note-003 "Health insurance ID"

# List all
vault-cli list ~/vault/personal.enc

# Export backup — copy to a friend's encrypted drive
vault-cli export ~/vault/personal.enc ~/Desktop/backup-dec-2024.enc
```

No subscription. No account. No cloud. No server. The entire password manager is
one file + the master password in Alex's head. He syncs the encrypted file via
whatever method he wants (USB, scp, syncthing — the file is always encrypted).

---

## Scenario 9: Incident Response — "My laptop was stolen"

### With Secret Manager
```
1. The vault file is on the disk: vault.enc
2. The vault file is encrypted with XChaCha20-Poly1305
3. The VEK is wrapped (encrypted) under the KEK
4. The KEK is derived from the master password via Argon2id
5. The attacker has: random ciphertext. They cannot derive the KEK without
   the password. They cannot unwrap the VEK. They cannot derive any DEK.
6. Result: the vault file is computationally infeasible to break
```

**What Alex does next:**
```bash
# On a new machine, same master password:
vault-cli create ~/vault/personal.enc  # Creates NEW vault with new salt
# Import from backup
vault-cli import ~/vault/personal.enc /Volumes/USB/backup-dec-2024.enc
Master password: ********
# Full vault restored. Old vault file on stolen laptop is worthless.
```

---

## Scenario 10: CI/CD Pipeline Secrets

### The Situation
A team deploys to AWS every day. Their CI secrets (AWS keys, database passwords,
Docker registry tokens) live in GitHub Secrets. GitHub is a US company. The team
is in the EU. They want an alternative that doesn't go through a US-hosted service.

### With Secret Manager
```bash
# Encrypted vault stored in the repo (looks like random bytes)
vault-cli create ci-secrets.enc

# Store all CI credentials
vault-cli set ci-secrets.enc aws-key "..."
vault-cli set ci-secrets.enc aws-secret "..."
vault-cli set ci-secrets.enc db-pass "..."
vault-cli set ci-secrets.ecr-token "..."

# Commit ci-secrets.enc to the repo — it's just ciphertext
git add ci-secrets.enc && git commit -m "Add encrypted CI secrets"

# GitHub Actions injects the master password as a repo secret
# .github/workflows/deploy.yml:
#   env:
#     VAULT_PASSWORD: ${{ secrets.VAULT_PASSWORD }}
#   run: |
#     export AWS_ACCESS_KEY_ID=$(echo "$VAULT_PASSWORD" | vault-cli get ci-secrets.enc aws-key)
#     export AWS_SECRET_ACCESS_KEY=$(echo "$VAULT_PASSWORD" | vault-cli get ci-secrets.enc aws-secret)
#     ./deploy.sh
```

The repo contains only ciphertext. GitHub never sees plaintext secrets. The vault
file can live in the git history without risk — it was always encrypted.

---

## Summary: The Recurring Pattern

Every scenario shares the same pattern:

1. **You have secrets** (passwords, keys, tokens, phrases, IDs)
2. **You don't want them in plaintext** on disk, in cloud sync, in shell history,
   in chat messages, in `.env` files, or in browser password managers
3. **You want one file** that's useless without your master password
4. **You want a CLI** that does one thing — decrypt one record, print it, zeroize
5. **You want backups** that are as encrypted as the original

That's what this tool does. Everything else is detail.
