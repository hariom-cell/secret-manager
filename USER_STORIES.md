# Secret Manager — User Stories

The story of how someone goes from "I'm drowning in passwords and tokens" to
"this is my daily driver" — step by step, with the exact moments of doubt,
struggle, and "aha."

---

## Story 1: "I Don't Even Know What I'm Doing Wrong"

### Day 0: The Wake-Up Call

Priya is a junior backend developer, 6 months into her first job. She's been
saving credentials in a `notes.txt` file on her desktop. Yesterday she
accidentally committed `notes.txt` to the company repo. Her manager pulled
her aside.

> "You need to learn to manage secrets properly. You're using AWS keys in
> commit messages. The security team noticed."

Priya goes home. She opens her laptop. She has a list of credentials she
needs:

- 2 AWS IAM access keys
- 1 AWS secret key
- PostgreSQL staging password
- GitHub personal access token (for the company GitHub org)
- Stripe test API key
- SendGrid API key
- Slack bot token

All in `notes.txt`. About to be nuked. She needs a place to put them.

### Day 1: Discovery — "What Are My Options?"

She googles "how to store credentials securely". The results:

- **1Password / LastPass / Bitwarden** — cloud-based, monthly fee, syncs
  across devices
- **HashiCorp Vault** — server, complicated setup
- **Mac Keychain** — works only on Mac, not great for server secrets
- **Encrypted file with GPG** — works but hard to use in scripts
- **This Secret Manager (vault-cli)** — single binary, encrypts a file on
  disk, zero-knowledge, no server

She reads the README. It sounds like what she wants. No cloud. No subscription.
A file. A password.

### Day 1, Evening: "OK, Let Me Try This"

She opens her terminal.

```bash
$ cargo build --release --bin vault-cli
# Compiling... finished in 30 seconds
$ ls target/release/vault-cli
-rwxr-xr-x  1 priya  staff  361K Sep 30 22:14 vault-cli
```

She runs it:

```bash
$ ./target/release/vault-cli
# Prints help
```

Wait — she needs to install it system-wide first.

```bash
$ cp target/release/vault-cli /usr/local/bin/secret-manager
$ secret-manager help
# All commands listed
```

OK. Now the real test — create a vault.

```bash
$ secret-manager create ~/vault/work.enc
Master password: ********
Confirm password: ********
Vault created at: /Users/priya/vault/work.enc
```

It worked. She opens the file in a hex viewer:

```
00000000  56 4c 54 31  00 01 00 00  00 01 00 00  00 00 00 03
00000010  00 00 00 04  c4 18 a3 1b  ...            ... (256-byte header)
```

Just ciphertext. Magic bytes `VLT1`. The rest is opaque.

> **Priya's thought:** "OK, it's a real file. It's not plaintext. Good."

### Day 1, Late Night: Migrating Her Credentials

She opens `notes.txt` and starts moving records. One by one.

```bash
$ secret-manager set ~/vault/work.enc 00112233445566778899aabbcceeff00 "AKIA..."
Master password: ********
Record stored.

$ secret-manager set ~/vault/work.enc 11112222333344445555666677778888 "abc123def456..."
Master password: ********
Record stored.

# ... continues for 20 minutes
```

She has a question: "Should I use a record ID like `aws-key-1`?" Let me check.

```bash
$ secret-manager get ~/vault/work.enc 00112233445566778899aabbcceeff00
Master password: ********
AKIA...
```

Wait — record IDs are 32-char hex. She has to come up with her own naming
convention. She writes it down in her head:

- `0011...` = aws-access-key
- `1111...` = aws-secret-key
- `2222...` = postgres-staging-pass
- ...

That's painful. She goes to the README again and finds a note:
> Record IDs are hex strings (32 hex chars = 16 bytes).

OK so she can use any hex. She generates IDs using her own pattern. Actually,
let me think about this — there's no command for generating a record ID. She
has to manually type 32 hex chars or use something else.

> **Priya's thought:** "Hmm, 32 hex chars is annoying to type. Let me make a
> small script to generate them."

She writes a quick function:

```bash
gen_id() {
  vault-cli gen-pass 16 | tr -d -c 'a-f0-9' | head -c 32
}

# Now: 
$ secret-manager set ~/vault/work.enc "$(gen_id)" "AKIA..."
```

Better. She moves on.

### Day 2: First Real Use — SSH Login to a Server

She needs to SSH into a new server. The password is in her vault.

```bash
$ secret-manager get ~/vault/work.enc 33334444555566667777888899990000 | pbcopy
Master password: ********
# paste into ssh prompt
$ ssh root@new-server
```

Worked. She's hooked.

### Day 2, Afternoon: The First Problem

Her deploy script needs an AWS key. She can't use `pbcopy` in a script — the
script needs the value, not a copy in the clipboard.

```bash
# In her deploy.sh:
AWS_ACCESS_KEY_ID=$(secret-manager get ~/vault/work.enc 00112233445566778899aabbcceeff00)
# Wait — this prompts for the master password. The script will hang.
```

She reads the help again. There's a `--password-stdin` flag? No. She reads the
README. No mention.

> **Priya's thought:** "Ugh. Now I need to type the password every time the
> script runs."

She looks at the code in `crates/vault-cli/src/main.rs`. She sees that
`prompt_password()` reads from stdin. She tries:

```bash
$ echo "mypassword" | secret-manager get ~/vault/work.enc 00112233445566778899aabbcceeff00
Master password:
# Empty — the prompt already printed
# Hmm, no output. Why?
```

Oh — `prompt_password` prints `Master password: ` and then reads stdin. But
the stdin was already consumed by the `echo` before the program started.
Actually wait, that's not right — pipe should work.

She tries with a newline:

```bash
$ printf 'mypassword\n' | secret-manager get ~/vault/work.enc 00112233445566778899aabbcceeff00
Master password:
# Output appears!
AKIA...
```

OK, that works. She updates her deploy script:

```bash
# Add to .bashrc / .zshrc:
export VAULT_PASSWORD="mypassword"  # Or read from keychain / etc
# In deploy.sh:
export VAULT_PASSWORD
AWS_ACCESS_KEY_ID=$(secret-manager get ~/vault/work.enc 00112233445566778899aabbcceeff00)
```

That's still not ideal — the password is in an env var. But for a personal
script, it's fine.

> **Priya's thought:** "OK, this works. But putting the master password in an
> env var feels wrong. Maybe I should look for a way to use the macOS Keychain
> as the master."

She files an issue: `vault-cli get` should support `--password` flag for
scripting. The author (you) adds it in the next release.

### Day 3: Password Rotation — A Real Use Case

AWS sends an email: "Your access key is 90 days old. Please rotate."

She generates a new key in the IAM console, then:

```bash
$ secret-manager set ~/vault/work.enc 00112233445566778899aabbcceeff00 "AKIA_NEW_KEY"
Record stored.

# Update her CI config to use the same record ID — no change needed
# Update her scripts — they pull from the vault by ID, no change needed
```

Done in 30 seconds.

### Day 4: The Incident

Her laptop is on her desk. She walks away to get coffee. Comes back. Someone
(nobody — but let's say a coworker at a coffee shop) might have looked at
her screen. She panics.

She runs `secret-manager lock`:

```bash
$ secret-manager lock
Vault locked.
```

Wait — it just prints "Vault locked" but doesn't do anything. She reads the
help again.

> The vault is stateless — every command opens, decrypts, operates, and exits.
> Lock is a no-op in single-shot CLI — the vault is never held open.

OK so the CLI doesn't have a session. The vault file is encrypted on disk. If
someone copies the file while she's away, they get ciphertext. They'd need
the master password to decrypt it. She breathes.

> **Priya's thought:** "OK, so the design is actually secure by default.
> Nothing's open. I just need to not type my master password in front of
> people."

### Day 7: A Backup

She buys a small USB drive. Encrypted backup:

```bash
$ secret-manager export ~/vault/work.enc /Volumes/USB/backups/work-2024-12.enc
Master password: ********
Backup exported to: /Volumes/USB/backups/work-2024-12.enc
```

The USB drive is small. She keeps it in her drawer. If her laptop dies, she
can restore from this.

### Day 14: The Day She Realizes This Is Better Than 1Password

She adds a new service to her workflow — a staging environment password that
rotates weekly. With 1Password, she'd:
1. Open 1Password
2. Search for the password
3. Copy it
4. Paste it
5. Manually update 1Password when it rotates

With vault-cli:
```bash
# Get the current one
$ secret-manager get ~/vault/work.enc 4444555566667777888899990000aaaa

# Rotate
$ secret-manager set ~/vault/work.enc 4444555566667777888899990000aaaa "$(vault-cli gen-pass 24)"
```

Faster. More direct. No UI. No sync lag.

### Day 30: The Day She Tells Her Team

Her team has 4 other developers. They have the same problem. She proposes a
shared vault.

> "We could each have a vault. The CI uses one specific vault. Personal
> credentials stay in personal vaults."

She sets up a CI vault:

```bash
$ secret-manager create ~/vault/ci.enc
# Stored in repo at .ci/secrets.enc — encrypted, looks like binary
# Master password in GitHub repo secret as VAULT_PASSWORD
```

In the GitHub Actions workflow:

```yaml
- name: Deploy
  env:
    VAULT_PASSWORD: ${{ secrets.VAULT_PASSWORD }}
  run: |
    export AWS_KEY=$(echo "$VAULT_PASSWORD" | ./vault-cli get .ci/secrets.enc aabbccdd)
    ./deploy.sh
```

The team adopts it. They each have personal vaults. The CI has its own.
Shared services go in CI's vault.

> **Priya's thought:** "We started with my messy notes.txt. Now the whole
> team has proper secret management. Zero cloud. Zero cost. Zero trust in
> third parties."

---

## Story 2: "I'm Setting This Up For My Family"

Raj is the family tech support. His parents, his wife, his sister — they all
ask him for passwords. He keeps getting pulled out of work to "fix" something.

### Setup

He creates one vault per family member. He keeps them on his laptop and on a
shared encrypted NAS.

```bash
$ secret-manager create ~/vault/family/mom.enc
Master password: ********  # He gives this to his mom verbally

$ secret-manager create ~/vault/family/dad.enc
Master password: ********

$ secret-manager create ~/vault/family/sister.enc
Master password: ********
```

For each, he pre-populates common passwords:

```bash
$ secret-manager set ~/vault/family/mom.enc mom-gmail "..."
$ secret-manager set ~/vault/family/mom.enc mom-bank "..."
$ secret-manager set ~/vault/family/mom.enc mom-facebook "..."
$ secret-manager set ~/vault/family/mom.enc mom-netflix "..."
```

He exports each one:

```bash
$ secret-manager export ~/vault/family/mom.enc /Volumes/FamilyUSB/mom-vault.enc
```

The USB drives to mom. Mom can now:

```bash
$ secret-manager get /Volumes/USB/mom-vault.enc mom-gmail
Master password: ********
# Prints her Gmail password
```

### Ongoing Support

His mom calls: "I forgot the Facebook password."

Raj: "OK, plug in the USB. Open Terminal. Type `secret-manager get ~/Volumes/USB/mom-vault.enc mom-facebook`. Type your master password. There's the password."

Mom: "What's Terminal?"

Raj: *(sighs, drives to her house)*

After he gets there, he types it for her. Mom copies the password. Raj updates
the vault with the new password.

> **Raj's thought:** "I wish this had a GUI for non-technical users."

He files an issue: Web app / GUI needed. The author builds one with WASM.

Six months later, mom opens `secret-manager.app`, types her master password,
clicks "Facebook", sees the password. Raj can stop driving over.

---

## Story 3: "I'm Building a Product With This"

Sasha is building a SaaS dashboard. Customers have API keys they paste into the
dashboard. Sasha needs to store them securely.

### Phase 1: The First Customer

Sasha builds the dashboard in Next.js. Customers paste their API keys. She
needs to encrypt them server-side.

```typescript
// Don't do this — she's a JS dev
const apiKey = req.body.apiKey;
await db.insert({ userId, apiKey });  // PLAINTEXT — TERRIBLE
```

She finds Secret Manager. It's a Rust library.

```toml
# Cargo.toml of her backend
[dependencies]
vault-core = { path = "../secret-manager/crates/vault-core" }
vault-db = { path = "../secret-manager/crates/vault-db" }
```

```rust
use vault_core::Vault;
use vault_db::VaultFile;

async fn store_customer_key(user_id: &str, api_key: &str) -> Result<()> {
    let path = format!("/var/lib/dashboard/{user_id}.enc");
    let vault = Vault::create("master-passphrase-for-this-user")?;
    vault.add_secret(/* record id */, api_key.as_bytes())?;
    // Persist to disk
    Ok(())
}

async fn retrieve_customer_key(user_id: &str, record_id: &[u8; 16]) -> Result<String> {
    let path = format!("/var/lib/dashboard/{user_id}.enc");
    let mut vf = VaultFile::open(path)?;
    vf.unlock("master-passphrase-for-this-user")?;
    let value = vf.get_secret(*record_id)?;
    Ok(String::from_utf8(value)?)
}
```

Every customer gets their own vault file. The master passphrase is derived
from their login session. The API key never hits the database in plaintext.

### Phase 2: Compliance

Her company gets acquired. The acquirer wants SOC 2 compliance. They ask
"How are customer API keys encrypted at rest?"

Sasha points to:
- `vault-core/CHANGELOG.md` — documents the algorithm
- `vault-core/tests/integration.rs` — proves it works
- `vault-core/src/kdf.rs` — Argon2id parameters documented
- `vault-core/src/format.rs` — file format documented

The auditor approves. The company continues to use Secret Manager as the
encryption layer.

### Phase 3: Scale

10,000 customers. 10,000 vault files. Performance:
- Vault creation: ~300ms (Argon2id is intentionally slow)
- Unlock: ~200ms
- Get record: <1ms (HMAC verification + XChaCha decrypt)

She batches vault creations in background workers. Customers don't notice.
Compliance is maintained. The data is safe.

> **Sasha's thought:** "I embedded a $50,000 product (HashiCorp Vault) into my
> SaaS for free. That's $500K over 10 years."

---

## Story 4: "I'm a Privacy Advocate"

Kai runs a privacy blog. They don't trust cloud password managers. They write
an article: "Why I Use Local-Only Encrypted Vaults."

### The Setup

```bash
# Personal vault
$ secret-manager create ~/vault/personal.enc

# Family vault (separate from personal)
$ secret-manager create ~/vault/family.enc

# PGP / GPG alternative vault — for keys that would have gone in GPG
$ secret-manager create ~/vault/pgp.enc
```

### The Backup Strategy

```bash
# Daily cron — exports to encrypted USB + offline NAS
0 3 * * * /usr/local/bin/secret-manager export /Users/kai/vault/personal.enc /Volumes/USB/daily.enc
0 4 * * 0 /usr/local/bin/secret-manager export /Users/kai/vault/personal.enc /Volumes/NAS/weekly.enc
```

### The Sharing Story

Kai wants to share a secret with their partner (joint account password).
They use the `sharing` module:

```rust
// Encrypt the DEK under the partner's X25519 public key
// Store the encrypted share
// Partner decrypts with their private key
```

Kai writes a CLI command for it: `vault-cli share <vault> <record-id> <recipient-pubkey>`.

> **Kai's thought:** "I can share a single secret with one person without
> sharing my master password. That's the killer feature."

---

## Story 5: "I Built This For Myself"

You're the developer of this tool. You use it daily.

### Morning

```bash
$ secret-manager get ~/.vault/personal.enc personal-gmail | pbcopy
# Login to Gmail
```

### Mid-Morning

```bash
$ ssh root@home-server "cat /etc/shadow" | secret-manager set ~/.vault/homelab.enc /etc/shadow-$(date +%s)
# Backup of server shadow file
```

### Afternoon

```bash
# Working on a new service
$ vault-cli gen-pass 32
new-service-32char-password
$ secret-manager set ~/.vault/personal.enc new-service "$(vault-cli gen-pass 32)"
$ ssh root@new-server "echo '$(secret-manager get ~/.vault/personal.enc new-service)' | passwd serviceuser"
```

### Evening

```bash
# Going to bed. Backup.
$ secret-manager export ~/.vault/personal.enc /Volumes/USB/$(date +%Y-%m-%d).enc
$ secret-manager export ~/.vault/work.enc /Volumes/USB/work-$(date +%Y-%m-%d).enc
```

### Years Later

You still use it. The format hasn't changed. The file from 5 years ago still
opens with the latest binary. Your master password is the same. Your data is
intact. Zero cloud breaches. Zero subscription renewals. Zero data migrations.

> **Your thought:** "I built the thing I needed. It's still working."

---

## The Recurring Arc

Every story has the same arc:

1. **The problem** — credentials scattered, in plaintext, in cloud services
2. **The discovery** — "There's a CLI that encrypts a file"
3. **The setup** — 5 minutes to install, 5 minutes to create a vault, 30 minutes to migrate
4. **The friction** — record IDs are 32 hex chars (annoying), passwords prompt every command (annoying)
5. **The workarounds** — generate IDs with a script, use env var for CI, write a wrapper
6. **The adoption** — every command becomes muscle memory
7. **The realization** — "I haven't typed a password in a notes app in 6 months"
8. **The evangelism** — "You should use this too"

That's the user journey. It's not glamorous. It's just someone solving their
own problem, day by day, until the problem is gone.
