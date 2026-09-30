# Secret Manager — Real-Time Scenarios

These are the moments you'd actually use this tool — not quarterly rotations,
not planned deployments, but the random Tuesday moments where you need a secret
right now.

---

## Scenario 1: 2:14 PM — You Need an SSH Key Passphrase

You're setting up a new remote server. The `ssh-keygen` just asked you to create
a passphrase. You have 3 seconds before you lose focus.

```bash
# Generate a strong passphrase instantly
$ vault-cli gen-pass 32
xK#9mP2vL5nQ8rT1wY4zA7bD0cF6gH3j

# Use it as your SSH key passphrase
# It never touches a notes app, a Slack message, or a password manager
# You remember it because you just generated it
```

Or if you already have a passphrase and need to retrieve it:

```bash
$ vault-cli get ~/.config/secret-manager/vault.enc ssh-github-key-pass
Master password: ********
xK#9mP2vL5nQ8rT1wY4zA7bD0cF6gH3j
```

The value prints to your terminal. You paste it. It's gone from your screen in
a second. No cloud sync, no browser autofill, no notes app involved.

---

## Scenario 2: 4:30 PM — Deploy Script Is Failing Because of a Wrong Password

Your deploy script is failing. The database password it's using is wrong. You
swapped it last week but forgot to update the deploy config.

```bash
# Check what's currently in the vault
$ vault-cli list ~/.config/secret-manager/vault.enc
Master password: ********
prod-db-user
prod-db-pass
prod-db-host
prod-redis-url

# Get the current password
$ vault-cli get ~/.config/secret-manager/vault.enc prod-db-pass
Master password: ********
NewPassw0rd!2024

# Oh — it was rotated last week. Update the deploy config.
$ sed -i '' 's/DB_PASS=.*/DB_PASS="'"$(vault-cli get ~/.config/secret-manager/vault.enc prod-db-pass)"'"/' deploy.sh

# Verify it works
$ ./deploy.sh dry-run
Connected to database: ✓
Deploy successful.
```

---

## Scenario 3: 5:45 PM — Your Pair-Programming Partner Needs the Staging URL

Your teammate asks for the staging environment credentials. They need to
reproduce a bug. Instead of DMing them the password (which goes into Slack's
cloud forever):

```bash
# List what staging records exist
$ vault-cli list ~/.config/secret-manager/vault.enc
...
staging-url
staging-user
staging-pass
staging-db-pass

# Read them out loud or paste them in a 1-on-1 call
$ vault-cli get ~/.config/secret-manager/vault.enc staging-url
$ vault-cli get ~/.config/secret-manager/vault.enc staging-user
$ vault-cli get ~/.config/secret-manager/vault.enc staging-pass

# Or send the vault file (encrypted) and tell them the master password verbally
$ scp ~/.config/secret-manager/vault.enc teammate@laptop:/tmp/
# Tell them the password in person / phone call / Signal
```

The vault file in transit is ciphertext. The password shared verbally can't be
replayed from a server log.

---

## Scenario 4: 7:00 PM — Switching Between Personal and Work Contexts

You work on personal projects after hours. You need different vaults for
personal and work secrets. No mixing.

```bash
# Personal vault — your personal GitHub, crypto wallet, personal email
$ vault-cli create ~/vault/personal.enc
Master password: ******** (different password from work vault)

# Work vault — company AWS, staging DB, internal tools
$ vault-cli create ~/vault/work.enc
Master password: ********

# Morning: use work vault
$ vault-cli get ~/vault/work.enc aws-access-key
Master password: ********

# Evening: switch to personal
$ vault-cli get ~/vault/personal.enc crypto-wallet-seed
Master password: ********

# Two passwords, two vaults, zero overlap. If one vault file is leaked,
# the other is unaffected.
```

---

## Scenario 5: 9:00 PM — Emergency: Server Is Down, You Need the Root Password

Your self-hosted server at home just went down. The IP is `192.168.1.50`.
You need the root password to SSH in and debug. You're at a friend's house
on their laptop. You have your vault file backed up on a USB drive.

```bash
# Plug in USB, copy the vault file
$ cp /Volumes/USB/vault-backup.enc /tmp/

# Import it
$ vault-cli import /tmp/vault-backup.enc
Master password: ********
Backup version:    1
KDF m_cost:        65536
KDF t_cost:        3
KDF p_cost:        4
Records in backup: 47
Backup verified. VEK recovered. 47 record(s).

# Get the root password
$ vault-cli get /tmp/vault-backup.enc homelab-root-pass
Master password: ********
R0otP@ss!2024

# SSH in, fix the issue
$ ssh root@192.168.1.50

# When done — delete the imported vault from the friend's machine
$ rm /tmp/vault-backup.enc
# Zeroized from memory when the process exited
```

---

## Scenario 6: 11:00 PM — You Forgot a Password Mid-Browser-Refresh

You're logging into your router admin panel. The password was rotated 6 months
ago. You don't remember the current one. The router is your home network's
gateway — if you factory reset, you lose all connected devices' settings.

```bash
# Check if it's in your vault
$ vault-cli list ~/.config/secret-manager/vault.enc
...
router-admin-url
router-admin-pass

# Get it
$ vault-cli get ~/.config/secret-manager/vault.enc router-admin-pass
Master password: ********
RtP@ss_N3w!

# Paste into browser, log in, and update to something you'll actually remember
# Then update the vault
$ vault-cli set ~/.config/secret-manager/vault.enc router-admin-pass "RtP@ss_Final!"
Record stored.
```

---

## Scenario 7: Midnight — Writing a Script That Needs a Token

You're writing a bash script that needs to call the GitHub API. The script
will be in your dotfiles repo. You can't hardcode the token.

```bash
#!/bin/bash
# ~/.local/bin/gh-issues.sh

# Pull token from vault at runtime — never in the script, never in history
GH_TOKEN=$(vault-cli get ~/.config/secret-manager/vault.enc gh-pat)
curl -s -H "Authorization: token $GH_TOKEN" \
  "https://api.github.com/repos/me/myproject/issues?state=open"

# Unset from environment
unset GH_TOKEN
```

The script is clean. The token is never in the script file, never in git
history, never in shell history (if you use `set +o history` or single quotes).

---

## Scenario 8: 11:00 AM Next Day — Someone Asks for the Database Password

A junior dev on your team pings you: "What's the staging DB password? I need
to run a migration." You don't want to paste it in Slack.

```bash
# Option A: Pull it and read it out loud on a call
$ vault-cli get ~/.config/secret-manager/vault.enc staging-db-pass
Master password: ********
St@g1nDB_P@ss_2024!

# Option B: Share the vault file + give them the password in person
$ scp ~/.config/secret-manager/vault.enc junior-dev@laptop:/tmp/
# Tell them the master password at their desk

# Option C (best for one-time): Derive a sharing envelope
# (sharing module in vault-core — encrypt a single record for their public key)
```

The password never goes through Slack's servers, never appears in your chat
history, never gets indexed by your company's DLP tool.

---

## Scenario 9: 3:00 PM — You're Moving to a New Laptop

You're migrating from your old Mac to a new one. You need to move your vault.

```bash
# On old Mac: export the vault
$ vault-cli export ~/.config/secret-manager/vault.enc ~/Desktop/backup-transfer.enc
Master password: ********
Backup exported to: /Users/me/Desktop/backup-transfer.enc

# Transfer via AirDrop / USB / scp — the file is encrypted
# On new Mac:
$ scp backup-transfer.enc new-mac:/tmp/

# Install vault-cli on new Mac
$ brew install secret-manager
# (or build from source)

# Import
$ vault-cli import /tmp/backup-transfer.enc
Master password: ********
# Full vault restored with all 47 records

# Verify
$ vault-cli list ~/.config/secret-manager/imported.enc
Master password: ********
aws-access-key
aws-secret-key
...
```

Zero downtime. No cloud account needed. The transfer file is useless without
the master password.

---

## Scenario 10: 6:00 PM — Quick Password Audit Before a Vacation

You're about to go on a 2-week trip. You want to make sure you haven't missed
any service accounts or that old credentials aren't floating around.

```bash
# List everything in your vault
$ vault-cli list ~/.config/secret-manager/vault.enc
Master password: ********
aws-access-key
aws-secret-key
prod-db-user
prod-db-pass
prod-redis-url
staging-db-user
staging-db-pass
github-pat
npm-token
dockerhub-token
cloudflare-api-token
s3-backup-key
personal-gmail
personal-coinbase-seed
router-admin-pass
pihole-admin-pass
...

# 23 records. For each one, ask: "Do I still need this?"
# For the ones you don't:
$ vault-cli delete ~/.config/secret-manager/vault.enc old-client-cpanel-pass
Record deleted.

# For ones that need rotating:
$ vault-cli set ~/.config/secret-manager/vault.enc github-pat "$(vault-cli gen-pass 40)"
Record stored.

# Export a clean backup before leaving
$ vault-cli export ~/.config/secret-manager/vault.enc /tmp/pre-trip-backup.enc
```

---

## Scenario 11: 10:00 PM — You're Debugging a Production Issue at 2 AM

Your on-call phone just buzzed. Production is down. You need the database
connection string and the Redis URL. You're half-asleep. The ops team's
Slack channel is noisy. You need the credentials fast.

```bash
# One command to get both
$ DB_URL=$(vault-cli get ~/.config/secret-manager/vault.enc prod-db-url)
$ REDIS_URL=$(vault-cli get ~/.config/secret-manager/vault.enc prod-redis-url)

# Run your diagnostic
$ ./diagnose.sh "$DB_URL" "$REDIS_URL"

# Found it — it's a connection pool exhaustion. Restart the pool.
# Zeroize
$ unset DB_URL REDIS_URL
```

No Slack searching. No 1Password unlock + search + copy + paste. Two commands,
diagnose done, keys zeroized.

---

## Scenario 12: The "Oops" Moment — You Piped a Password Into the Wrong Command

You typed `vault-cli set` but pointed it at a test vault instead of production.
You just overwrote a production record with a test value.

```bash
# Undo: the previous version is gone from disk...
# But if you have the backup from your nightly export:
$ vault-cli import /Volumes/USB/nightly-backup.enc prod-vault.enc
Master password: ********
# Restored from backup. Good — you automated that backup, right?

# Lesson: set up a cron job
$ (crontab -l; echo "0 2 * * * vault-cli export ~/.config/secret-manager/vault.enc /Volumes/USB/nightly.enc") | crontab -
```

---

## The Pattern Across All of These

1. **A moment arises** — you need a credential, right now
2. **One command** — `vault-cli get <vault> <record-id>` — asks for your master
   password, decrypts, prints, zeroizes
3. **Done** — the secret was never in a notes app, never in Slack, never in
   your browser's password manager, never in a `.env` file on disk
4. **Memory is clean** — all keys zeroized on process exit

That's the real-time value. It's not about grand security policies. It's about
having a tool that's fast enough to use when you actually need it, and secure
enough that using it is better than the alternatives.
