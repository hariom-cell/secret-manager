# 19.1 Recovery Options

**Source:** §19 — Secret Manager Architecture Study

---

## 19. Backup & Recovery

### 19.1 Recovery Options

#### Option A: Recovery Phrase (Recommended)

- 24-word mnemonic (256 bits entropy, BIP-39-style).
- Shown ONCE during setup. User must acknowledge.
- Written down, stored offline.
- Equivalent security to master password.
- Recovery: enter phrase → Argon2id → KEK → VEK → vault recovered.

#### Option B: Shamir Secret Sharing

- Split KEK recovery material into N shares (e.g., 3 of 5).
- M-1 shares provide zero information.
- Pros: No single point of failure.
- Cons: Complex UX. User must manage trusted contacts.

#### Option C: Recovery Key File

- 256-bit random recovery key encrypted with user-provided password.
- User downloads and stores separately from vault.
- Simple. No memorization required.
- Cons: File can be lost, stolen, or damaged.

### 19.2 Recommended Architecture

All three options provided, user chooses:
1. Master password (primary)
2. Recovery phrase (backup) — shown once, user confirms recording
3. Recovery key file (alternative)

**What we CANNOT do:**
- Recover vault if ALL recovery material is lost
- Provide a backdoor recovery mechanism
- Send the user's master password via email

This is the honest cost of zero-knowledge.

---
