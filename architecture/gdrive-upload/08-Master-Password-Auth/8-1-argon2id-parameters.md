# 8.1 Argon2id Parameters

**Source:** §8 — Secret Manager Architecture Study

---

## 8. Master Password & Authentication

### 8.1 Argon2id Parameters

```
Function:   Argon2id
Version:    0x13 (latest)
Type:       Argon2id (mode 2 = hybrid: first pass Argon2i, rest Argon2d)
Salt:       16 bytes, cryptographically random, unique per vault
Memory:     128 MiB (desktop), 64 MiB (mobile, configurable)
Time cost:  3 iterations
Parallelism: 4 lanes (desktop), 2 lanes (mobile)
Output:     32 bytes (256 bits)
```

**Parameter rationale:**

| Parameter | Desktop | Mobile | Rationale |
|---|---|---|---|
| Memory | 128 MiB | 64 MiB | Desktop can afford 128 MiB. Mobile limited by RAM but 64 MiB feasible. |
| Time | 3 | 3 | ~1-2 seconds on modern hardware. |
| Parallelism | 4 | 2 | Matches available CPU cores. |
| Salt | 16 bytes | 16 bytes | 2^128 possible salts. Prevents precomputation. |

**Mobile adaptation:** Detect device class at vault creation. Offer presets: "Standard" (64 MiB, 2 iters), "High" (128 MiB, 3 iters), "Custom." On low-RAM devices (<4 GB), default to standard. On high-RAM devices (>8 GB), default to high.

### 8.2 Offline Password Guessing

```
Attacker obtains: encrypted vault file
Attacker can:
1. Read vault header: salt (16B), Argon2id params, wrapped VEK, nonce, tag
2. For each password guess:
   a. KEK = Argon2id(guess, salt, m, t, p)
   b. VEK = AES-GCM_Decrypt(KEK, nonce, wrapped_vek, tag, AAD)
   c. If tag fails → try next guess
   d. If tag succeeds → have KEK and VEK → full vault access
```

**Protection:** Argon2id memory hardness limits GPU parallelism. A 6-word Diceware passphrase (~78 bits) provides ~600 years of attack time at ~10,000-50,000 guesses/second on a modern GPU.

### 8.3 Honest Assessment

An attacker with a modern GPU can attempt ~10,000-50,000 passwords/second. A strong master password with 60+ bits of entropy provides ~2 years of attack time. A 6-word Diceware passphrase (~78 bits) provides ~600 years. These are practical security levels.

---
