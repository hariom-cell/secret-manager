# 45.1 Key Derivation

**Source:** §45 — Secret Manager Architecture Study

---

## 45. Formal Protocol Specifications

### 45.1 Key Derivation

```
K_KEK = Argon2id(
    P = master_password (UTF-8 encoded),
    S = vault_salt (16 bytes, random),
    K = NULL,
    T = 3,
    M = 128 MiB (desktop) / 64 MiB (mobile),
    p = 4 (desktop) / 2 (mobile),
    d = 1 (data-dependent, Argon2d variant),
    type = Argon2id (hybrid: Argon2i first pass, Argon2d rest)
)
Output: K_KEK (32 bytes)
```

### 45.2 VEK Encryption

```
nonce_vek = CSPRNG(12 bytes)  // AES-GCM nonce
wrapped_vek, tag_vek = AES-256-GCM_Encrypt(
    key = K_KEK,
    nonce = nonce_vek,
    plaintext = VEK (32 bytes),
    ad = AAD_VAULT = "VAULT-v1" || version || vault_salt
)
```

### 45.3 DEK Encryption (Record-Level)

```
nonce_dek = counter_nonce(record_index)  // Deterministic, unique per record
wrapped_dek, tag_dek = AES-256-GCM_Encrypt(
    key = VEK,
    nonce = nonce_dek,
    plaintext = DEK (32 bytes),
    ad = AAD_DEK = "DEK-v1" || record_type || record_id
)

nonce_payload = CSPRNG(24 bytes)  // XChaCha20 nonce
ciphertext, tag_payload = XChaCha20-Poly1305_Encrypt(
    key = DEK,
    nonce = nonce_payload,
    plaintext = record_plaintext,
    ad = AAD_RECORD = "REC-v1" || record_type || record_id
)
```

### 45.4 Sharing Key Derivation

```
// Sender side:
eph_priv = CSPRNG(32 bytes)
eph_pub = X25519(eph_priv)
shared = X25519(eph_priv, recipient_pub_x)
enc_key = HKDF-SHA256(
    ikm = shared,
    salt = eph_pub || recipient_pub_x,
    info = "share-v1-enc",
    length = 32
)
sig = Ed25519_Sign(sender_priv, 
    BLAKE3("SHR1" || eph_pub || recipient_pub_x || sender_pub_x || ciphertext))

// Recipient side:
shared = X25519(recipient_priv, eph_pub)
enc_key = HKDF-SHA256(
    ikm = shared,
    salt = eph_pub || recipient_pub_x,
    info = "share-v1-enc",
    length = 32
)
valid = Ed25519_Verify(sender_pub_x, 
    BLAKE3("SHR1" || eph_pub || recipient_pub_x || sender_pub_x || ciphertext), sig)
```

### 45.5 Pairing Key Exchange

```
// Device A (initiator):
pairing_code = CSPRNG(8)  // 8-digit decimal
dpk_a_priv, dpk_a_pub = Ed25519_KeyGen()
display_code = dpk_a_pub || pairing_code

// Device B (responder):
dpk_b_priv, dpk_b_pub = Ed25519_KeyGen()
sig_b = Ed25519_Sign(dpk_b_priv, dpk_a_pub || dpk_b_pub || pairing_code)

// Device A verifies:
valid_a = Ed25519_Verify(dpk_b_pub, dpk_a_pub || dpk_b_pub || pairing_code, sig_b)
// User confirms both devices display same pairing_code
// If valid_a and user confirms → pairing established
```

---
