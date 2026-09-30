# 15.1 Protocol: X25519 + Ed25519 Envelope

**Source:** §15 — Secret Manager Architecture Study

---

## 15. No-Server Secret Sharing Protocol

### 15.1 Protocol: X25519 + Ed25519 Envelope

```
SENDER
1. Load recipient's public key
2. Generate ephemeral X25519 key pair (eph_priv, eph_pub)
3. shared_secret = X25519(eph_priv, recipient_pub_x)
4. enc_key = HKDF-SHA256(shared_secret, salt=eph_pub||recipient_pub_x, info="share-v1-enc")
5. ciphertext = XChaCha20-Poly1305_Encrypt(enc_key, nonce, plaintext)
6. signature = Ed25519_Sign(sender_priv, package_contents)
7. Assemble package: { version, eph_pub, recipient_pub_x, sender_pub_x, ciphertext, nonce, signature, expiry, one_time, package_id }
8. Transmit via WhatsApp/email/QR/etc.

RECIPIENT
1. Receive package
2. Verify recipient_pub_x matches own key (reject if not)
3. Verify Ed25519 signature (reject if invalid)
4. Check expiry (reject if expired)
5. Check one_time flag (reject if already used)
6. shared_secret = X25519(recipient_priv, eph_pub)
7. enc_key = HKDF-SHA256(shared_secret, salt=eph_pub||recipient_pub_x, info="share-v1-enc")
8. plaintext = XChaCha20-Poly1305_Decrypt(enc_key, nonce, ciphertext)
9. Present to user / store in vault
```

### 15.2 Package Format

```
Share Package (version 1) — 256 bytes fixed for small secrets:
┌─────────────────────────────────────────────────────────────────┐
│ Bytes  │ Field           │ Type      │ Description             │
├─────────────────────────────────────────────────────────────────┤
│ 0-3    │ magic           │ uint32    │ 0x53485231 ("SHR1")    │
│ 4      │ version         │ uint8     │ Protocol version        │
│ 5      │ flags           │ uint8     │ Bitfield (expiry, etc.) │
│ 6-7    │ reserved        │ uint16    │ Future use              │
│ 8-15   │ package_id      │ uint64    │ Random ID (replay)      │
│ 16-19  │ created_at      │ uint32    │ Unix timestamp          │
│ 20-23  │ expires_at      │ uint32    │ Unix timestamp (0=∞)    │
│ 24-55  │ sender_pub_x    │ 32 bytes  │ Sender X25519 pubkey    │
│ 56-87  │ recipient_pub_x │ 32 bytes  │ Recipient X25519 pub    │
│ 88-119 │ eph_pub         │ 32 bytes  │ Ephemeral X25519 pub    │
│ 120-183│ ciphertext      │ 64 bytes  │ Encrypted secret        │
│ 184-199│ nonce           │ 16 bytes  │ XChaCha20 nonce         │
│ 200-247│ nonce           │ 16 bytes  │ XChaCha20 nonce         │
│ 248-311│ signature       │ 64 bytes  │ Ed25519 signature       │
│ 312-319│ aad_hash        │ 8 bytes   │ BLAKE3 of AAD fields    │
└─────────────────────────────────────────────────────────────────┘
```

### 15.3 Security Properties

| Property | How Achieved |
|---|---|
| Confidentiality | X25519 ECDH + HKDF-derived AES key |
| Sender authentication | Ed25519 signature |
| Recipient binding | X25519 shared secret requires recipient's private key |
| Forward secrecy | Ephemeral key pair per share |
| Replay protection | Random package_id |
| Key confirmation | AAD hash verified during decryption |
| Expiry | Timestamp in package |
| One-time use | Flag + recipient-side tracking |

### 15.4 QR Code Pairing for Sharing

QR code contains: sender's X25519 + Ed25519 public keys, display name, one-time code for MITM detection. Recipient scans, verifies display name matches expected sender (out-of-band), sends response QR with their public keys.

---
