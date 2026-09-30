# 16.1 Security Boundary

**Source:** §16 — Secret Manager Architecture Study

---

## 16. WhatsApp as Transport Layer

### 16.1 Security Boundary

**What WhatsApp CAN see:**
- Ciphertext (encrypted package bytes)
- Sender/recipient phone numbers
- Timestamp of message
- Delivery status

**What WhatsApp CANNOT see:**
- Plaintext secret
- Master password
- Vault key
- Sharing private key
- Shared secret (ECDH result)

**What WhatsApp provides:**
- Transport encryption (Signal Protocol)
- Delivery confirmation

**What WhatsApp does NOT provide (we handle):**
- Application-level plaintext protection
- Sender authentication (we provide Ed25519)
- Recipient authentication (we provide X25519 binding)
- Forward secrecy for sharing (we provide ephemeral keys)
- Replay protection (we provide package_id)
- Expiry enforcement (we provide timestamp)

### 16.2 WhatsApp-Specific Risks

| Risk | Severity | Mitigation |
|---|---|---|
| WhatsApp backups | Medium | Package already encrypted. Backup stores ciphertext only. |
| Message forwarding | Low | Recipient verifies sender identity regardless. |
| Screenshots | Medium | Recipient-side risk, not transport. |
| Notification previews | Low-Medium | Ciphertext in preview has no readable content. |
| Linked devices | Medium | Compromised linked device sees ciphertext only. |
| Compromised recipient device | High | Cannot protect against this. |

### 16.3 Transport Comparison

| Transport | Confidentiality | Practicality | Notes |
|---|---|---|---|
| WhatsApp | Good | Excellent | Ubiquitous. E2E transport + our encryption. |
| Signal | Better | Good | No cloud backup by default. Less widely used. |
| Email | Poor | High | Not E2E at transport. Avoid for sensitive shares. |
| SMS | Poor | High | SS7 not encrypted. Avoid entirely. |
| QR code | Excellent | Good | Physical proximity. Best for same-room. |
| NFC | Excellent | Limited range | Best for device-to-device. |
| Bluetooth | Good | Medium range | Good for local sharing. |

**Recommendation:** WhatsApp is acceptable. Our application-level encryption is independent of transport encryption. Even if WhatsApp's encryption fails, the share package is protected by X25519 + AES.

**Honest limitations:** Cannot prevent recipient's device being compromised, recipient taking screenshots, or recipient forwarding plaintext after decryption.

---
