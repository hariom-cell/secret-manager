# section-4

**Source:** §4 — Secret Manager Architecture Study

---

## 4. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                     TRUSTED BOUNDARY                             │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              SECRET MANAGER APPLICATION                    │  │
│  │  ┌────────────┐  ┌──────────────┐  ┌──────────────────┐   │  │
│  │  │   Crypto   │  │   Vault      │  │   UI /           │   │  │
│  │  │   Engine   │  │   Manager    │  │   Autofill       │   │  │
│  │  └────────────┘  └──────────────┘  └──────────────────┘   │  │
│  │       │                │                  │                │  │
│  │  ┌────┴────────────────┴──────────────────┴───────┐        │  │
│  │  │           Platform Secure Storage                │        │  │
│  │  │  (Keystore / Keychain / DPAPI / Secret Service)  │        │  │
│  │  └──────────────────────────────────────────────────┘        │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                              │                                    │
│                ┌─────────────┴──────────────┐                    │
│                ▼                             ▼                    │
│  ┌──────────────────────┐    ┌──────────────────────────┐        │
│  │   USER INPUT         │    │  EXTERNAL TRANSPORT        │        │
│  │  (master pw,         │    │  (WhatsApp, Signal, QR,    │        │
│  │   biometrics)        │    │   NFC, Bluetooth)          │        │
│  └──────────────────────┘    └──────────────────────────┘        │
│                                    │  TRUSTED FOR TRANSPORT ONLY  │
│                                    │  Never trusts plaintext      │
│                                    ▼                               │
│  ┌───────────────────────────────────────────────────────────┐    │
│  │  OPTIONAL CLOUD (Sync server)                             │    │
│  │  Sees only encrypted packages. Cannot derive keys.        │    │
│  └───────────────────────────────────────────────────────────┘    │
│                        UNTRUSTED BOUNDARY                         │
└───────────────────────────────────────────────────────────────────┘
```

**Trust boundary rules:**
1. Everything inside the application boundary is trusted. Everything outside is untrusted.
2. Platform secure storage is a trusted boundary extension — we delegate key storage to the OS.
3. External transports carry ciphertext only. Trusted for delivery, not confidentiality.
4. The optional sync server is trusted for availability and conflict resolution only. Never trusted for confidentiality.
5. User input enters the trust boundary at the application layer and is immediately consumed for key derivation — never persisted.

---
