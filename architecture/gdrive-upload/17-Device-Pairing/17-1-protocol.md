# 17.1 Protocol

**Source:** §17 — Secret Manager Architecture Study

---

## 17. Device-to-Device Pairing

### 17.1 Protocol

```
DEVICE A (initiator)                  DEVICE B (responder)
1. Generate pairing ID (random 8-digit)
2. Generate Ed25519 key pair (DPK_A)
3. Display pairing code [A][B][C][D] ──────────────▶
                                              4. User confirms pairing code
5. Generate DPK_B, sign both DPKs ◀────────────── 6. Sign response with device key
7. User confirms pairing on A
8. Verify B's signature
9. Store B's DPK_B
10. Send A's DPK_A (signed) ─────────────────────▶
                                             11. Verify A's signature
                                             12. Store DPK_A
13. Paired!                                    14. Paired!
```

### 17.2 Human Verification

The 8-digit code displayed on both devices simultaneously. User compares visually or verbally. If codes match → MITM excluded. If codes don't match → abort. Same method used by Signal.

### 17.3 Post-Pairing

Paired devices can exchange encrypted vault sync packages, send encrypted secrets directly. Any device can revoke others. Revoked devices cannot decrypt future packages.

---
