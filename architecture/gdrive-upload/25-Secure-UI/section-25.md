# section-25

**Source:** §25 — Secret Manager Architecture Study

---

## 25. Secure UI

| Control | Implementation |
|---|---|
| Secret masking | `••••••` by default |
| Reveal timeout | Auto-mask after N seconds (default: 5s) |
| Re-authentication | Biometric/master password for sensitive records |
| Screenshot blocking | FLAG_SECURE (Android), platform equivalents |
| Notification privacy | No secret content in notifications |
| Recent-apps preview | FLAG_SECURE prevents preview |
| Copy buttons | Explicit copy with confirmation |
| Destructive actions | Confirmation dialog + re-auth |
| Lock behavior | Auto-lock after configurable timeout (default: 5 min) |

---
