# 22.1 Android Autofill

**Source:** §22 — Secret Manager Architecture Study

---

## 22. Autofill Architecture

### 22.1 Android Autofill

```kotlin
class SecretManagerAutofillService : AutofillService() {
    override fun onFillRequest(request: FillRequest, callback: FillResponseCallback) {
        // 1. Get autofill field context
        // 2. Verify domain matches saved URL
        // 3. Present credentials to user for selection
        // 4. Fill response with credential data
    }
}
```

**Security controls:**
1. **Domain verification:** Match requesting app's domain against stored URLs. Mismatch → warn.
2. **User confirmation:** Never silently autofill.
3. **Save prompt:** Prompt user to save new credentials with preview.
4. **Category filtering:** Only autofill passwords on login forms, credit cards on payment forms.

### 22.2 Desktop Autofill

- Manifest V3 browser extension (Chrome/Firefox/Edge).
- Native Messaging Host communicates with desktop app.
- Desktop app decrypts credentials, sends to extension.
- Extension injects into page.

### 22.3 Anti-Phishing

| Attack | Protection |
|---|---|
| Domain mismatch | Compare against stored URL. Mismatch → warn. |
| Subdomain attack | `evil.example.com` vs `example.com` → different domains |
| IDN/punycode | Convert IDN to Unicode. Detect homoglyphs. |
| Deceptive URLs | Warn on unexpected TLD or suspicious patterns. |
| HTTP sites | Warn when autofilling on non-HTTPS. |

---
