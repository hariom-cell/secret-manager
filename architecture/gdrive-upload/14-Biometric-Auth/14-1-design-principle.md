# 14.1 Design Principle

**Source:** §14 — Secret Manager Architecture Study

---

## 14. Biometric Authentication

### 14.1 Design Principle

**Biometric authentication is a convenience gating mechanism. It is NOT the vault encryption key.**

Biometric templates are:
- Not secrets (fingerprint/face is left everywhere).
- Not consistent (fingerprints change, face ages).
- Not revocable (cannot get a new fingerprint).

### 14.2 Correct Biometric Flow

```
Step 1: User touches fingerprint / looks at face
Step 2: OS Secure Hardware validates biometric (TEE / Secure Enclave)
Step 3: TEE/SE authorizes use of hardware-backed private key
Step 4: Application receives authorization token / key use
Step 5: Application decrypts cached KEK using DUK
Step 6: Application decrypts VEK from cached KEK
Step 7: Vault is unlocked. Session begins.

What biometrics UNLOCK:
✓ A cached, KEK-encrypted key wrapper
✗ The master password
✗ The VEK directly
✗ The vault encryption process
```

### 14.3 Why Not Direct Biometric Keys?

**Hypothetical (DO NOT implement):** Use biometric template hash as KEK.
- Fingerprint changes → KEK changes → vault inaccessible.
- Biometric data is not secret → anyone with fingerprint can derive KEK.
- No revocation possible.

### 14.4 Biometric Change Handling

| Event | Action |
|---|---|
| Fingerprint added | No action (additional fingerprint) |
| Fingerprint removed | No action (remaining fingerprints work) |
| All fingerprints removed | Biometric unlock disabled. Master password still works. |
| Face data reset | Biometric unlock disabled. Master password still works. |

### 14.5 Hardware-Backed vs Software-Backed

| Scenario | Behavior |
|---|---|
| StrongBox / Secure Enclave | Hardware-backed DUK. Biometric unlock enabled. |
| TEE only | TEE-backed DUK. Biometric enabled with warning. |
| Software-backed only | Disable biometric unlock. Master password only. Warn user. |
| Rooted / compromised TEE | Disable biometric unlock. Master password only. |

---
