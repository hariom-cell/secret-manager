# 41.1 Identified Anti-Patterns

**Source:** §41 — Secret Manager Architecture Study

---

## 41. Security Theater Avoidance

### 41.1 Identified Anti-Patterns

#### ❌ "Multiple Encryption Layers"

**Claim:** "We encrypt the data three times with three different keys for triple protection."

**Reality:** Properly implemented single-layer encryption with a strong key is not weakened by adding more encryption layers. Triple encryption does not meaningfully increase security but increases complexity, attack surface, and the chance of implementation errors. It also creates a false sense of security.

**Verdict:** DO NOT implement. One well-implemented layer with a strong key is sufficient.

#### ❌ "Proprietary Cryptography"

**Claim:** "Our custom encryption algorithm is unbreakable because it's secret."

**Reality:** Kerckhoffs's Principle: a cryptographic system should be secure even if everything about the system is public knowledge except the key. Proprietary algorithms are universally weaker than public, peer-reviewed algorithms.

**Verdict:** DO NOT implement. Use only standard, peer-reviewed algorithms.

#### ❌ "Hiding/Renaming Encrypted Files"

**Claim:** "We hide the vault file with a random name to protect it."

**Reality:** Security through obscurity. An attacker with file system access can find the vault file by scanning for magic bytes or known patterns. The encryption protects the data; the filename does not.

**Verdict:** DO NOT rely on. File naming is irrelevant when data is properly encrypted.

#### ❌ "Biometrics as Encryption Keys"

**Claim:** "Your fingerprint IS your encryption key."

**Reality:** As discussed in §14, biometrics are not secrets, are not consistent, and are not revocable. Using biometrics directly as encryption keys creates security vulnerabilities and usability problems.

**Verdict:** DO NOT implement. Biometrics are a convenience gating mechanism for hardware-backed key release.

#### ❌ "Pretending Screenshot Blocking is Absolute"

**Claim:** "Our app prevents all screenshots."

**Reality:** FLAG_SECURE prevents screenshots from the OS, but cannot prevent:
- Physical cameras photographing the screen
- Rooted devices bypassing FLAG_SECURE
- Screen recording on some platforms
- Memory forensics

**Verdict:** Implement screenshot blocking as a mitigation, but never claim it is absolute. Be honest about limitations.

#### ❌ "Pretending WhatsApp Transport Encryption Protects Plaintext"

**Claim:** "WhatsApp's end-to-end encryption keeps your secrets safe."

**Reality:** WhatsApp's encryption protects the transport channel. Our application-level encryption protects the secret content. These are independent layers. WhatsApp cannot protect our application's plaintext — we must do that ourselves.

**Verdict:** Implement our own encryption regardless of transport. Never rely on transport encryption for application-level security.

#### ❌ "Password Complexity Requirements That Don't Help"

**Claim:** "Passwords must contain uppercase, lowercase, numbers, and special characters."

**Reality:** NIST SP 800-63B explicitly advises against composition rules. They reduce entropy by forcing predictable patterns and don't significantly improve security. Length and entropy matter, not character class diversity.

**Verdict:** Show entropy estimate. Recommend passphrases. No composition rules.

#### ❌ "Security by Obfuscation"

**Claim:** "Our code is obfuscated so attackers can't reverse engineer it."

**Reality:** Security through obscurity does not protect against determined reverse engineering. The cryptographic design must be secure even when fully understood (Kerckhoffs's Principle). Obfuscation may slow down attackers slightly but does not provide real security.

**Verdict:** Obfuscation is fine as a minor additional barrier. Never rely on it as a primary security measure. Security must come from the cryptographic design.

---
