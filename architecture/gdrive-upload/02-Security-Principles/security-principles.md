# Section 2: Security Principles

**From:** Secret Manager — Complete Security Architecture
**Source Section:** §2

---

## 2. Security Principles

These are non-negotiable design principles that govern every subsequent architectural decision.

### P1: Zero-Knowledge by Default
The application developer never possesses any material from which plaintext can be derived. This is a property of the cryptographic architecture, not a policy.

### P2: Local-First Operation
All core functionality (unlock, create, read, update, delete, search, generate TOTP) must work without any network connection. External services are optional enhancements, never prerequisites.

### P3: Cryptographic Agility
Algorithms, key sizes, and KDF parameters must be migratable. The vault format carries versioning and algorithm identifiers so future upgrades do not require plaintext exposure.

### P4: Defense in Depth
Multiple independent layers of protection. Failure of one layer does not compromise the whole system.

### P5: Minimal Trusted Computing Base
The security-critical path (key derivation, encryption, decryption) should be implemented in as small and auditable a surface as possible.

### P6: Fail-Safe Defaults
Default settings maximize security. Security-weakening options must be explicitly opt-in.

### P7: Honest Security Claims
Marketing language must not overstate protection. Users must be informed of genuine limitations.

### P8: Cryptographic Correctness Over Convenience
When security and convenience conflict, the architecture chooses security and makes the convenience cost explicit.
