# 5.1 Primitive Selection

**Source:** §5 — Secret Manager Architecture Study

---

## 5. Cryptographic Architecture

### 5.1 Primitive Selection

#### Symmetric Encryption: XChaCha20-Poly1305 (RFC 8439)

**Selected over AES-256-GCM because:**

1. **Nonce management.** XChaCha20 uses 192-bit nonces, making random nonce generation safe without collision concerns. AES-GCM requires careful nonce management (96-bit, unique per key). A 96-bit nonce space with random generation reaches birthday bound at ~2^48 encryptions — feasible in a long-lived vault. XChaCha20's 192-bit nonce eliminates this concern entirely.

2. **Software performance.** ChaCha20 is faster than AES on devices without AES-NI. Even with ARM Crypto Extensions on modern SoCs, ChaCha20-Poly1305 is competitive.

3. **Consistent performance.** AES-GCM performance varies dramatically across platforms (hardware-accelerated on some, pure software on others). XChaCha20-Poly1305 delivers consistent performance everywhere.

4. **Side-channel resistance.** ChaCha20 is inherently more resistant to timing side-channels than table-based AES implementations. ChaCha20's constant-time arithmetic is simpler to verify.

**AES-256-GCM is still used internally** for hardware-backed key wrapping in Android Keystore / iOS Secure Enclave (these hardware modules only support AES operations internally). Our application code never handles the raw AES key in these cases.

#### Key Derivation: Argon2id (RFC 9106)

**Selected over PBKDF2 and scrypt because:**

1. **Modern standard.** RFC 9106 (June 2023) formalizes Argon2 as the IETF-recommended password hashing function. Argon2id won the Password Hashing Competition (2015).

2. **Memory-hard.** Argon2id's memory cost parameter makes parallelized brute-force attacks (GPU, ASIC, FPGA) economically infeasible. PBKDF2 with SHA-256 requires minimal memory, making it highly parallelizable.

3. **Tunable parameters.** Independent control over time cost, memory cost, and parallelism allows optimization for mobile vs desktop.

4. **Resistance to side-channel attacks.** Argon2id's hybrid construction provides resistance to both side-channel and time-memory tradeoff attacks.

5. **Widely implemented.** Available in libsodium, Argon2 reference implementation, and platform-native implementations across all target platforms.

**Parameters:**
```
Type:     Argon2id
Version:  0x13 (latest)
Salt:     16 bytes, cryptographically random (per vault)
Memory:   128 MiB (desktop), 64 MiB (mobile, configurable)
Time:     3 (iterations)
Parallelism: 4 (desktop), 2 (mobile)
Output:   32 bytes (256 bits)
```

**OWASP alignment:** The OWASP Password Storage Cheat Sheet (2024) recommends Argon2id with minimum 128 MiB memory, minimum 2 iterations, and minimum parallelism of 1. Our parameters meet or exceed these on desktop, and slightly below on mobile (64 MiB) — compensated by the Device Unlock Key mechanism.

#### Key Wrapping: HMAC-SHA256 + AES-256-GCM

**Selected for authenticated wrapping of keys.** HMAC-SHA256 is well-analyzed, hardware-accelerated on all target platforms, and provides the necessary authentication guarantee. We wrap DEKs using a key derived from the VEK via HMAC-SHA256, then encrypt with AES-256-GCM.

#### Signatures: Ed25519 (RFC 8032)

**Selected for sharing package authentication.** 64-byte signatures, 32-byte public keys, deterministic signatures (no per-signature randomness), fast verification. Available in libsodium, BouncyCastle, and platform libraries.

#### Key Agreement: X25519 (RFC 7748)

**Selected for sharing key exchange.** 32-byte keys, fast scalar multiplication, co-designed with Ed25519, resistant to timing attacks.

#### Random Number Generation

- **Android:** `java.security.SecureRandom` (seeded from `/dev/urandom`). Native: `libsodium randombytes_buf()`.
- **Desktop:** OS CSPRNG (`CryptGenRandom` on Windows, `/dev/urandom` on Linux, `SecRandomCopyBytes` on macOS).
- **Never:** `java.util.Random`, `Math.random()`, `rand()`, or any non-cryptographic PRNG.

### 5.2 Cryptographic Parameters Summary

| Primitive | Algorithm | Key/Output Size | Parameters |
|---|---|---|---|
| Master key derivation | Argon2id | 32 bytes | m=128MiB/64MiB, t=3, p=4/2 |
| Record encryption | XChaCha20-Poly1305 | 32-byte key | 192-bit nonce, 128-bit tag |
| Key wrapping | HMAC-SHA256 + AES-256-GCM | 32-byte keys | 96-bit nonce, counter-based |
| Digital signatures | Ed25519 | 32B key, 64B sig | RFC 8032 |
| Key agreement | X25519 | 32-byte keys | RFC 7748 |
| Secure random | OS CSPRNG | N/A | Platform-native |

### 5.3 Authenticated Encryption Properties

Every encrypted record produces `(nonce, ciphertext, authentication_tag)`.

XChaCha20-Poly1305 provides:
- **Confidentiality:** Ciphertext reveals no information about plaintext without the key.
- **Authenticity:** Any modification to ciphertext, nonce, or associated data causes verification failure.
- **Associated Data (AAD):** We bind ciphertext to record metadata (type, version, record ID) to prevent record type confusion attacks.

**Critical rule:** Decryption failure MUST abort the entire vault unlock. A single corrupted or tampered record must halt the process and alert the user.

---
