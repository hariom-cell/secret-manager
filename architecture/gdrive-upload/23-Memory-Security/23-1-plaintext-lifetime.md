# 23.1 Plaintext Lifetime

**Source:** §23 — Secret Manager Architecture Study

---

## 23. Memory Security

### 23.1 Plaintext Lifetime

| Phase | Plaintext in Memory | Duration |
|---|---|---|
| Vault unlocked | VEK + decrypted records | Entire session |
| Record viewed | Individual record | While viewing |
| TOTP displayed | TOTP code | ~5 seconds |
| Search | Decrypted fields | During search |

### 23.2 Zeroization

**Rust:**
```rust
use zeroize::Zeroize;
struct SecretBuffer { data: [u8; 32] }
impl Drop for SecretBuffer {
    fn drop(&mut self) { self.data.zeroize(); }
}
```

**Kotlin:**
```kotlin
class SecureByteArray(private val size: Int) {
    private val data = ByteArray(size)
    fun clear() { Arrays.fill(data, 0.toByte()) }
}
```

### 23.3 What We CANNOT Control

| Threat | Platform | Mitigation |
|---|---|---|
| Garbage collection | JVM | Explicitly zero byte arrays before dereferencing |
| Swap/page file | Desktop | `mlock()` / `VirtualLock()` |
| Core dumps | Linux | Disable core dumps (`ulimit -c 0`) |
| Crash dumps | All | Configure crash reporters to exclude app data |
| Debugging | All | Detect debugger attachment |
| Memory forensics | All | Minimize plaintext lifetime. Cannot fully prevent. |
| JIT compilation | JVM | Interpreter mode for crypto-critical paths |
| Copy-on-write | All | OS-level. Cannot prevent. |

**Honest assessment:** Complete memory security is impossible on modern operating systems. We minimize plaintext lifetime, use secure buffers with zeroization, lock sensitive pages, and use Rust for crypto-critical code. We cannot prevent kernel exploits, DMA attacks, cold boot attacks, or debugging by privileged attackers.

---
