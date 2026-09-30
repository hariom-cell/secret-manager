# 20.1 Design

**Source:** §20 — Secret Manager Architecture Study

---

## 20. Password Generator

### 20.1 Design

**Modes:**
1. **Random:** charset = user-selected groups. Entropy = L × log2(N).
2. **Passphrase:** 7776-word Diceware list. 6 words → 77.5 bits entropy.
3. **PIN:** Digits only. Entropy = 3.32 × L.
4. **Pronounceable:** Markov chain generation.

**Character groups (user toggles):**
- Uppercase (26), Lowercase (26), Digits (10), Symbols (32), Custom

**Minimum recommendations:**
- Random: 16+ chars, ≥80 bits entropy
- Passphrase: 6+ words, ≥77 bits entropy
- PIN: 6+ digits (low security only)

**CSPRNG:** Platform-native OS CSPRNG only. Never `Math.random()` or equivalents.

---
