# 40.1 Attacker Scenarios

**Source:** §40 — Secret Manager Architecture Study

---

## 40. Red-Team Analysis

### 40.1 Attacker Scenarios

#### R01: Stolen Encrypted Vault File

**Attack:** Attacker obtains `vault.db` from device backup, sync, or file system.

**Expected result without password:** Attacker has salt, wrapped VEK, Argon2id parameters, but cannot derive KEK without password. Vault is secure.

**Expected result with weak password:** Attacker performs offline dictionary attack. Weak passwords (<30 bits entropy) can be cracked in hours/days.

**Mitigation:** Strong master password (≥60 bits), Argon2id memory hardness, recovery phrase backup.

**Residual risk:** Weak master passwords are vulnerable to offline brute force. User education is essential.

#### R02: Offline Brute-Force

**Attack:** Attacker has vault file and performs optimized GPU-based Argon2id attack.

**Expected result:** ~10,000-50,000 guesses/second on high-end GPU. 6-word Diceware (~78 bits) → ~600 years. 12-character random password (~78 bits) → ~600 years.

**Mitigation:** Argon2id memory hardness, strong password guidance, Device Unlock Key as additional barrier.

**Residual risk:** Economic attacks (nation-state with dedicated ASICs for Argon2id). Acceptable for commercial product targeting individuals and businesses (not nation-state adversaries).

#### R03: Rooted Android Device

**Attack:** Attacker roots device, reads application private storage, extracts vault file. With root, can potentially access Keystore keys.

**Expected result:** Vault file accessible. If Keystore is compromised, DUK and wrapped KEK accessible. Attacker can decrypt VEK without master password.

**Mitigation:** Root detection + warning, disable biometric unlock, require master password. Hardware-backed keys (StrongBox) persist even if OS is compromised — but attacker with root can still call Keystore APIs to decrypt using the hardware key if they can trigger biometric auth.

**Residual risk:** High. Rooted devices fundamentally cannot be trusted. Best mitigation: detect root and require master password.

#### R04: Malware on Device

**Attack:** Keylogger captures master password at input time. Screen scraper captures vault contents. Memory dumper reads RAM.

**Expected result:** Malware with user privileges can capture plaintext secrets.

**Mitigation:** FLAG_SECURE, anti-keylogging input fields, memory zeroization, short auto-lock.

**Residual risk:** HIGH. We cannot fully protect against malware running with user-level access on the same device. This is an OS security boundary issue. We mitigate but cannot eliminate.

#### R05: Compromised Sync Server

**Attack:** Attacker gains access to cloud sync storage (Google Drive, etc.).

**Expected result:** Attacker obtains encrypted vault packages. Without VEK, packages are useless.

**Mitigation:** E2E encryption. VEK never leaves device. Server sees only ciphertext.

**Residual risk:** None for confidentiality. Server could delete or corrupt packages (availability attack). Hash chain provides tamper detection.

#### R06: MITM During Sharing

**Attack:** Attacker intercepts WhatsApp message, modifies share package.

**Expected result:** Ed25519 signature verification fails. Package rejected.

**Mitigation:** Ed25519 sender authentication. Recipient verifies signature before decryption.

**Residual risk:** If recipient does not have sender's verified public key, attacker could substitute their own key. User must verify sender identity through an out-of-band channel.

#### R07: Phishing via Autofill

**Attack:** Malicious website mimics legitimate login form. Autofill provides credentials.

**Expected result:** Credentials sent to attacker's server.

**Mitigation:** Domain verification, user confirmation before autofill, no silent autofill, subdomain checking, IDN/punycode detection.

**Residual risk:** User can still be tricked into manually approving autofill on a phishing site. Domain verification helps but cannot prevent all phishing.

#### R08: Evil Maid

**Attack:** Attacker gains physical access to powered-off device. Boots from external media, extracts disk contents.

**Expected result:** If full-disk encryption is enabled, disk is encrypted. Attacker cannot read vault file without credentials.

**Mitigation:** Full-disk encryption (LUKS, BitLocker, FileVault). Vault is additionally encrypted with VEK.

**Residual risk:** If device is left unlocked and unattended, attacker can access unlocked vault. Auto-lock mitigates this.

#### R09: Malicious Update

**Attack:** Attacker compromises update server, delivers trojanized application.

**Expected result:** Attacker's code runs with full application privileges, can exfiltrate secrets.

**Mitigation:** Signed updates with Ed25519. Unsigned updates rejected. Reproducible builds enable independent verification.

**Residual risk:** If signing key is compromised, attacker can sign malicious updates. Key rotation and HSM storage of signing key mitigate this.

#### R10: Supply Chain Attack

**Attack:** Attacker compromises a popular dependency library, introduces backdoor.

**Expected result:** Backdoor code runs in our application, potentially exfiltrating secrets.

**Mitigation:** Minimal dependencies, dependency auditing (cargo audit), SBOM, reproducible builds, fuzzing, security-focused code review.

**Residual risk:** Sophisticated supply chain attacks (e.g., xz Utils backdoor, 2024) are difficult to detect. Minimizing dependencies and maintaining audit capability reduces risk.

#### R11: Clipboard Exposure

**Attack:** Malicious app monitors clipboard, reads copied password.

**Expected result:** Password captured from clipboard.

**Mitigation:** Auto-clear clipboard after 30 seconds. Warn before copy. No auto-copy.

**Residual risk:** Clipboard monitoring apps can capture clipboard content between our clear and the user's paste. Minimizing hold time reduces window.

#### R12: Screenshot/Screen Recording

**Attack:** Attacker takes screenshot or screen recording while app is visible.

**Expected result:** Secrets visible in screenshot.

**Mitigation:** FLAG_SECURE (Android), platform equivalents on desktop.

**Residual risk:** Rooted/jailbroken devices can bypass FLAG_SECURE. Attacker with physical access can use another device's camera. Cannot prevent physical photography.

#### R13: Compromised Recipient Device

**Attack:** Attacker gains access to recipient's device after share package is delivered.

**Expected result:** Attacker can use recipient's app to view decrypted secret.

**Mitigation:** None — this is a recipient-side security issue, not a transport or protocol issue.

**Residual risk:** INHERENT LIMITATION. We explicitly do not protect against compromised recipient devices. The share protocol protects the secret in transit and ensures only the intended recipient can decrypt. What the recipient does with the plaintext afterward is out of scope.

---
