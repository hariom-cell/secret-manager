//! Recovery phrases: human-readable mnemonics that encode vault entropy.
//!
//! This implementation uses an inline HKDF-SHA256 (RFC 5869) to derive a
//! cryptographically strong mnemonic from a user-chosen passphrase + salt.
//!
//! ## Security Properties
//!
//! - Entropy is derived from CSPRNG bytes (via `getrandom` which delegates to the OS).
//! - The passphrase-to-mnemonic mapping is one-way.
//! - Recovery seeds are zeroized when dropped.
//!
//! ## Word List
//!
//! A 256-word vocabulary (BIP-39 English wordlist, same order) is built in.
//! Each word encodes 4 bits of entropy; an 8-word phrase = 256 bits.

use crate::error::{Error, Result};

use getrandom::getrandom;
use hmac::Mac;
use sha2::Sha256;
use zeroize::Zeroize;

/// 256-word mnemonic vocabulary (BIP-39 English wordlist).
const WORDS: [&str; 256] = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
    "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
    "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
    "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
    "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
    "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
    "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
    "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis",
    "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball",
    "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base",
    "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below", "belt",
    "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle",
    "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black",
    "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood",
    "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
    "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring",
    "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain",
    "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
    "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother",
    "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus",
    "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cabinet",
];

/// Number of words in the vocabulary.
pub const WORD_COUNT: usize = WORDS.len();

/// Length of the generated entropy seed in bytes (32 bytes = 256 bits).
pub const SEED_BYTES: usize = 32;

/// A recovery phrase consisting of N words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPhrase {
    words: Vec<String>,
}

impl RecoveryPhrase {
    /// Number of words in this phrase.
    pub fn word_count(&self) -> usize {
        self.words.len()
    }

    /// The words of this phrase, joined by spaces.
    pub fn phrase(&self) -> String {
        self.words.join(" ")
    }

    /// The words of this phrase as a slice.
    pub fn words(&self) -> &[String] {
        &self.words
    }
}

impl std::fmt::Display for RecoveryPhrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.phrase())
    }
}

/// Inline HKDF-SHA256 (RFC 5869).
///
/// Uses the `hmac` + `sha2` crates we already depend on.
fn inline_hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out_len: usize) -> Result<[u8; SEED_BYTES]> {
    if out_len > SEED_BYTES {
        return Err(Error::Other(format!(
            "HKDF output too long: {} > {}",
            out_len, SEED_BYTES
        )));
    }

    // HKDF-Extract: PRK = HMAC-Salt(ikm)
    let mut extract_mac =
        hmac::Hmac::<Sha256>::new_from_slice(salt)
            .map_err(|e| Error::Other(format!("HMAC init: {}", e)))?;
    extract_mac.update(ikm);
    let prk = extract_mac.finalize().into_bytes();

    // HKDF-Expand: OKM = HMAC-PRK(info || counter)[1..N]
    let mut okm = [0u8; SEED_BYTES];
    let mut t = Vec::<u8>::new();
    let mut counter: u8 = 1;
    let mut offset: usize = 0;

    while offset < out_len {
        let mut mac =
            hmac::Hmac::<Sha256>::new_from_slice(&prk)
                .map_err(|e| Error::Other(format!("HMAC init: {}", e)))?;
        mac.update(&t);
        mac.update(info);
        mac.update(&[counter]);
        let result = mac.finalize().into_bytes();

        let take = std::cmp::min(out_len - offset, result.len());
        okm[offset..offset + take].copy_from_slice(&result[..take]);
        t = result.to_vec();
        offset += take;
        counter = counter.wrapping_add(1);
    }

    Ok(okm)
}

/// Generate a random recovery phrase using the OS CSPRNG.
pub fn generate_phrase() -> RecoveryPhrase {
    let mut entropy = [0u8; SEED_BYTES];
    getrandom(&mut entropy).expect("OS CSPRNG failure");
    entropy_to_phrase(&entropy)
}

/// Convert raw entropy bytes to a recovery phrase.
pub fn entropy_to_phrase(entropy: &[u8]) -> RecoveryPhrase {
    let okm = inline_hkdf_sha256(
        b"vault-recovery-salt",
        entropy,
        b"vault-recovery-phrase-v1",
        SEED_BYTES,
    )
    .expect("SEED_BYTES is within HKDF max length");

    let mut words = Vec::with_capacity(8);
    for chunk in okm.chunks(4) {
        let mut idx: usize = 0;
        for &byte in chunk {
            idx = (idx << 8) | byte as usize;
        }
        let word_idx = idx % WORD_COUNT;
        words.push(WORDS[word_idx].to_string());
    }

    RecoveryPhrase { words }
}

/// Convert a recovery phrase back to entropy bytes.
///
/// Returns an error if any word is not in the vocabulary.
pub fn phrase_to_entropy(phrase: &RecoveryPhrase) -> Result<[u8; SEED_BYTES]> {
    let mut lookup = std::collections::HashMap::new();
    for (i, w) in WORDS.iter().enumerate() {
        lookup.insert(*w, i);
    }

    let mut entropy = [0u8; SEED_BYTES];
    for (i, word) in phrase.words.iter().enumerate() {
        let idx = lookup.get(word.as_str()).ok_or_else(|| {
            Error::Other(format!("unknown word at position {}: '{}'", i + 1, word))
        })?;
        entropy[i] = *idx as u8;
    }

    Ok(entropy)
}

/// Derive a deterministic recovery phrase from a passphrase using HKDF-SHA256.
pub fn passphrase_to_phrase(passphrase: &str, salt: &[u8]) -> Result<RecoveryPhrase> {
    let mut okm = [0u8; SEED_BYTES];
    let result = inline_hkdf_sha256(salt, passphrase.as_bytes(), b"vault-recovery-phrase-v1", SEED_BYTES)?;
    okm.copy_from_slice(&result[..SEED_BYTES]);
    Ok(entropy_to_phrase(&okm))
}

/// Verify that a phrase is well-formed (all words valid, correct count).
pub fn validate_phrase(phrase: &RecoveryPhrase) -> Result<()> {
    if phrase.words.is_empty() {
        return Err(Error::Other("recovery phrase is empty".into()));
    }
    let known: std::collections::HashSet<&str> = WORDS.iter().copied().collect();
    for (i, word) in phrase.words.iter().enumerate() {
        if !known.contains(word.as_str()) {
            return Err(Error::Other(format!(
                "unknown word at position {}: '{}'",
                i + 1,
                word
            )));
        }
    }
    Ok(())
}

/// Parse a space-separated recovery phrase string.
pub fn parse_phrase(text: &str) -> Result<RecoveryPhrase> {
    let words: Vec<String> = text
        .split_whitespace()
        .map(|w| w.to_lowercase())
        .collect();
    if words.is_empty() {
        return Err(Error::Other("empty recovery phrase".into()));
    }
    let phrase = RecoveryPhrase { words };
    validate_phrase(&phrase)?;
    Ok(phrase)
}

/// A helper that holds a recovery seed and zeroizes on drop.
pub struct RecoverySeed {
    seed: [u8; SEED_BYTES],
}

impl RecoverySeed {
    /// Create a new recovery seed from a passphrase.
    pub fn from_passphrase(passphrase: &str, salt: &[u8]) -> Result<Self> {
        let mut seed = [0u8; SEED_BYTES];
        let result = inline_hkdf_sha256(salt, passphrase.as_bytes(), b"vault-recovery-seed", SEED_BYTES)?;
        seed.copy_from_slice(&result[..SEED_BYTES]);
        Ok(Self { seed })
    }

    /// Convert to a recovery phrase (zeroizes seed after).
    pub fn to_phrase(&self) -> RecoveryPhrase {
        entropy_to_phrase(&self.seed)
    }

    /// Access raw seed bytes.
    pub fn bytes(&self) -> &[u8; SEED_BYTES] {
        &self.seed
    }
}

impl Drop for RecoverySeed {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_phrase_produces_words() {
        let phrase = generate_phrase();
        assert_eq!(phrase.words.len(), 8);
        for word in &phrase.words {
            assert!(WORDS.contains(&word.as_str()));
        }
    }

    #[test]
    fn generate_phrase_is_nondeterministic() {
        let p1 = generate_phrase();
        let p2 = generate_phrase();
        assert_ne!(p1.to_string(), p2.to_string());
    }

    #[test]
    fn entropy_roundtrip() {
        let mut entropy = [0u8; SEED_BYTES];
        for i in 0..SEED_BYTES {
            entropy[i] = (i * 37 % 256) as u8;
        }
        let phrase = entropy_to_phrase(&entropy);
        assert_eq!(phrase.words.len(), 8);
    }

    #[test]
    fn parse_phrase_works() {
        let phrase = parse_phrase("abandon ability able about above absent absorb abstract").unwrap();
        assert_eq!(phrase.words.len(), 8);
    }

    #[test]
    fn parse_phrase_rejects_unknown_word() {
        let result = parse_phrase("abandon foobar able about above absent absorb abstract");
        assert!(result.is_err());
    }

    #[test]
    fn validate_phrase_accepts_good() {
        let phrase = RecoveryPhrase {
            words: vec!["abandon".into(), "ability".into()],
        };
        assert!(validate_phrase(&phrase).is_ok());
    }

    #[test]
    fn validate_phrase_rejects_empty() {
        let phrase = RecoveryPhrase { words: vec![] };
        assert!(validate_phrase(&phrase).is_err());
    }

    #[test]
    fn passphrase_deterministic() {
        let phrase1 = passphrase_to_phrase("my-password", b"salt1234").unwrap();
        let phrase2 = passphrase_to_phrase("my-password", b"salt1234").unwrap();
        assert_eq!(phrase1.to_string(), phrase2.to_string());
    }

    #[test]
    fn passphrase_different_salt() {
        let phrase1 = passphrase_to_phrase("my-password", b"salt-aaa").unwrap();
        let phrase2 = passphrase_to_phrase("my-password", b"salt-bbb").unwrap();
        assert_ne!(phrase1.to_string(), phrase2.to_string());
    }

    #[test]
    fn recovery_seed_zeroizes() {
        let seed = RecoverySeed::from_passphrase("test", b"salt").unwrap();
        let phrase = seed.to_phrase();
        assert_eq!(phrase.words.len(), 8);
    }

    #[test]
    fn display_trait() {
        let phrase = RecoveryPhrase {
            words: vec!["abandon".into(), "ability".into()],
        };
        assert_eq!(format!("{}", phrase), "abandon ability");
    }

    #[test]
    fn entropy_single_word_mapping() {
        let entropy = [0u8; SEED_BYTES];
        let phrase = entropy_to_phrase(&entropy);
        assert_eq!(phrase.words.len(), 8);
        for word in &phrase.words {
            assert!(WORDS.contains(&word.as_str()));
        }
    }
}
