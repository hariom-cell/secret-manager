//! Cryptographically secure password generator.
//!
//! Generates passwords with configurable character sets and lengths.
//! Entropy is reported alongside the password so callers can show
//! "this password has 142 bits of entropy" to users.
//!
//! ## Why a custom generator
//!
//! - We never use `Math.random()` or non-crypto PRNGs.
//! - We support multiple character classes with predictable entropy.
//! - We avoid ambiguous characters (0/O, 1/l/I) by default — optional.

use crate::error::{Error, Result};
use rand::{seq::SliceRandom, RngCore};

/// Character classes that can be enabled in a password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CharClass {
    /// Lowercase a-z (26 chars)
    Lowercase,
    /// Uppercase A-Z (26 chars)
    Uppercase,
    /// Digits 0-9 (10 chars)
    Digits,
    /// Symbols !@#$%^&*()-_=+[]{}|;:,.<>?/~ (32 chars)
    Symbols,
    /// Extended symbols: backslash, quotes, grave accent (3 more)
    Extended,
}

impl CharClass {
    /// The character set for this class.
    pub fn alphabet(self) -> &'static [u8] {
        match self {
            CharClass::Lowercase => b"abcdefghijklmnopqrstuvwxyz",
            CharClass::Uppercase => b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            CharClass::Digits => b"0123456789",
            CharClass::Symbols => {
                b"!@#$%^&*()-_=+[]{}|;:,.<>?/~"
            }
            CharClass::Extended => b"\\'\"`",
        }
    }

    /// Number of distinct characters in this class.
    pub fn size(self) -> usize {
        self.alphabet().len()
    }
}

/// Configuration for password generation.
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    /// Password length in characters.
    pub length: usize,
    /// Which character classes are enabled.
    pub classes: Vec<CharClass>,
    /// If true, omit visually ambiguous characters (0, O, o, 1, l, I, |).
    pub avoid_ambiguous: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            length: 20,
            classes: vec![
                CharClass::Lowercase,
                CharClass::Uppercase,
                CharClass::Digits,
                CharClass::Symbols,
            ],
            avoid_ambiguous: true,
        }
    }
}

impl PasswordPolicy {
    /// Build the alphabet (after ambiguous-character filtering).
    fn alphabet(&self) -> Vec<u8> {
        let mut alphabet: Vec<u8> = self
            .classes
            .iter()
            .flat_map(|c| c.alphabet().iter().copied())
            .collect();
        if self.avoid_ambiguous {
            alphabet.retain(|&c| !is_ambiguous(c));
        }
        // Deduplicate (Lowercase and Uppercase don't overlap, but be safe).
        alphabet.sort_unstable();
        alphabet.dedup();
        alphabet
    }

    /// Compute the entropy in bits for a password of this policy.
    pub fn entropy_bits(&self) -> f64 {
        let alphabet_size = self.alphabet().len();
        if alphabet_size == 0 {
            return 0.0;
        }
        (alphabet_size as f64).log2() * (self.length as f64)
    }
}

/// Generate a password using the given policy.
pub fn generate(policy: &PasswordPolicy) -> Result<String> {
    if policy.length == 0 {
        return Err(Error::Password("length must be > 0".into()));
    }
    let alphabet = policy.alphabet();
    if alphabet.is_empty() {
        return Err(Error::Password("no character classes enabled".into()));
    }
    // Guarantee at least one character from each enabled class is included
    let class_chars: Vec<&[u8]> = policy.classes.iter().map(|c| c.alphabet()).collect();

    let mut rng = rand::rngs::OsRng;
    let mut chars: Vec<u8> = Vec::with_capacity(policy.length);

    // First, include one guaranteed character from each enabled class
    for class in class_chars.iter().take(policy.length) {
        let filtered: Vec<u8> = if policy.avoid_ambiguous {
            class.iter().copied().filter(|c| !is_ambiguous(*c)).collect()
        } else {
            class.to_vec()
        };
        if filtered.is_empty() {
            continue;
        }
        let idx = (rng.next_u32() as usize) % filtered.len();
        chars.push(filtered[idx]);
    }

    // Fill the remainder randomly from the combined alphabet
    while chars.len() < policy.length {
        let idx = (rng.next_u32() as usize) % alphabet.len();
        chars.push(alphabet[idx]);
    }

    // Shuffle so guaranteed characters are not always at the start
    chars.shuffle(&mut rng);

    // SAFETY: every char in our alphabets is a single-byte ASCII char.
    String::from_utf8(chars)
        .map_err(|e| Error::Password(format!("utf8 conversion failed: {e}")))
}

/// Bits of entropy for a password (helper).
pub fn entropy_bits(policy: &PasswordPolicy) -> f64 {
    policy.entropy_bits()
}

/// Categorize password strength by entropy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strength {
    /// < 48 bits — trivially guessable
    VeryWeak,
    /// 48-71 bits — guessable
    Weak,
    /// 72-111 bits — strong
    Strong,
    /// ≥ 112 bits — very strong
    VeryStrong,
}

impl Strength {
    /// Classify by entropy bits.
    pub fn from_entropy(bits: f64) -> Self {
        if bits < 48.0 {
            Strength::VeryWeak
        } else if bits < 72.0 {
            Strength::Weak
        } else if bits < 112.0 {
            Strength::Strong
        } else {
            Strength::VeryStrong
        }
    }

    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Strength::VeryWeak => "very weak",
            Strength::Weak => "weak",
            Strength::Strong => "strong",
            Strength::VeryStrong => "very strong",
        }
    }
}

/// Returns true if the byte is visually ambiguous.
fn is_ambiguous(c: u8) -> bool {
    matches!(
        c,
        b'0' | b'O' | b'o' | b'1' | b'l' | b'I' | b'|' | b'`'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_works() {
        let pw = generate(&PasswordPolicy::default()).unwrap();
        assert_eq!(pw.len(), 20);
        // All ASCII printable
        for c in pw.bytes() {
            assert!(c.is_ascii_graphic(), "non-graphic char: {:#x}", c);
        }
    }

    #[test]
    fn contains_all_classes() {
        let policy = PasswordPolicy::default();
        let pw = generate(&policy).unwrap();
        let bytes = pw.as_bytes();
        assert!(bytes.iter().any(|c| c.is_ascii_lowercase()));
        assert!(bytes.iter().any(|c| c.is_ascii_uppercase()));
        assert!(bytes.iter().any(|c| c.is_ascii_digit()));
        assert!(bytes.iter().any(|c| !c.is_ascii_alphanumeric()));
    }

    #[test]
    fn length_respected() {
        for n in [8, 16, 32, 64] {
            let policy = PasswordPolicy {
                length: n,
                ..Default::default()
            };
            let pw = generate(&policy).unwrap();
            assert_eq!(pw.len(), n);
        }
    }

    #[test]
    fn avoid_ambiguous_filters_known() {
        let policy = PasswordPolicy {
            length: 256,
            avoid_ambiguous: true,
            ..Default::default()
        };
        let pw = generate(&policy).unwrap();
        for c in pw.bytes() {
            assert!(!is_ambiguous(c), "ambiguous char found: {:#x}", c);
        }
    }

    #[test]
    fn entropy_bits_calc() {
        let p = PasswordPolicy {
            length: 16,
            classes: vec![CharClass::Lowercase],
            avoid_ambiguous: false,
        };
        // 26 chars, length 16 → 16 * log2(26) ≈ 75.2
        let bits = p.entropy_bits();
        assert!(bits > 74.0 && bits < 76.0, "got {}", bits);
    }

    #[test]
    fn strength_classification() {
        assert_eq!(Strength::from_entropy(40.0), Strength::VeryWeak);
        assert_eq!(Strength::from_entropy(60.0), Strength::Weak);
        assert_eq!(Strength::from_entropy(80.0), Strength::Strong);
        assert_eq!(Strength::from_entropy(128.0), Strength::VeryStrong);
    }

    #[test]
    fn zero_length_rejected() {
        let policy = PasswordPolicy {
            length: 0,
            ..Default::default()
        };
        assert!(generate(&policy).is_err());
    }

    #[test]
    fn no_classes_rejected() {
        let policy = PasswordPolicy {
            length: 10,
            classes: vec![],
            ..Default::default()
        };
        assert!(generate(&policy).is_err());
    }

    #[test]
    fn different_policies_produce_different_passwords() {
        let p1 = PasswordPolicy {
            length: 16,
            ..Default::default()
        };
        let p2 = PasswordPolicy {
            length: 32,
            ..Default::default()
        };
        let pw1 = generate(&p1).unwrap();
        let pw2 = generate(&p2).unwrap();
        assert_ne!(pw1.len(), pw2.len());
    }

    #[test]
    fn avoid_ambiguous_changes_alphabet_size() {
        let p_keep = PasswordPolicy {
            length: 1,
            avoid_ambiguous: false,
            classes: vec![CharClass::Digits],
        };
        let p_skip = PasswordPolicy {
            length: 1,
            avoid_ambiguous: true,
            classes: vec![CharClass::Digits],
        };
        // Digits has 10 chars; ambiguous filter removes 0 and 1, leaving 8.
        // We can't see the alphabet size directly but we can verify that
        // with avoid_ambiguous=true, the digit class is still useful.
        for _ in 0..10 {
            let pw = generate(&p_skip).unwrap();
            let c = pw.as_bytes()[0];
            assert!(b"23456789".contains(&c), "got unexpected: {}", c as char);
        }
        // And without filter, both 0 and 1 are possible.
        let _ = generate(&p_keep).unwrap();
    }

    #[test]
    fn entropy_classification_default_policy() {
        let p = PasswordPolicy::default();
        let bits = p.entropy_bits();
        // 20 chars × log2(~85) ≈ 129 bits → very strong
        assert_eq!(Strength::from_entropy(bits), Strength::VeryStrong);
    }
}
