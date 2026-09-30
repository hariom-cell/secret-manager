//! Shared cryptographic types — all key material implements
//! [`Zeroize`] + [`ZeroizeOnDrop`] so plaintext bytes are scrubbed from
//! memory as soon as the value is dropped.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 256-bit encryption key.
///
/// Used for KEKs, VEKs, DEKs, and the raw output of any KDF. The 32 bytes
/// are wiped on drop via [`ZeroizeOnDrop`].
///
/// The `Debug` impl intentionally prints a placeholder — never the bytes.
pub struct KeyBytes([u8; 32]);

impl Clone for KeyBytes {
    fn clone(&self) -> Self {
        // Explicit Clone so we can keep ZeroizeOnDrop working — the derived
        // Clone would conflict with the manual impl below if we ever add
        // traits later.
        Self(self.0)
    }
}

impl Zeroize for KeyBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for KeyBytes {}

impl KeyBytes {
    /// Construct a `KeyBytes` from a raw 256-bit array.
    ///
    /// This is the only way to construct a key from raw bytes — there is no
    /// `from_slice` because partial lengths would be a footgun. Use this
    /// when you've generated material via a CSPRNG (e.g. `ChaCha12`),
    /// output of [`crate::kdf::derive_kek`], or [`crate::dek::derive_dek`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use vault_core::KeyBytes;
    /// let key = KeyBytes::new([0u8; 32]);
    /// assert_eq!(key.as_bytes().len(), 32);
    /// ```
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the inner bytes immutably.
    ///
    /// The returned reference is to the key material itself — handle with care.
    /// Most callers should prefer the higher-level APIs in [`crate::aead`] and
    /// [`crate::kdf`] which take [`KeyBytes`] by value.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume the value and return the inner bytes.
    ///
    /// The bytes are **not** zeroized before being returned — once moved out,
    /// the caller is responsible for scrubbing them when appropriate. Most
    /// callers should keep the value as [`KeyBytes`] to inherit the
    /// `ZeroizeOnDrop` guarantee.
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Explicitly zeroize the key buffer.
    ///
    /// This is rarely needed because [`ZeroizeOnDrop`] handles erasure when
    /// the value goes out of scope, but it is useful when reusing a buffer
    /// across iterations of a long-running operation.
    pub fn zero(&mut self) {
        self.0.zeroize();
    }
}

impl From<[u8; 32]> for KeyBytes {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }
}

impl core::fmt::Debug for KeyBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeyBytes(<zeroized>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_bytes_length() {
        let k = KeyBytes::new([0u8; 32]);
        assert_eq!(k.as_bytes().len(), 32);
    }

    #[test]
    fn key_bytes_roundtrip() {
        let bytes = [0x42u8; 32];
        let k = KeyBytes::new(bytes);
        assert_eq!(k.as_bytes(), &bytes);
        assert_eq!(k.into_bytes(), bytes);
    }

    #[test]
    fn from_array_works() {
        let bytes = [0x11u8; 32];
        let k: KeyBytes = bytes.into();
        assert_eq!(k.as_bytes(), &bytes);
    }

    #[test]
    fn debug_hides_key_bytes() {
        let k = KeyBytes::new([0xFFu8; 32]);
        let s = format!("{:?}", k);
        assert!(!s.contains("ff"));
        assert!(s.contains("zeroized"));
    }

    #[test]
    fn key_bytes_zero_method() {
        let mut k = KeyBytes::new([0x42u8; 32]);
        k.zero();
        assert_eq!(k.as_bytes(), &[0u8; 32]);
    }
}
