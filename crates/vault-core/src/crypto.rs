//! Security utilities for the vault.
//!
//! Provides constant-time comparison operations and other
//! cryptographic safety helpers to prevent timing attacks.

/// Constant-time comparison of two byte slices.
///
/// Returns `true` if the slices are equal, `false` otherwise.
/// The comparison always runs in time proportional to the
/// length of the inputs, regardless of where they differ,
/// to prevent timing side-channel attacks.
///
/// If the slices have different lengths, the function returns
/// `false` immediately (the length itself is not considered
/// secret in this context).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Constant-time comparison of two fixed-size arrays.
///
/// Generic over any `PartialEq`-compatible type that can be
/// viewed as bytes. Returns `true` if equal, `false` otherwise.
pub fn constant_time_eq_array<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    let mut result: u8 = 0;
    for i in 0..N {
        result |= a[i] ^ b[i];
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_slices_are_true() {
        let a = b"hello world";
        let b = b"hello world";
        assert!(constant_time_eq(a, b));
    }

    #[test]
    fn different_slices_are_false() {
        let a = b"hello world";
        let b = b"hello worle";
        assert!(!constant_time_eq(a, b));
    }

    #[test]
    fn different_lengths_are_false() {
        let a = b"hello";
        let b = b"hello world";
        assert!(!constant_time_eq(a, b));
    }

    #[test]
    fn empty_slices_are_equal() {
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn single_byte_equality() {
        assert!(constant_time_eq(&[0xAB], &[0xAB]));
        assert!(!constant_time_eq(&[0xAB], &[0xAC]));
    }

    #[test]
    fn array_comparison() {
        let a = [0xAAu8; 32];
        let b = [0xAAu8; 32];
        let c = {
            let mut arr = [0xAAu8; 32];
            arr[31] = 0xBB;
            arr
        };
        assert!(constant_time_eq_array(&a, &b));
        assert!(!constant_time_eq_array(&a, &c));
    }

    #[test]
    fn early_difference_at_start() {
        let a = b"aaaaaa";
        let b = b"baaaaa";
        assert!(!constant_time_eq(a, b));
    }

    #[test]
    fn early_difference_at_end() {
        let a = b"aaaaaa";
        let b = b"aaaaba";
        assert!(!constant_time_eq(a, b));
    }
}
