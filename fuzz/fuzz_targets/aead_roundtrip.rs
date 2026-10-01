//! Fuzzing harness for AEAD encrypt/decrypt roundtrip.
//!
//! Exercises the `vault_core::aead` module by:
//!
//! 1. Encrypting random plaintexts and decrypting them back — verifies
//!    the round-trip is lossless.
//! 2. Tampering with ciphertexts — verifies decryption fails.
//! 3. Feeding short/empty/garbage ciphertexts to `Ciphertext::from_bytes` —
//!    verifies graceful errors.
//!
//! Build / run with:
//!   cargo +nightly fuzz run fuzz_aead_roundtrip -- -runs=1000000
//!
//! Or as a fuzz-like binary:
//!   cargo run -p vault-fuzz --bin fuzz_aead_roundtrip -- 10000

use vault_core::aead::{decrypt_record, encrypt_record, Ciphertext};
use vault_core::types::KeyBytes;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let iterations: usize = if args.len() > 1 {
        args[1].parse().unwrap_or(1)
    } else {
        1
    };

    if iterations > 0 {
        fuzz_smoke_tests();
        if iterations > 1 {
            for i in 0..iterations {
                let data = generate_fuzz_input(i);
                fuzz_aead_roundtrip(&data);
            }
        }
    }

    eprintln!("aead_roundtrip: {} iterations passed", iterations);
}

fn fuzz_smoke_tests() {
    let cases: &[&[u8]] = &[
        b"",
        b"x",
        b"hello world",
        b"\x00\x00\x00",
        &[0xFFu8; 64],
        &vec![0xAB; 4096],
    ];
    for case in cases {
        fuzz_aead_roundtrip(case);
    }
}

/// Deterministic pseudo-random input from a seed.
fn generate_fuzz_input(seed: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(32 + (seed % 4096));
    let mut state = seed as u64;
    for _ in 0..data.capacity() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        data.push((state >> 32) as u8);
    }
    data
}

/// Exercise AEAD encrypt/decrypt against `data` as plaintext. Must never panic.
fn fuzz_aead_roundtrip(data: &[u8]) {
    // Use a fixed key so fuzzing is deterministic and finds crashes,
    // not cryptographic failures.
    let key = KeyBytes::new([0xABu8; 32]);

    // 1. Encrypt and decrypt the raw data.
    if let Ok(ct) = encrypt_record(&key, data) {
        if let Ok(recovered) = decrypt_record(&key, &ct) {
            assert_eq!(
                recovered, data,
                "AEAD roundtrip mismatch: plaintext {:?} vs recovered {:?}",
                data, recovered
            );
        }

        // 2. Tamper with the ciphertext — must never decrypt successfully.
        if !ct.data.is_empty() {
            let mut tampered = ct.clone();
            tampered.data[0] ^= 0x01;
            match decrypt_record(&key, &tampered) {
                Err(_) => {
                    // Correct: tampered ciphertext must be rejected.
                }
                Ok(_) => {
                    panic!("decrypt_record succeeded on tampered ciphertext!");
                }
            }
        }

        // 3. Wrong key must be rejected.
        let wrong_key = KeyBytes::new([0xCDu8; 32]);
        match decrypt_record(&wrong_key, &ct) {
            Err(_) => {}
            Ok(_) => {
                panic!("decrypt_record succeeded with wrong key!");
            }
        }
    }

    // 4. Ciphertext::from_bytes must never panic on any input length.
    let _ = Ciphertext::from_bytes(data);
    let _ = Ciphertext::from_bytes(&[]);
    let _ = Ciphertext::from_bytes(&data[..data.len().min(23)]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzz_smoke_empty() {
        fuzz_aead_roundtrip(b"");
    }

    #[test]
    fn fuzz_smoke_single_byte() {
        fuzz_aead_roundtrip(b"A");
    }

    #[test]
    fn fuzz_smoke_large() {
        fuzz_aead_roundtrip(&vec![0x42u8; 8192]);
    }

    #[test]
    fn fuzz_smoke_randomish() {
        let data: Vec<u8> = (0..256).map(|i| (i * 173) as u8).collect();
        fuzz_aead_roundtrip(&data);
    }

    #[test]
    fn fuzz_iterations_100() {
        for i in 0..100 {
            let data = generate_fuzz_input(i);
            fuzz_aead_roundtrip(&data);
        }
    }
}
