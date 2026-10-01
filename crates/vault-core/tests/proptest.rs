//! Property-based tests for `vault-core` using `proptest`.
//!
//! These tests verify cryptographic and structural invariants over
//! randomly-generated inputs, catching edge-case bugs that fixed-value
//! unit tests miss.

use proptest::prelude::*;
use vault_core::{
    aead::{decrypt_record, encrypt_record, Ciphertext, Nonce},
    dek::derive_dek,
    format::{deserialize_records, serialize_records},
    kdf::{derive_kek, KdfParams},
    types::KeyBytes,
    RecordId,
};

// ─── Helpers ───────────────────────────────────────────────────────────────

fn key_from_seed(seed: u8) -> KeyBytes {
    KeyBytes::new([seed; 32])
}

fn fast_kdf_params() -> KdfParams {
    KdfParams {
        m_cost: 8192,
        t_cost: 2,
        p_cost: 1,
    }
}

fn test_salt(seed: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    for i in 0..32 {
        s[i] = seed.wrapping_add(i as u8);
    }
    s
}

// ─── AEAD Properties ──────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 200, .. ProptestConfig::default()
    })]

    #[test]
    fn prop_aead_encrypt_decrypt_roundtrip(
        key_byte in any::<u8>(),
        len in 0usize..4096,
    ) {
        let key = key_from_seed(key_byte);
        let plaintext: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();

        let ct = encrypt_record(&key, &plaintext).expect("encrypt must succeed");
        let recovered = decrypt_record(&key, &ct).expect("decrypt must succeed");

        prop_assert_eq!(recovered, plaintext);
    }

    #[test]
    fn prop_different_keys_different_ciphertexts(
        seed1 in any::<u8>(),
        seed2 in any::<u8>(),
        len in 1usize..512,
    ) {
        prop_assume!(seed1 != seed2);

        let key_a = key_from_seed(seed1);
        let key_b = key_from_seed(seed2);
        let pt: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();

        let ct_a = encrypt_record(&key_a, &pt).expect("encrypt a");
        let ct_b = encrypt_record(&key_b, &pt).expect("encrypt b");

        let bytes_a = ct_a.to_bytes();
        let bytes_b = ct_b.to_bytes();
        prop_assert_ne!(bytes_a, bytes_b);
    }

    #[test]
    fn prop_wrong_key_decrypt_fails(
        seed1 in any::<u8>(),
        seed2 in any::<u8>(),
        len in 1usize..512,
    ) {
        prop_assume!(seed1 != seed2);

        let key_a = key_from_seed(seed1);
        let key_b = key_from_seed(seed2);
        let pt: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();

        let ct = encrypt_record(&key_a, &pt).expect("encrypt");
        let result = decrypt_record(&key_b, &ct);
        prop_assert!(result.is_err());
    }

    #[test]
    fn prop_empty_plaintext_roundtrip(key_byte in any::<u8>()) {
        let key = key_from_seed(key_byte);
        let ct = encrypt_record(&key, &[]).expect("encrypt empty");
        let recovered = decrypt_record(&key, &ct).expect("decrypt empty");
        prop_assert_eq!(recovered, Vec::<u8>::new());
    }

    #[test]
    fn prop_large_plaintext_roundtrip(key_byte in any::<u8>()) {
        let key = key_from_seed(key_byte);
        let plaintext: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();

        let ct = encrypt_record(&key, &plaintext).expect("encrypt large");
        let recovered = decrypt_record(&key, &ct).expect("decrypt large");
        prop_assert_eq!(recovered, plaintext);
    }
}

// ─── KDF Properties ───────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 100, .. ProptestConfig::default()
    })]

    #[test]
    fn prop_kdf_deterministic(
        pw_len in 1usize..64,
        seed in any::<u8>(),
    ) {
        let params = fast_kdf_params();
        let salt = test_salt(seed);
        let password: String = (0..pw_len)
            .map(|i| ((i * 37 + seed as usize) % 94 + 33) as u8 as char)
            .collect();

        let kek1 = derive_kek(&password, &salt, params).expect("kek 1");
        let kek2 = derive_kek(&password, &salt, params).expect("kek 2");

        prop_assert_eq!(kek1.as_bytes(), kek2.as_bytes());
    }

    #[test]
    fn prop_kdf_param_sensitivity(seed in any::<u8>()) {
        let salt = test_salt(seed);
        let password = "test-password";
        let base = fast_kdf_params();

        let base_kek = derive_kek(password, &salt, base).expect("base kek");

        let mut p_m = base;
        p_m.m_cost *= 2;
        let kek_m = derive_kek(password, &salt, p_m).expect("kek m_cost");
        prop_assert_ne!(base_kek.as_bytes(), kek_m.as_bytes());

        let mut p_t = base;
        p_t.t_cost += 1;
        let kek_t = derive_kek(password, &salt, p_t).expect("kek t_cost");
        prop_assert_ne!(base_kek.as_bytes(), kek_t.as_bytes());

        let mut p_p = base;
        p_p.p_cost += 1;
        let kek_p = derive_kek(password, &salt, p_p).expect("kek p_cost");
        prop_assert_ne!(base_kek.as_bytes(), kek_p.as_bytes());
    }
}

// ─── DEK Properties ───────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 100, .. ProptestConfig::default()
    })]

    #[test]
    fn prop_dek_derivation_deterministic(
        vek_seed in any::<u8>(),
        rid_byte in any::<u8>(),
    ) {
        let vek = key_from_seed(vek_seed);
        let rid = [rid_byte; 16];

        let dek1 = derive_dek(&vek, &rid).expect("dek 1");
        let dek2 = derive_dek(&vek, &rid).expect("dek 2");

        prop_assert_eq!(dek1.as_bytes(), dek2.as_bytes());
    }

    #[test]
    fn prop_different_rids_different_deks(
        vek_seed in any::<u8>(),
        rid1 in any::<u8>(),
        rid2 in any::<u8>(),
    ) {
        prop_assume!(rid1 != rid2);

        let vek = key_from_seed(vek_seed);
        let r1 = [rid1; 16];
        let r2 = [rid2; 16];

        let dek1 = derive_dek(&vek, &r1).expect("dek 1");
        let dek2 = derive_dek(&vek, &r2).expect("dek 2");

        prop_assert_ne!(dek1.as_bytes(), dek2.as_bytes());
    }
}

// ─── Serialization Properties ─────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 100, .. ProptestConfig::default()
    })]

    #[test]
    fn prop_serialize_deserialize_roundtrip(
        count in 0usize..50,
        record_len in 0usize..256,
        seed in any::<u8>(),
    ) {
        let records: Vec<(RecordId, Ciphertext)> = (0..count)
            .map(|i| {
                let id = [(i % 256) as u8; 16];
                let nonce = Nonce::from_bytes([((i * 7 + seed as usize) % 256) as u8; 24]);
                let data: Vec<u8> = (0..record_len).map(|j| ((i + j) % 251) as u8).collect();
                let ct = Ciphertext { nonce, data };
                (id, ct)
            })
            .collect();

        let bytes = serialize_records(&records);
        let recovered = deserialize_records(&bytes).expect("deserialize must succeed");

        prop_assert_eq!(recovered.len(), records.len());
        for ((orig_id, orig_ct), (rec_id, rec_ct)) in records.iter().zip(recovered.iter()) {
            prop_assert_eq!(orig_id, rec_id);
            prop_assert_eq!(orig_ct.nonce.as_bytes(), rec_ct.nonce.as_bytes());
            prop_assert_eq!(orig_ct.data, rec_ct.data);
        }
    }

    #[test]
    fn prop_record_encrypt_with_dek_roundtrip(
        vek_seed in any::<u8>(),
        rid_byte in any::<u8>(),
        pt_len in 0usize..1024,
    ) {
        let vek = key_from_seed(vek_seed);
        let rid = [rid_byte; 16];
        let dek = derive_dek(&vek, &rid).expect("derive dek");

        let plaintext: Vec<u8> = (0..pt_len).map(|i| (i % 251) as u8).collect();

        let ct = encrypt_record(&dek, &plaintext).expect("encrypt");
        let recovered = decrypt_record(&dek, &ct).expect("decrypt");

        prop_assert_eq!(recovered, plaintext);
    }
}
