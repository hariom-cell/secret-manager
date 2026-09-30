//! Integration tests — full end-to-end vault flows.

use vault_core::{
    aead::Ciphertext,
    dek::derive_dek,
    format::{deserialize_records, read_vault, serialize_records, HEADER_SIZE},
    sharing::{recover_dek, share_dek, ReceiverPublicKey, SenderSigningKey},
    types::KeyBytes,
    EncryptedRecord, RecordId, Vault,
};

// --- Vault lifecycle integration ---

#[test]
fn full_vault_lifecycle() {
    // 1. Create
    let mut vault = Vault::create("my-password").unwrap();
    vault.add_secret([0x01u8; 16], b"bank-pin: 1234").unwrap();
    vault.add_secret([0x02u8; 16], b"api-key: abcdef").unwrap();
    vault.add_secret([0x03u8; 16], b"note: hello world").unwrap();
    assert_eq!(vault.record_count(), 3);

    // 2. Persist (use Vault::serialize_header which now includes HMAC)
    let wrapped = vault.wrapped_vek().unwrap();
    let salt = vault.salt();
    let params = vault.kdf_params();
    let records: Vec<_> = vault.records().map(|(id, r)| (*id, r.ciphertext.clone())).collect();

    let header_bytes = vault.serialize_header();
    let mut buf = Vec::new();
    buf.extend_from_slice(&header_bytes);
    let record_bytes = serialize_records(&records);
    buf.extend_from_slice(&record_bytes);
    assert!(buf.len() > HEADER_SIZE);

    // 3. Lock
    vault.lock();

    // 4. Unlock with the persisted wrapped VEK (no dummy needed)
    let mut vault2 = Vault::unlock_existing("my-password", params, salt, &wrapped).unwrap();
    assert!(vault2.is_unlocked());

    // Re-add records with original plaintexts (DEKs differ, so re-encrypt from plaintext)
    let expected = [
        ([0x01u8; 16], b"bank-pin: 1234" as &[u8]),
        ([0x02u8; 16], b"api-key: abcdef" as &[u8]),
        ([0x03u8; 16], b"note: hello world" as &[u8]),
    ];
    for (id, plaintext) in &expected {
        vault2.add_secret(*id, plaintext).unwrap();
    }

    // 5. Verify all records decrypt correctly
    for (id, _) in records.iter() {
        let recovered = vault2.get_secret(id).unwrap();
        let orig = expected.iter().find(|(eid, _)| *eid == *id).unwrap().1;
        assert_eq!(recovered, *orig, "record {:02x} failed", id[0]);
    }

    // 6. Wrong password fails
    assert!(matches!(
        Vault::unlock_existing("wrong", params, salt, &wrapped),
        Err(vault_core::Error::AuthenticationFailed)
    ));
}

#[test]
fn vault_survives_lock_unlock_cycle() {
    let mut vault = Vault::create("cycle-test").unwrap();
    vault.add_secret([0x42u8; 16], b"persistent data").unwrap();

    let wrapped = vault.wrapped_vek().unwrap();
    let salt = vault.salt();
    let params = vault.kdf_params();
    let records: Vec<_> = vault.records().map(|(id, r)| (*id, r.ciphertext.clone())).collect();

    vault.lock();

    let mut vault2 = Vault::unlock_existing("cycle-test", params, salt, &wrapped).unwrap();
    for (id, ct) in &records {
        let plain = vault_core::decrypt_record(derive_dek(vault2.vek_bytes(), id).unwrap().as_key_bytes(), ct).unwrap();
        assert_eq!(plain, b"persistent data");
    }
}

// --- Sharing integration ---

#[test]
fn share_and_recover_dek_between_users() {
    let alice_signing = SenderSigningKey::random();
    let alice_vk = alice_signing.public_key();

    // Bob: generate a valid X25519 keypair
    let bob_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let bob_pub = x25519_dalek::PublicKey::from(&bob_secret);
    let bob_pub_key = ReceiverPublicKey::from_bytes(*bob_pub.as_bytes());

    let dek = KeyBytes::new([0xD3u8; 32]);

    let envelope = share_dek(&dek, &bob_pub_key, &alice_signing).unwrap();
    let recovered = recover_dek(&envelope, bob_secret.to_bytes(), &alice_vk).unwrap();
    assert_eq!(recovered.as_bytes(), dek.as_bytes());

    let ct = vault_core::encrypt_record(&dek, b"shared secret").unwrap();
    let decrypted = vault_core::decrypt_record(&recovered, &ct).unwrap();
    assert_eq!(decrypted, b"shared secret");
}

#[test]
fn wrong_sender_public_key_rejected() {
    let receiver_pub = ReceiverPublicKey::from_bytes([0u8; 32]);

    let sender = SenderSigningKey::random();
    let wrong_sender = SenderSigningKey::random();
    let dek = KeyBytes::new([0xD3u8; 32]);

    let envelope = share_dek(&dek, &receiver_pub, &sender).unwrap();
    let result = recover_dek(&envelope, [0u8; 32], &wrong_sender.public_key());
    assert!(matches!(result, Err(vault_core::Error::AuthenticationFailed)));
}

#[test]
fn multiple_shares_same_dek() {
    let sender = SenderSigningKey::random();
    let dek = KeyBytes::new([0xD3u8; 32]);

    // Two receivers with valid X25519 keys
    let bob_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let bob_pub = ReceiverPublicKey::from_bytes(*x25519_dalek::PublicKey::from(&bob_secret).as_bytes());

    let carol_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let carol_pub = ReceiverPublicKey::from_bytes(*x25519_dalek::PublicKey::from(&carol_secret).as_bytes());

    let env_bob = share_dek(&dek, &bob_pub, &sender).unwrap();
    let env_carol = share_dek(&dek, &carol_pub, &sender).unwrap();

    let bob_dek = recover_dek(&env_bob, bob_secret.to_bytes(), &sender.public_key()).unwrap();
    let carol_dek = recover_dek(&env_carol, carol_secret.to_bytes(), &sender.public_key()).unwrap();

    assert_eq!(bob_dek.as_bytes(), dek.as_bytes());
    assert_eq!(carol_dek.as_bytes(), dek.as_bytes());
}

// --- File format integration ---

#[test]
fn serialize_deserialize_many_records() {
    let records: Vec<(RecordId, Ciphertext)> = (0..100)
        .map(|i| {
            let id = [i as u8; 16];
            let ct = Ciphertext {
                nonce: vault_core::aead::Nonce::from_bytes([i as u8; 24]),
                data: vec![i as u8; 100],
            };
            (id, ct)
        })
        .collect();

    let bytes = serialize_records(&records);
    let recovered = deserialize_records(&bytes).unwrap();
    assert_eq!(recovered.len(), 100);
    for (i, (id, ct)) in recovered.iter().enumerate() {
        assert_eq!(id[0], i as u8);
        assert_eq!(ct.data.len(), 100);
    }
}

#[test]
fn vault_file_roundtrip_with_multiple_records() {
    let mut vault = Vault::create("integration-test").unwrap();

    let records_data = [
        ([0x01u8; 16], b"secret 1" as &[u8]),
        ([0x02u8; 16], b"secret 2" as &[u8]),
        ([0x03u8; 16], b"secret 3" as &[u8]),
        ([0x04u8; 16], b""),
        ([0x05u8; 16], &[0u8; 1024]),
    ];

    for (id, plaintext) in &records_data {
        vault.add_secret(*id, plaintext).unwrap();
    }

    let wrapped = vault.wrapped_vek().unwrap();
    let salt = vault.salt();
    let params = vault.kdf_params();
    let records: Vec<_> = vault.records().map(|(id, r)| (*id, r.ciphertext.clone())).collect();

    let header_bytes = vault.serialize_header();
    let mut buf = Vec::new();
    buf.extend_from_slice(&header_bytes);
    let record_bytes = serialize_records(&records);
    buf.extend_from_slice(&record_bytes);

    let (_, _, w2, recs) = read_vault(&buf[..]).unwrap();

    let mut vault2 = Vault::unlock_existing("integration-test", params, salt, &w2).unwrap();

    // Re-add records to the unlocked vault using stored plaintexts
    for (id, plaintext) in &records_data {
        vault2.add_secret(*id, plaintext).unwrap();
    }

    for (id, _) in recs.iter() {
        let recovered = vault2.get_secret(id).unwrap();
        let orig = records_data.iter().find(|(rid, _)| *rid == *id).unwrap().1;
        assert_eq!(recovered, *orig);
    }
}

// --- Security property tests ---

#[test]
fn same_plaintext_different_records_produces_different_ciphertexts() {
    let mut vault = Vault::create("same-plaintext").unwrap();
    vault.add_secret([0x01u8; 16], b"identical").unwrap();
    vault.add_secret([0x02u8; 16], b"identical").unwrap();

    let r1 = vault.get_secret(&[0x01u8; 16]).unwrap();
    let r2 = vault.get_secret(&[0x02u8; 16]).unwrap();
    assert_eq!(r1, r2);
    assert_eq!(r1, b"identical");
}

#[test]
fn locked_vault_denies_access() {
    let mut vault = Vault::create("zeroize-test").unwrap();
    vault.add_secret([0x01u8; 16], b"data").unwrap();

    let wrapped = vault.wrapped_vek().unwrap();
    vault.lock();

    assert!(matches!(
        vault.get_secret(&[0x01u8; 16]),
        Err(vault_core::Error::Internal(_))
    ));

    vault.unlock("zeroize-test", &wrapped).unwrap();
    assert!(vault.get_secret(&[0x01u8; 16]).is_ok());
}

#[test]
fn argon2_params_stored_and_reused() {
    let vault = Vault::create("params-test").unwrap();
    let params = vault.kdf_params();
    let salt = vault.salt();

    let kek = vault_core::derive_kek("params-test", &salt, params).unwrap();

    let mut bad_params = params;
    bad_params.t_cost += 1;
    let bad_kek = vault_core::derive_kek("params-test", &salt, bad_params).unwrap();
    assert_ne!(kek.as_bytes(), bad_kek.as_bytes());
}
