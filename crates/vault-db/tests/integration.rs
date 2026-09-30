//! Integration tests for the vault-db file-backed storage layer.

use std::sync::atomic::{AtomicUsize, Ordering};

use vault_core::RecordId;
use vault_db::{DbError, VaultFile};

/// Atomically incremented counter used to generate unique test file paths.
static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Build a unique path under `/tmp` for this test invocation.
fn temp_vault_path(label: &str) -> std::path::PathBuf {
    let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    std::env::temp_dir()
        .join(format!("vault-db-test-{label}-{pid}-{n}.vlt"))
}

#[test]
fn create_and_open_locks_vault() {
    let path = temp_vault_path("create-open");

    let store = VaultFile::create(&path, "password123").unwrap();
    assert!(store.is_unlocked());

    drop(store);

    let store2 = VaultFile::open(&path).unwrap();
    assert!(!store2.is_unlocked());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn unlock_with_correct_password() {
    let path = temp_vault_path("unlock-ok");

    {
        let mut store = VaultFile::create(&path, "my-secret-password").unwrap();
        store.put_secret([1u8; 16], b"hello world").unwrap();
    }

    let mut store = VaultFile::open(&path).unwrap();
    store.unlock("my-secret-password").unwrap();
    assert!(store.is_unlocked());
    let plain = store.get_secret([1u8; 16]).unwrap();
    assert_eq!(plain, b"hello world");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn unlock_with_wrong_password_fails() {
    let path = temp_vault_path("unlock-bad");

    let _store = VaultFile::create(&path, "correct-password").unwrap();

    let mut store = VaultFile::open(&path).unwrap();
    let result = store.unlock("wrong-password");
    assert!(result.is_err());
    assert!(!store.is_unlocked());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn lock_then_unlock_roundtrip() {
    let path = temp_vault_path("lock-unlock");

    let mut store = VaultFile::create(&path, "password").unwrap();
    store.put_secret([1u8; 16], b"data1").unwrap();
    store.put_secret([2u8; 16], b"data2").unwrap();

    store.lock().unwrap();
    assert!(!store.is_unlocked());
    assert!(store.vault().is_err());

    store.unlock("password").unwrap();
    assert!(store.is_unlocked());
    assert_eq!(store.get_secret([1u8; 16]).unwrap(), b"data1");
    assert_eq!(store.get_secret([2u8; 16]).unwrap(), b"data2");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn record_crud_operations() {
    let path = temp_vault_path("crud");

    let mut store = VaultFile::create(&path, "pw").unwrap();

    store.put_secret([1u8; 16], b"alpha").unwrap();
    store.put_secret([2u8; 16], b"beta").unwrap();
    store.put_secret([3u8; 16], b"gamma").unwrap();
    assert_eq!(store.record_count(), 3);

    assert_eq!(store.get_secret([1u8; 16]).unwrap(), b"alpha");
    assert_eq!(store.get_secret([2u8; 16]).unwrap(), b"beta");

    store.put_secret([2u8; 16], b"beta-updated").unwrap();
    assert_eq!(store.get_secret([2u8; 16]).unwrap(), b"beta-updated");
    assert_eq!(store.record_count(), 3);

    store.remove_secret([3u8; 16]).unwrap();
    assert_eq!(store.record_count(), 2);
    assert!(store.get_secret([3u8; 16]).is_err());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn list_records_returns_all_ids() {
    let path = temp_vault_path("list");

    let mut store = VaultFile::create(&path, "pw").unwrap();
    store.put_secret([10u8; 16], b"a").unwrap();
    store.put_secret([20u8; 16], b"b").unwrap();
    store.put_secret([30u8; 16], b"c").unwrap();

    let mut ids = store.list_records().unwrap();
    ids.sort();
    assert_eq!(ids, vec![[10u8; 16], [20u8; 16], [30u8; 16]]);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn records_persist_across_reopen() {
    let path = temp_vault_path("persist");

    {
        let mut store = VaultFile::create(&path, "password").unwrap();
        store.put_secret([1u8; 16], b"persisted").unwrap();
        store.put_secret([2u8; 16], b"also-persisted").unwrap();
    }

    let mut store = VaultFile::open(&path).unwrap();
    store.unlock("password").unwrap();
    assert_eq!(store.get_secret([1u8; 16]).unwrap(), b"persisted");
    assert_eq!(store.get_secret([2u8; 16]).unwrap(), b"also-persisted");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn operations_on_locked_vault_fail() {
    let path = temp_vault_path("locked-ops");

    VaultFile::create(&path, "pw").unwrap();
    let mut store = VaultFile::open(&path).unwrap();
    let result = store.put_secret([1u8; 16], b"data");
    assert!(matches!(result, Err(DbError::VaultLocked)));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn different_vaults_have_different_salts() {
    let p1 = temp_vault_path("salt-1");
    let p2 = temp_vault_path("salt-2");

    let s1 = VaultFile::create(&p1, "pw").unwrap();
    let s2 = VaultFile::create(&p2, "pw").unwrap();
    assert_ne!(s1.vault().unwrap().salt(), s2.vault().unwrap().salt());

    let _ = std::fs::remove_file(&p1);
    let _ = std::fs::remove_file(&p2);
}

#[test]
fn tamper_detection_blocks_unlock() {
    let path = temp_vault_path("tamper");

    let mut store = VaultFile::create(&path, "password").unwrap();
    store.put_secret([1u8; 16], b"some data").unwrap();

    let mut data = std::fs::read(&path).unwrap();
    data[60] ^= 0xFF; // tamper with wrapped VEK region
    std::fs::write(&path, &data).unwrap();
    drop(store);

    let mut store = VaultFile::open(&path).unwrap();
    let result = store.unlock("password");
    assert!(result.is_err(), "tampered vault should not unlock");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn invalid_magic_rejected() {
    let path = temp_vault_path("bad-magic");

    let mut data = vec![0u8; 512];
    data[..4].copy_from_slice(b"BAAD");
    std::fs::write(&path, &data).unwrap();

    let result = VaultFile::open(&path);
    assert!(matches!(result, Err(DbError::InvalidFormat(_))));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn too_short_file_rejected() {
    let path = temp_vault_path("short");
    std::fs::write(&path, b"VLT1").unwrap();

    let result = VaultFile::open(&path);
    assert!(matches!(result, Err(DbError::InvalidFormat(_))));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn many_records_roundtrip() {
    let path = temp_vault_path("many");

    let mut store = VaultFile::create(&path, "pw").unwrap();
    for i in 0..50u8 {
        let id = [i; 16];
        let data = format!("record-{}", i);
        store.put_secret(id, data.as_bytes()).unwrap();
    }

    drop(store);
    let mut store = VaultFile::open(&path).unwrap();
    store.unlock("pw").unwrap();

    for i in 0..50u8 {
        let id = [i; 16];
        let expected = format!("record-{}", i);
        assert_eq!(store.get_secret(id).unwrap(), expected.as_bytes());
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn record_id_at_max_value() {
    let path = temp_vault_path("max-id");

    let mut store = VaultFile::create(&path, "pw").unwrap();
    let id: RecordId = [0xFFu8; 16];
    store.put_secret(id, b"max-value-id").unwrap();

    drop(store);
    let mut store = VaultFile::open(&path).unwrap();
    store.unlock("pw").unwrap();
    assert_eq!(store.get_secret(id).unwrap(), b"max-value-id");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn binary_blobs_preserve_exact_bytes() {
    let path = temp_vault_path("binary");

    let mut store = VaultFile::create(&path, "pw").unwrap();
    let payload: Vec<u8> = (0..=255u8).collect();
    store.put_secret([1u8; 16], &payload).unwrap();

    drop(store);
    let mut store = VaultFile::open(&path).unwrap();
    store.unlock("pw").unwrap();
    let recovered = store.get_secret([1u8; 16]).unwrap();
    assert_eq!(recovered, payload);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn many_reopen_cycles_stable() {
    let path = temp_vault_path("reopen-cycle");

    VaultFile::create(&path, "password").unwrap();

    for cycle in 0..10u8 {
        let mut store = VaultFile::open(&path).unwrap();
        store.unlock("password").unwrap();
        let id = [cycle; 16];
        let payload = format!("cycle-{}", cycle);
        store.put_secret(id, payload.as_bytes()).unwrap();
    }

    let mut store = VaultFile::open(&path).unwrap();
    store.unlock("password").unwrap();
    for cycle in 0..10u8 {
        let id = [cycle; 16];
        let expected = format!("cycle-{}", cycle);
        assert_eq!(store.get_secret(id).unwrap(), expected.as_bytes());
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn file_size_grows_with_records() {
    let path = temp_vault_path("growth");

    let mut store = VaultFile::create(&path, "pw").unwrap();
    let size_empty = std::fs::metadata(&path).unwrap().len();

    for i in 0..20u8 {
        store.put_secret([i; 16], b"some-payload").unwrap();
    }

    let size_full = std::fs::metadata(&path).unwrap().len();
    assert!(
        size_full > size_empty,
        "file should grow with records (empty={}, full={})",
        size_empty,
        size_full
    );

    let _ = std::fs::remove_file(&path);
}
