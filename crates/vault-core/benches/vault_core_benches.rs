//! Performance benchmarks for `vault-core` cryptographic operations.
//!
//! Run with: `cargo bench --bench vault_core_benches`
//!
//! Requires the `criterion` crate as a dev-dependency.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use vault_core::{
    aead::{decrypt_record, encrypt_record},
    dek::{derive_dek, wrap_dek, random_dek},
    kdf::KdfParams,
    types::KeyBytes,
    vek::{Vek, WrappedVek},
    RecordId, Vault,
};

// ─── Benchmarks ─────────────────────────────────────────────────────────────

fn bench_kdf(c: &mut Criterion) {
    let salt = [0xABu8; 32];
    let params = KdfParams::default(); // m_cost: 65536, t_cost: 3, p_cost: 2

    c.bench_function("kdf_derive_kek", |b| {
        b.iter(|| {
            let kek = vault_core::derive_kek("bench-password", &salt, params)
                .expect("kdf must succeed");
            black_box(kek);
        });
    });
}

fn bench_aead_encrypt(c: &mut Criterion) {
    let key = KeyBytes::new([0xCDu8; 32]);

    for size in [64, 512, 4096, 65536].iter() {
        let plaintext = vec![0xEFu8; *size];
        c.bench_with_input(
            BenchmarkId::new("aead_encrypt", size),
            &plaintext,
            |b, pt| {
                b.iter(|| {
                    let ct = encrypt_record(&key, black_box(pt)).expect("encrypt must succeed");
                    black_box(ct);
                });
            },
        );
    }
}

fn bench_aead_decrypt(c: &mut Criterion) {
    let key = KeyBytes::new([0xCDu8; 32]);

    for size in [64, 512, 4096, 65536].iter() {
        let plaintext = vec![0xEFu8; *size];
        let ct = encrypt_record(&key, &plaintext).expect("encrypt must succeed");

        c.bench_with_input(
            BenchmarkId::new("aead_decrypt", size),
            &ct,
            |b, ct| {
                b.iter(|| {
                    let pt = decrypt_record(&key, black_box(ct)).expect("decrypt must succeed");
                    black_box(pt);
                });
            },
        );
    }
}

fn bench_dek_derivation(c: &mut Criterion) {
    let vek = Vek::random();
    let rid = [0x01u8; 16];

    c.bench_function("dek_hkdf_derive", |b| {
        b.iter(|| {
            let dek = derive_dek(vek.as_key_bytes(), &rid).expect("derive must succeed");
            black_box(dek);
        });
    });
}

fn bench_dek_wrap_unwrap(c: &mut Criterion) {
    let vek = Vek::random();
    let kek = KeyBytes::new([0x99u8; 32]);

    c.bench_function("dek_wrap", |b| {
        b.iter(|| {
            let dek = random_dek();
            let wrapped = wrap_dek(vek.as_key_bytes(), &dek).expect("wrap must succeed");
            black_box(wrapped);
        });
    });
}

fn bench_vek_wrap(c: &mut Criterion) {
    let vek = Vek::random();
    let kek = KeyBytes::new([0x99u8; 32]);

    c.bench_function("vek_wrap", |b| {
        b.iter(|| {
            let wrapped = vek.wrap(&kek).expect("wrap must succeed");
            black_box(wrapped);
        });
    });
}

fn bench_record_crud(c: &mut Criterion) {
    let mut vault = Vault::create("bench-password").unwrap();

    let ids: Vec<RecordId> = (0..100).map(|i| [i as u8; 16]).collect();
    let values: Vec<Vec<u8>> = (0..100).map(|i| vec![(i % 251) as u8; 256]).collect();

    // Pre-populate
    for (&id, val) in ids.iter().zip(&values) {
        vault.add_secret(id, val).unwrap();
    }

    c.bench_function("record_get_100", |b| {
        b.iter(|| {
            for &id in &ids {
                let pt = vault.get_secret(&id).expect("get must succeed");
                black_box(pt);
            }
        });
    });

    c.bench_function("record_add_100", |b| {
        let mut new_vault = Vault::create("bench-password-2").unwrap();
        b.iter(|| {
            for (&id, val) in ids.iter().zip(&values) {
                new_vault.add_secret(id, black_box(val.as_slice())).unwrap();
            }
        });
    });
}

fn bench_full_lifecycle(c: &mut Criterion) {
    c.bench_function("vault_create_unlock_lock", |b| {
        b.iter(|| {
            let vault = Vault::create("bench-lifecycle").expect("create must succeed");
            let wrapped = vault.wrapped_vek().expect("wrap must succeed");
            drop(vault);

            let mut vault2 = Vault::unlock_existing("bench-lifecycle", KdfParams::default(), [0u8; 32], &wrapped)
                .expect("unlock must succeed");
            black_box(&mut vault2);
            vault2.lock();
        });
    });
}

// ─── Group & Main ───────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_kdf,
    bench_aead_encrypt,
    bench_aead_decrypt,
    bench_dek_derivation,
    bench_dek_wrap_unwrap,
    bench_vek_wrap,
    bench_record_crud,
    bench_full_lifecycle,
);

criterion_main!(benches);
