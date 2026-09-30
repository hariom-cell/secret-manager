//! Fuzzing harness for vault file format parsing.
//!
//! Feeds random byte sequences into every parser the vault file format
//! exposes (header, records, complete vault) and verifies that:
//!
//! 1. The parsers never panic.
//! 2. When parsing succeeds, the parsed values are well-formed.
//! 3. `parse_header` is consistent with `parse_header_with_mac` on
//!    well-formed input.
//!
//! Build / run with:
//!   cargo +nightly fuzz run fuzz_format_parse -- -runs=1000000
//!
//! Or as a fuzz-like binary:
//!   cargo run -p vault-fuzz --bin fuzz_format_parse -- 10000

use vault_core::format::{
    deserialize_records, parse_header, parse_header_with_mac, read_vault, HEADER_SIZE,
};

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
                fuzz_format_parse(&data);
            }
        }
    }

    eprintln!("format_parse: {} iterations passed", iterations);
}

fn fuzz_smoke_tests() {
    let cases: &[&[u8]] = &[
        &[],
        &[0u8; 10],
        &[0u8; 100],
        &[0u8; HEADER_SIZE],
        &vec![0u8; HEADER_SIZE + 1024],
        b"VLT1",
        b"VLT1\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        b"bad magic\x00\x00",
    ];
    for case in cases {
        fuzz_format_parse(case);
    }
}

/// Deterministic pseudo-random input generation from a seed.
fn generate_fuzz_input(seed: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(32 + (seed % 4096));
    let mut state = seed as u64;
    for _ in 0..data.capacity() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        data.push((state >> 32) as u8);
    }
    data
}

/// Exercise every parser against `data`. Must never panic.
fn fuzz_format_parse(data: &[u8]) {
    // 1. parse_header: minimal surface area, just magic + version + KDF + salt + wrapped_vek.
    let _ = parse_header(data);

    // 2. parse_header_with_mac: same fields plus a 32-byte HMAC tag.
    let _ = parse_header_with_mac(data);

    // 3. deserialize_records: variable-length, may consume any prefix.
    let _ = deserialize_records(data);

    // 4. read_vault: full file (header + body).
    let _ = read_vault(data);

    // 5. Cross-check: if the data is exactly HEADER_SIZE bytes and parses
    //    as a header, it must also parse as a header-with-mac, and the
    //    KDF params must be round-trip-stable.
    if data.len() == HEADER_SIZE {
        if let Ok((p, salt, wv)) = parse_header(data) {
            if let Ok((p2, salt2, wv2, _mac)) = parse_header_with_mac(data) {
                assert_eq!(p, p2, "kdf params differ between parse_header and parse_header_with_mac");
                assert_eq!(salt, salt2, "salt differs");
                assert_eq!(
                    wv.to_bytes(),
                    wv2.to_bytes(),
                    "wrapped vek differs between parse_header and parse_header_with_mac"
                );
            }
        }
    }

    // 6. Verify that any well-formed header has reasonable KDF param values
    //    (catches deserialization bugs where garbage values are accepted).
    if data.len() >= HEADER_SIZE {
        if let Ok((p, _, _)) = parse_header(data) {
            assert!(p.m_cost > 0, "m_cost should not be zero from valid parse");
            assert!(p.t_cost > 0, "t_cost should not be zero from valid parse");
            assert!(p.p_cost > 0, "p_cost should not be zero from valid parse");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzz_smoke_empty() {
        fuzz_format_parse(&[]);
    }

    #[test]
    fn fuzz_smoke_short() {
        fuzz_format_parse(&[0u8; 50]);
    }

    #[test]
    fn fuzz_smoke_header_sized() {
        fuzz_format_parse(&[0u8; HEADER_SIZE]);
    }

    #[test]
    fn fuzz_smoke_oversized() {
        fuzz_format_parse(&vec![0u8; HEADER_SIZE + 1024]);
    }

    #[test]
    fn fuzz_iterations_100() {
        for i in 0..100 {
            let data = generate_fuzz_input(i);
            fuzz_format_parse(&data);
        }
    }
}
