//! TOTP / HOTP (RFC 6238 / RFC 4226) implementation.
//!
//! Generates and validates Time-based One-Time Passwords using HMAC-SHA256.
//!
//! ## Algorithm (RFC 6238)
//!
//! 1. Compute time step: `T = (current_unix_time) / time_step`
//! 2. HMAC-SHA256(secret, T)
//! 3. Dynamic truncation: last 4 bits = offset, extract 31-bit value
//! 4. Modulo 10^digits → numeric code

use crate::error::{Error, Result};

use hmac::Mac;

/// Default TOTP time step in seconds (30 seconds per RFC 6238).
pub const DEFAULT_TIME_STEP: u64 = 30;

/// Default code length (6 digits).
pub const DEFAULT_DIGITS: usize = 6;

/// RFC 4648 base32 alphabet decode table (indexed by ASCII code).
fn b32_decode_table() -> [u8; 128] {
    let mut t = [255u8; 128];
    let mut i = 0u8;
    while i < 26 {
        t[(b'A' + i) as usize] = i;
        t[(b'a' + i) as usize] = i;
        i += 1;
    }
    i = 26;
    while i < 32 {
        t[(b'2' + (i - 26)) as usize] = i;
        i += 1;
    }
    t[b'=' as usize] = 0;
    t
}

/// A TOTP configuration.
#[derive(Debug, Clone)]
pub struct TotpConfig {
    /// Raw shared secret bytes.
    pub secret: Vec<u8>,
    /// Time step in seconds.
    pub time_step: u64,
    /// Number of digits in the code.
    pub digits: usize,
}

impl TotpConfig {
    /// Build a config from a base32-encoded shared secret.
    pub fn from_secret_b32(secret_b32: &str, time_step: u64, digits: usize) -> Result<Self> {
        let secret = decode_base32(secret_b32)?;
        Ok(Self {
            secret,
            time_step,
            digits,
        })
    }

    /// Build a config from raw secret bytes.
    pub fn from_secret_raw(secret: Vec<u8>, time_step: u64, digits: usize) -> Self {
        Self {
            secret,
            time_step,
            digits,
        }
    }
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            secret: vec![0u8; 20],
            time_step: DEFAULT_TIME_STEP,
            digits: DEFAULT_DIGITS,
        }
    }
}

/// Decode an RFC 4648 base32 string (case-insensitive, padding optional).
fn decode_base32(encoded: &str) -> Result<Vec<u8>> {
    let clean: Vec<u8> = encoded
        .as_bytes()
        .iter()
        .copied()
        .filter(|c| *c != b'=' && *c != b' ' && *c != b'\n' && *c != b'\r')
        .collect();

    if clean.is_empty() {
        return Err(Error::Totp("empty base32 input".into()));
    }

    let table = b32_decode_table();
    let mut out = Vec::with_capacity(clean.len() * 5 / 8);
    let mut acc = 0u32;
    let mut bits = 0u32;

    for &byte in &clean {
        if byte as usize >= 128 {
            return Err(Error::Totp(format!("invalid base32 char: {byte:#x}")));
        }
        let val = table[byte as usize];
        if val == 255 {
            return Err(Error::Totp(format!("invalid base32 char: {byte:#x}")));
        }
        acc = (acc << 5) | val as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }

    Ok(out)
}

/// Generate a TOTP code for the current time.
pub fn generate(config: &TotpConfig) -> Result<u32> {
    generate_at(config, current_time_step(config))
}

/// Generate a TOTP code at a specific time step.
pub fn generate_at(config: &TotpConfig, time_step: u64) -> Result<u32> {
    let counter_bytes = time_step.to_be_bytes();

    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&config.secret)
        .map_err(|e| Error::Totp(format!("HMAC init failed: {e}")))?;
    mac.update(&counter_bytes);
    let result = mac.finalize().into_bytes();

    let offset = (result[result.len() - 1] & 0x0F) as usize;
    let code = ((result[offset] & 0x7F) as u32) << 24
        | (result[offset + 1] as u32) << 16
        | (result[offset + 2] as u32) << 8
        | (result[offset + 3] as u32);

    let divisor = 10u32.pow(config.digits as u32);
    Ok(code % divisor)
}

/// Validate a TOTP code against the current time (with window).
///
/// Checks the code at `T`, `T-1`, and `T+1` to allow for clock drift.
pub fn validate(config: &TotpConfig, code: u32) -> Result<bool> {
    let t = current_time_step(config);
    for delta in -1i64..=1 {
        let ts = (t as i64 + delta) as u64;
        let generated = generate_at(config, ts)?;
        // Use slice comparison for constant-time equality.
        let generated_bytes = generated.to_be_bytes();
        let code_bytes = code.to_be_bytes();
        if subtle::ConstantTimeEq::ct_eq(&generated_bytes[..], &code_bytes[..]).into() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Compute the current time step.
fn current_time_step(config: &TotpConfig) -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        / config.time_step
}

#[cfg(test)]
mod tests {
    use super::*;

    // Base32: "Hello World" = JBSWY3DPEHPK3PXP
    const TEST_SECRET: &str = "JBSWY3DPEHPK3PXP";

    fn test_config() -> TotpConfig {
        TotpConfig::from_secret_b32(TEST_SECRET, 30, 6).unwrap()
    }

    #[test]
    fn generate_returns_six_digits() {
        let config = test_config();
        let code = generate(&config).unwrap();
        assert!(code < 1_000_000);
    }

    #[test]
    fn same_counter_same_code() {
        let config = test_config();
        let c0 = generate_at(&config, 100).unwrap();
        let c1 = generate_at(&config, 100).unwrap();
        assert_eq!(c0, c1);
    }

    #[test]
    fn consecutive_counters_differ() {
        let config = test_config();
        let c0 = generate_at(&config, 100).unwrap();
        let c1 = generate_at(&config, 101).unwrap();
        assert!(c0 != c1);
    }

    #[test]
    fn validate_accepts_current_code() {
        let config = test_config();
        let code = generate(&config).unwrap();
        assert!(validate(&config, code).unwrap());
    }

    #[test]
    fn validate_rejects_zero() {
        let config = test_config();
        assert!(!validate(&config, 0).unwrap());
    }

    #[test]
    fn raw_secret_works() {
        let secret = [0xABu8; 20];
        let config = TotpConfig::from_secret_raw(secret.to_vec(), 30, 6);
        let code = generate(&config).unwrap();
        assert!(code < 1_000_000);
    }

    #[test]
    fn invalid_base32_rejected() {
        let result = TotpConfig::from_secret_b32("not-valid!!!", 30, 6);
        assert!(result.is_err());
    }

    #[test]
    fn empty_base32_rejected() {
        let result = TotpConfig::from_secret_b32("", 30, 6);
        assert!(result.is_err());
    }

    #[test]
    fn base32_decoding() {
        let decoded = decode_base32("JBSWY3DPE").unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn base32_decoding_no_padding() {
        let decoded = decode_base32("JBSWY3DPE=").unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn base32_decoding_lowercase() {
        let decoded = decode_base32("jbswy3dpe").unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn custom_time_step() {
        let config = TotpConfig::from_secret_b32(TEST_SECRET, 60, 6).unwrap();
        let code = generate(&config).unwrap();
        assert!(code < 1_000_000);
    }

    #[test]
    fn eight_digit_code() {
        let config = TotpConfig::from_secret_b32(TEST_SECRET, 30, 8).unwrap();
        let code = generate(&config).unwrap();
        assert!(code < 100_000_000);
    }
}
