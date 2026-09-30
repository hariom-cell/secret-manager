//! Argon2id KDF — master password to KEK derivation (section 5, RFC 9106).
//!
//! ## Parameters
//!
//! ```text
//! m_cost = 65536  (64 MiB memory)
//! t_cost = 3      (3 passes)
//! p_cost = 2      (2 parallel lanes)
//! output = 256 bits
//! ```
//!
//! These values are stored in the vault file header so decryption is
//! reproducible regardless of when the vault was created.
//!
//! ## Security floor
//!
//! Any [`KdfParams`] used at unlock time is validated against the minimum
//! floor defined by [`MIN_M_COST`], [`MIN_T_COST`], and [`MIN_P_COST`].
//! We refuse to derive a key with parameters below these values, so a
//! tampered vault file cannot trick the application into a fast unlock
//! that an attacker could brute-force.

use crate::{error::Result, types::KeyBytes};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

/// Minimum allowed Argon2id memory cost in KiB (8 MiB).
///
/// Rejecting anything below this prevents a tampered header from forcing
/// a fast (and thus brute-forceable) derivation.
pub const MIN_M_COST: u32 = 8192;

/// Minimum allowed Argon2id time cost (passes).
pub const MIN_T_COST: u32 = 2;

/// Minimum allowed Argon2id parallelism (lanes).
pub const MIN_P_COST: u32 = 1;

/// Argon2id parameters — serialized into the vault file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB. Default: 65536 (64 MiB).
    pub m_cost: u32,
    /// Time cost (number of passes). Default: 3.
    pub t_cost: u32,
    /// Parallelism (lanes). Default: 2.
    pub p_cost: u32,
}

impl KdfParams {
    /// Validate that the parameters meet the minimum security floor.
    ///
    /// Returns an error if any parameter is below its minimum threshold.
    /// This prevents attackers from tampering with the vault header to
    /// reduce the cost of brute-forcing the master password.
    pub fn validate(&self) -> Result<()> {
        if self.m_cost < MIN_M_COST {
            return Err(crate::Error::KeyDerivation(format!(
                "m_cost {} below minimum {} (rejected — possible tampering)",
                self.m_cost, MIN_M_COST
            )));
        }
        if self.t_cost < MIN_T_COST {
            return Err(crate::Error::KeyDerivation(format!(
                "t_cost {} below minimum {} (rejected — possible tampering)",
                self.t_cost, MIN_T_COST
            )));
        }
        if self.p_cost < MIN_P_COST {
            return Err(crate::Error::KeyDerivation(format!(
                "p_cost {} below minimum {} (rejected — possible tampering)",
                self.p_cost, MIN_P_COST
            )));
        }
        Ok(())
    }

    /// Validate and build Argon2 Params. Rejects impossible values.
    fn to_argon2_params(&self) -> Result<Params> {
        Params::new(self.m_cost, self.t_cost, self.p_cost, Some(32))
            .map_err(|e| crate::Error::KeyDerivation(format!("invalid params: {e}")))
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 2,
        }
    }
}

impl Zeroize for KdfParams {
    fn zeroize(&mut self) {
        self.m_cost.zeroize();
        self.t_cost.zeroize();
        self.p_cost.zeroize();
    }
}

/// Derive a KEK from a master password and vault salt using Argon2id.
///
/// The KEK is the key used to wrap the VEK. It is never stored directly —
/// it is re-derived on every vault unlock.
///
/// # Arguments
/// - `password`: the user's master password (UTF-8)
/// - `salt`: 256-bit vault salt (from `VaultSalt::random()` or the file header)
/// - `params`: Argon2id parameters (stored in the vault file header)
///
/// # Returns
/// 256-bit KEK as [`KeyBytes`].
///
/// # Errors
/// Returns an error if the parameters fail the security-floor validation
/// (see [`KdfParams::validate`]) or if Argon2id itself fails.
pub fn derive_kek(password: &str, salt: &[u8; 32], params: KdfParams) -> Result<KeyBytes> {
    params.validate()?;
    let argon2_params = params.to_argon2_params()?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut key_material = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key_material)
        .map_err(|e| crate::Error::KeyDerivation(format!("argon2 failed: {e}")))?;

    Ok(KeyBytes::new(key_material))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: full derivation with default params.
    fn kek(password: &str, salt: &[u8; 32]) -> KeyBytes {
        derive_kek(password, salt, KdfParams::default()).unwrap()
    }

    #[test]
    fn deterministic_output() {
        let salt = [0x42u8; 32];
        let a = kek("password", &salt);
        let b = kek("password", &salt);
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_passwords_different_keys() {
        let salt = [0x42u8; 32];
        assert_ne!(kek("a", &salt).as_bytes(), kek("b", &salt).as_bytes());
    }

    #[test]
    fn different_salts_different_keys() {
        assert_ne!(kek("pw", &[0x11u8; 32]).as_bytes(), kek("pw", &[0x22u8; 32]).as_bytes());
    }

    #[test]
    fn output_is_32_bytes() {
        let salt = [0x42u8; 32];
        assert_eq!(kek("test", &salt).as_bytes().len(), 32);
    }

    #[test]
    fn empty_password_derives_key() {
        let salt = [0x42u8; 32];
        // Empty password is valid input (user chose it).
        let key = kek("", &salt);
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn custom_params_work() {
        let salt = [0x42u8; 32];
        let custom = KdfParams { m_cost: 32768, t_cost: 2, p_cost: 1 };
        let key = derive_kek("pw", &salt, custom).unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn custom_params_produce_different_key_than_default() {
        let salt = [0x42u8; 32];
        let default = derive_kek("pw", &salt, KdfParams::default()).unwrap();
        let custom = KdfParams { m_cost: 32768, t_cost: 2, p_cost: 2 };
        let slow = derive_kek("pw", &salt, custom).unwrap();
        assert_ne!(default.as_bytes(), slow.as_bytes());
    }

    #[test]
    fn default_params_are_sensible() {
        let p = KdfParams::default();
        assert_eq!(p.m_cost, 65536);
        assert_eq!(p.t_cost, 3);
        assert_eq!(p.p_cost, 2);
    }

    #[test]
    fn default_params_pass_validation() {
        assert!(KdfParams::default().validate().is_ok());
    }

    #[test]
    fn reject_m_cost_below_minimum() {
        let bad = KdfParams { m_cost: MIN_M_COST - 1, t_cost: 3, p_cost: 2 };
        assert!(bad.validate().is_err());
        assert!(derive_kek("pw", &[0u8; 32], bad).is_err());
    }

    #[test]
    fn reject_t_cost_below_minimum() {
        let bad = KdfParams { m_cost: 65536, t_cost: MIN_T_COST - 1, p_cost: 2 };
        assert!(bad.validate().is_err());
        assert!(derive_kek("pw", &[0u8; 32], bad).is_err());
    }

    #[test]
    fn reject_p_cost_below_minimum() {
        let bad = KdfParams { m_cost: 65536, t_cost: 3, p_cost: 0 };
        assert!(bad.validate().is_err());
        assert!(derive_kek("pw", &[0u8; 32], bad).is_err());
    }

    #[test]
    fn minimum_params_accepted() {
        let at_floor = KdfParams { m_cost: MIN_M_COST, t_cost: MIN_T_COST, p_cost: MIN_P_COST };
        assert!(at_floor.validate().is_ok());
    }
}
