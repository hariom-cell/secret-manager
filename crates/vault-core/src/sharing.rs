//! Sharing protocol — X25519 key agreement + Ed25519 signatures.
//!
//! Sender wraps a [`RecordKey`] so a receiver can decrypt it without ever
//! transmitting the VEK. The flow:
//!
//! 1. Sender creates an ephemeral X25519 keypair (`es`, `Es`)
//! 2. Sender computes `Z = es * receiver_pubkey` (X25519 ECDH)
//! 3. Sender derives `shared_key = HKDF-SHA256(Z, info)` with `es_pub || receiver_pub` as salt
//! 4. Sender encrypts the DEK under `shared_key` with XChaCha20-Poly1305
//! 5. Sender signs `(ephemeral_pub || receiver_pub || ciphertext)` with their Ed25519 key
//! 6. Bundle = `ephemeral_pub || receiver_pub || ciphertext || signature`
//!
//! Receiver reverses with their static X25519 private key and the sender's
//! Ed25519 public key (pulled from the user's address book or out-of-band
//! exchange of long-term identity keys).
//!
//! ## Why this design
//!
//! - **Forward secrecy**: ephemeral sender key — recovering `shared_key`
//!   for one share does not expose it for any other share.
//! - **Authentication**: Ed25519 signature — only the named sender could
//!   have produced this ciphertext.
//! - **No KDF confusion**: HKDF info string `b"vault-share-v1"` so the
//!   same X25519 output cannot be reused for a different purpose.
//! - **Transport-agnostic**: the bundle is bytes; can ride any channel.

use crate::{
    aead::{decrypt_record, encrypt_record, Ciphertext},
    error::Result,
    types::KeyBytes,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, SECRET_KEY_LENGTH};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain separator for HKDF during share key derivation.
const SHARE_INFO: &[u8] = b"vault-share-v1";

/// 32-byte X25519 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiverPublicKey([u8; 32]);

impl ReceiverPublicKey {
    /// Load from raw 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the inner bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The sender's long-term signing identity (Ed25519).
///
/// Separate from the ephemeral X25519 keys used per-share — this is the
/// identity the receiver checks the signature against.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SenderSigningKey {
    inner: SigningKey,
}

impl SenderSigningKey {
    /// Generate a new random signing keypair.
    pub fn random() -> Self {
        let mut bytes = [0u8; SECRET_KEY_LENGTH];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let inner = SigningKey::from_bytes(&bytes);
        bytes.zeroize();
        Self { inner }
    }

    /// Return the public verifying key bytes.
    pub fn public_key(&self) -> SenderVerifyingKey {
        SenderVerifyingKey { inner: self.inner.verifying_key() }
    }

    /// Sign a message. Returns the 64-byte Ed25519 signature.
    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.inner.sign(msg).to_bytes()
    }
}

impl core::fmt::Debug for SenderSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SenderSigningKey(<redacted>)")
    }
}

/// The sender's Ed25519 public key — used by the receiver to verify signatures.
#[derive(Clone, Debug)]
pub struct SenderVerifyingKey {
    inner: VerifyingKey,
}

impl SenderVerifyingKey {
    /// Load from raw 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        VerifyingKey::from_bytes(&bytes)
            .map(|inner| Self { inner })
            .map_err(|e| crate::Error::Crypto(format!("invalid sender public key: {e}")))
    }

    /// Serialize as 32 raw bytes (standard Ed25519 format).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Verify a 64-byte signature over the message.
    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> Result<()> {
        let signature = Signature::from_bytes(sig);
        self.inner
            .verify(msg, &signature)
            .map_err(|_| crate::Error::AuthenticationFailed)
    }
}

impl PartialEq for SenderVerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Eq for SenderVerifyingKey {}

/// Bundle sent to the receiver. Contains everything they need to recover the DEK.
#[derive(Debug, Clone)]
pub struct ShareEnvelope {
    /// Sender's ephemeral X25519 public key (32 bytes).
    pub ephemeral_pubkey: [u8; 32],
    /// Receiver's static X25519 public key (32 bytes, embedded for domain separation).
    pub receiver_pubkey: [u8; 32],
    /// Encrypted DEK (nonce || ciphertext || tag).
    pub encrypted_dek: Vec<u8>,
    /// Sender's Ed25519 signature over the concatenation of all preceding fields.
    pub signature: [u8; 64],
}

impl ShareEnvelope {
    /// Serialize for transport. Length is 32 + 32 + encrypted_dek.len() + 64.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + self.encrypted_dek.len() + 64);
        out.extend_from_slice(&self.ephemeral_pubkey);
        out.extend_from_slice(&self.receiver_pubkey);
        out.extend_from_slice(&self.encrypted_dek);
        out.extend_from_slice(&self.signature);
        out
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 32 + 32 + 64 {
            return Err(crate::Error::CiphertextTooShort { min: 128, got: bytes.len() });
        }
        let mut ephemeral_pubkey = [0u8; 32];
        ephemeral_pubkey.copy_from_slice(&bytes[0..32]);
        let mut receiver_pubkey = [0u8; 32];
        receiver_pubkey.copy_from_slice(&bytes[32..64]);
        let encrypted_dek = bytes[64..bytes.len() - 64].to_vec();
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[bytes.len() - 64..]);
        Ok(Self { ephemeral_pubkey, receiver_pubkey, encrypted_dek, signature })
    }
}

/// Encrypt a record DEK so a specific receiver can decrypt it.
///
/// Returns the [`ShareEnvelope`] ready to be transported via any channel
/// (email, file, QR code, etc.).
pub fn share_dek(
    dek: &KeyBytes,
    receiver_pubkey: &ReceiverPublicKey,
    sender_signing_key: &SenderSigningKey,
) -> Result<ShareEnvelope> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);

    let receiver = X25519PublicKey::from(*receiver_pubkey.as_bytes());
    let shared = ephemeral_secret.diffie_hellman(&receiver);

    let share_key = derive_share_key(&shared.to_bytes(), &ephemeral_public, receiver_pubkey)?;

    let ciphertext = encrypt_record(&share_key, dek.as_bytes())?;

    let mut signed_msg = Vec::new();
    signed_msg.extend_from_slice(ephemeral_public.as_bytes());
    signed_msg.extend_from_slice(receiver_pubkey.as_bytes());
    signed_msg.extend_from_slice(&ciphertext.to_bytes());

    let signature = sender_signing_key.sign(&signed_msg);

    Ok(ShareEnvelope {
        ephemeral_pubkey: *ephemeral_public.as_bytes(),
        receiver_pubkey: *receiver_pubkey.as_bytes(),
        encrypted_dek: ciphertext.to_bytes(),
        signature,
    })
}

/// Decrypt a share envelope to recover the original DEK.
///
/// # Arguments
/// - `envelope`: the bundle received from the sender
/// - `receiver_secret`: the receiver's static X25519 private key
/// - `sender_public`: the sender's long-term Ed25519 public key (out-of-band)
pub fn recover_dek(
    envelope: &ShareEnvelope,
    receiver_secret_bytes: [u8; 32],
    sender_public: &SenderVerifyingKey,
) -> Result<KeyBytes> {
    // Verify signature first — never decrypt without verification.
    let mut msg = Vec::new();
    msg.extend_from_slice(&envelope.ephemeral_pubkey);
    msg.extend_from_slice(&envelope.receiver_pubkey);
    msg.extend_from_slice(&envelope.encrypted_dek);
    sender_public.verify(&msg, &envelope.signature)?;

    let receiver_secret = StaticSecret::from(receiver_secret_bytes);
    let ephemeral_pub = X25519PublicKey::from(envelope.ephemeral_pubkey);
    let shared = receiver_secret.diffie_hellman(&ephemeral_pub);
    let receiver_pub = X25519PublicKey::from(envelope.receiver_pubkey);

    let share_key = derive_share_key(&shared.to_bytes(), &ephemeral_pub, &ReceiverPublicKey::from_bytes(*receiver_pub.as_bytes()))?;

    let ct = Ciphertext::from_bytes(&envelope.encrypted_dek)?;
    let plaintext = decrypt_record(&share_key, &ct)?;

    if plaintext.len() != 32 {
        return Err(crate::Error::InvalidKeyLength { expected: 32, got: plaintext.len() });
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&plaintext);
    Ok(KeyBytes::new(bytes))
}

/// Derive the symmetric encryption key from a shared secret.
///
/// Two parties calling this with matching inputs will derive the same key.
fn derive_share_key(
    shared_secret: &[u8],
    ephemeral_pub: &X25519PublicKey,
    receiver_pub: &ReceiverPublicKey,
) -> Result<KeyBytes> {
    let mut salt_input = Vec::with_capacity(64);
    salt_input.extend_from_slice(ephemeral_pub.as_bytes());
    salt_input.extend_from_slice(receiver_pub.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(&salt_input), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(SHARE_INFO, &mut okm)
        .map_err(|e| crate::Error::Crypto(format!("HKDF failed: {e}")))?;

    Ok(KeyBytes::new(okm))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_receiver() -> ([u8; 32], ReceiverPublicKey) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        (secret.to_bytes(), ReceiverPublicKey::from_bytes(*public.as_bytes()))
    }

    #[test]
    fn roundtrip_with_known_sender() {
        let (receiver_secret, receiver_pub) = fresh_receiver();
        let sender_signing = SenderSigningKey::random();
        let sender_pub = sender_signing.public_key();

        let dek = KeyBytes::new([0xD3u8; 32]);
        let envelope = share_dek(&dek, &receiver_pub, &sender_signing).unwrap();

        let recovered = recover_dek(&envelope, receiver_secret, &sender_pub).unwrap();
        assert_eq!(recovered.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn tampered_signature_rejected() {
        let (receiver_secret, receiver_pub) = fresh_receiver();
        let sender_signing = SenderSigningKey::random();
        let sender_pub = sender_signing.public_key();

        let dek = KeyBytes::new([0xD3u8; 32]);
        let mut envelope = share_dek(&dek, &receiver_pub, &sender_signing).unwrap();
        envelope.signature[0] ^= 1;

        assert!(matches!(
            recover_dek(&envelope, receiver_secret, &sender_pub),
            Err(crate::Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let (receiver_secret, receiver_pub) = fresh_receiver();
        let sender_signing = SenderSigningKey::random();
        let sender_pub = sender_signing.public_key();

        let dek = KeyBytes::new([0xD3u8; 32]);
        let mut envelope = share_dek(&dek, &receiver_pub, &sender_signing).unwrap();
        envelope.encrypted_dek[0] ^= 1;

        assert!(matches!(
            recover_dek(&envelope, receiver_secret, &sender_pub),
            Err(crate::Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn wrong_sender_rejected() {
        let (receiver_secret, receiver_pub) = fresh_receiver();
        let sender_signing = SenderSigningKey::random();
        let wrong_sender_pub = SenderSigningKey::random().public_key();

        let dek = KeyBytes::new([0xD3u8; 32]);
        let envelope = share_dek(&dek, &receiver_pub, &sender_signing).unwrap();

        assert!(matches!(
            recover_dek(&envelope, receiver_secret, &wrong_sender_pub),
            Err(crate::Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn envelope_serde_roundtrip() {
        let (_, receiver_pub) = fresh_receiver();
        let sender_signing = SenderSigningKey::random();

        let dek = KeyBytes::new([0xD3u8; 32]);
        let envelope = share_dek(&dek, &receiver_pub, &sender_signing).unwrap();

        let bytes = envelope.to_bytes();
        let restored = ShareEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(restored.ephemeral_pubkey, envelope.ephemeral_pubkey);
        assert_eq!(restored.receiver_pubkey, envelope.receiver_pubkey);
        assert_eq!(restored.encrypted_dek, envelope.encrypted_dek);
        assert_eq!(restored.signature, envelope.signature);
    }

    #[test]
    fn distinct_dek_shares_different_ephemeral_keys() {
        let (_, receiver_pub) = fresh_receiver();
        let sender_signing = SenderSigningKey::random();

        let dek1 = KeyBytes::new([0x01u8; 32]);
        let dek2 = KeyBytes::new([0x02u8; 32]);

        let env1 = share_dek(&dek1, &receiver_pub, &sender_signing).unwrap();
        let env2 = share_dek(&dek2, &receiver_pub, &sender_signing).unwrap();

        assert_ne!(env1.ephemeral_pubkey, env2.ephemeral_pubkey);
    }

    #[test]
    fn envelope_too_short() {
        let bytes = vec![0u8; 50];
        assert!(matches!(
            ShareEnvelope::from_bytes(&bytes),
            Err(crate::Error::CiphertextTooShort { .. })
        ));
    }
}
