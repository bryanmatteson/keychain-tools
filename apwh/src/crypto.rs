//! Hashing, big-integer serialization, and the AES-GCM layer.
//!
//! Two conventions here are load-bearing and easy to get wrong:
//!
//! * Big integers travel as **minimal-length** big-endian bytes (no fixed-width
//!   padding) everywhere except inside the `u` and `k` hashes, which pad to the
//!   384-byte group size. Padding a value that should be minimal changes every
//!   hash downstream of it.
//! * The AES-GCM framing is **asymmetric**. Requests carry the IV as a suffix
//!   (`ciphertext || tag || iv`); responses carry it as a prefix
//!   (`iv || ciphertext || tag`). That is not a transcription slip: both the
//!   `apw` CLI and the `icloud-passwords-firefox` extension do exactly this, and
//!   both interoperate with the shipping helper.

use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::aes::Aes128;
use aes_gcm::{AesGcm, Nonce};
use num_bigint::BigUint;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fmt;
use std::ops::Deref;
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// AES-128-GCM with the helper's 16-byte IV (GCM's usual nonce is 12 bytes; the
/// helper uses 16, which GCM handles by hashing the IV through GHASH).
type HelperCipher = AesGcm<Aes128, U16>;

/// Length of the AES-GCM initialization vector, in bytes.
pub const IV_LEN: usize = 16;

/// Length of the AES key taken from the front of the SRP shared key.
pub const AES_KEY_LEN: usize = 16;

/// Byte buffer that is zeroed on drop and never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

impl Deref for SecretBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// SHA-256 over the concatenation of `parts`.
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Fill a buffer from the OS CSPRNG.
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Minimal-length big-endian bytes, matching JavaScript's
/// `while (n > 0n) { unshift(n & 0xff); n >>= 8n }`.
///
/// Note the shared edge case with the reference implementations: zero encodes as
/// an empty buffer, not `[0x00]`.
pub fn to_bytes_be(value: &BigUint) -> Vec<u8> {
    if value == &BigUint::ZERO {
        Vec::new()
    } else {
        value.to_bytes_be()
    }
}

/// Right-align `bytes` in a `len`-byte buffer, zero-padding on the left.
/// Inputs longer than `len` are truncated to their first `len` bytes.
pub fn pad_left(bytes: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let take = bytes.len().min(len);
    let offset = len.saturating_sub(bytes.len());
    out[offset..offset + take].copy_from_slice(&bytes[..take]);
    out
}

/// Interpret big-endian bytes as an unsigned integer.
pub fn from_bytes_be(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

/// AES key: the first 16 bytes of the SRP shared key's minimal big-endian form.
pub fn aes_key(shared_key: &BigUint) -> Result<SecretBytes> {
    let bytes = to_bytes_be(shared_key);
    if bytes.len() < AES_KEY_LEN {
        return Err(Error::Crypto(
            "SRP shared key is too short to derive an AES key",
        ));
    }
    Ok(SecretBytes::new(&bytes[..AES_KEY_LEN]))
}

fn cipher(key: &SecretBytes) -> Result<HelperCipher> {
    HelperCipher::new_from_slice(key.as_slice())
        .map_err(|_| Error::Crypto("invalid AES key length"))
}

/// Encrypt a request body with a fresh IV. Returns `ciphertext || tag || iv`.
pub fn seal(key: &SecretBytes, plaintext: &[u8]) -> Result<Vec<u8>> {
    seal_with_iv(key, plaintext, &random_bytes(IV_LEN))
}

/// [`seal`] with a caller-supplied IV, so the output can be checked against a
/// known vector. Production code must use [`seal`]: reusing an IV under one key
/// breaks GCM's confidentiality and its authentication.
pub fn seal_with_iv(key: &SecretBytes, plaintext: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    if iv.len() != IV_LEN {
        return Err(Error::Crypto("initialization vector must be 16 bytes"));
    }
    let mut out = cipher(key)?
        .encrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .map_err(|_| Error::Crypto("failed to encrypt request payload"))?;
    out.extend_from_slice(iv);
    Ok(out)
}

/// Decrypt a response body of the form `iv || ciphertext || tag`.
pub fn open(key: &SecretBytes, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() <= IV_LEN {
        return Err(Error::Crypto("encrypted payload is too short"));
    }
    let (iv, body) = data.split_at(IV_LEN);
    cipher(key)?
        .decrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: body,
                aad: &[],
            },
        )
        .map_err(|_| Error::Crypto("failed to decrypt response payload (stale session key?)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_bytes_be_is_minimal_length() {
        assert_eq!(to_bytes_be(&BigUint::from(0u8)), Vec::<u8>::new());
        assert_eq!(to_bytes_be(&BigUint::from(1u8)), vec![1]);
        assert_eq!(to_bytes_be(&BigUint::from(0x0102u16)), vec![1, 2]);
        assert_eq!(to_bytes_be(&BigUint::from(0xffu8)), vec![0xff]);
    }

    #[test]
    fn pad_left_right_aligns_and_truncates() {
        assert_eq!(pad_left(&[1, 2], 4), vec![0, 0, 1, 2]);
        assert_eq!(pad_left(&[1, 2, 3, 4], 4), vec![1, 2, 3, 4]);
        // Matches the reference `pad`: over-long input keeps its leading bytes.
        assert_eq!(pad_left(&[1, 2, 3, 4, 5], 4), vec![1, 2, 3, 4]);
        assert_eq!(pad_left(&[], 2), vec![0, 0]);
    }

    #[test]
    fn sha256_matches_known_vector() {
        // FIPS 180-4 "abc"
        assert_eq!(
            hex::encode(sha256(&[b"a", b"bc"])),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn seal_then_open_round_trips_with_iv_reordered() {
        let key = SecretBytes::new(vec![0x11; AES_KEY_LEN]);
        let sealed = seal(&key, b"{\"ACT\":5}").unwrap();

        // seal() emits ciphertext || tag || iv; open() expects iv first, so a
        // round trip has to move the IV, exactly as the helper does.
        let (body, iv) = sealed.split_at(sealed.len() - IV_LEN);
        let mut response = iv.to_vec();
        response.extend_from_slice(body);

        assert_eq!(open(&key, &response).unwrap(), b"{\"ACT\":5}");
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let key = SecretBytes::new(vec![0x22; AES_KEY_LEN]);
        let sealed = seal(&key, b"secret").unwrap();
        let (body, iv) = sealed.split_at(sealed.len() - IV_LEN);
        let mut response = iv.to_vec();
        response.extend_from_slice(body);
        let last = response.len() - 1;
        response[last] ^= 0x01;

        assert!(open(&key, &response).is_err());
    }

    #[test]
    fn aes_key_takes_the_first_sixteen_bytes() {
        let shared = from_bytes_be(&[0xab; 32]);
        assert_eq!(aes_key(&shared).unwrap().as_slice(), &[0xab; 16]);
    }

    #[test]
    fn secret_bytes_debug_is_redacted() {
        let secret = SecretBytes::new(vec![1, 2, 3]);
        assert_eq!(format!("{secret:?}"), "SecretBytes([REDACTED])");
    }
}
