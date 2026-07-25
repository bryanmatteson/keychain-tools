//! Secret bytes and the randomness that produces them.
//!
//! Key material lives in [`SecretBytes`], which is zeroed when it drops and
//! never prints its contents: a keychain's derived keys, item keys and decrypted
//! secrets all pass through it.

use std::fmt;
use std::ops::Deref;

use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroize;

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

/// Fill a buffer from the OS CSPRNG.
///
/// Every salt, IV and key this crate writes comes from here.
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_do_not_print_themselves() {
        let secret = SecretBytes::new(b"hunter2".to_vec());
        assert_eq!(format!("{secret:?}"), "SecretBytes([REDACTED])");
        assert_eq!(secret.as_slice(), b"hunter2");
    }

    #[test]
    fn random_bytes_are_the_length_asked_for_and_not_constant() {
        assert_eq!(random_bytes(24).len(), 24);
        assert_ne!(random_bytes(24), random_bytes(24));
    }
}
