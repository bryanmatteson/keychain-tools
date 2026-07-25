//! Keychain cryptography: master key derivation, the database blob, wrapped
//! item keys, and item secrets.
//!
//! The dtformats specification covers the container but not the encryption, so
//! the blob layouts here come from Apple's own `ssblob.h`
//! (`Security/OSX/libsecurityd/lib/ssblob.h`, `CommonBlob`/`DbBlob`/`KeyBlob`)
//! and the key-unwrap sequence from `securityd`'s `BLOBFORMAT` notes as
//! implemented by `chainbreaker`. Every value here is checked against keychains
//! written by macOS in `tests/keychain_crypto.rs`.
//!
//! The chain is:
//!
//! ```text
//! password --PBKDF2-SHA1(salt, 1000, 24)--> master key
//! master key --3DES-CBC(DbBlob.iv)--> DbBlob crypto blob
//!                                     -> encryption key (24) + signing key (20)
//! encryption key --unwrap(KeyBlob)--> item key
//! item key --3DES-CBC(SSGP.iv)--> item secret
//! ```
//!
//! Everything is 3DES (EDE, three-key) in CBC mode. That is what the format
//! specifies; it is not a choice this code makes.

use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use des::TdesEde3;
use hmac::Hmac;
use sha1::Sha1;

use crate::acl::AclBlob;
use crate::cssm::{KeyHeader, WrappedKeyFields};
use crate::error::{Error, Result};

type Decryptor = cbc::Decryptor<TdesEde3>;
type Encryptor = cbc::Encryptor<TdesEde3>;

/// `CommonBlob::magicNumber`.
pub const BLOB_MAGIC: u32 = 0xfade_0711;

/// `CommonBlob::version_MacOS_10_0`. Blobs at this version — and only this
/// version — are signed with [`legacy_hmac_sha1`].
pub const BLOB_VERSION_MACOS_10_0: u32 = 0x0000_0100;

/// `CommonBlob::version_MacOS_10_1`.
pub const BLOB_VERSION_MACOS_10_1: u32 = 0x0000_0101;

/// `CommonBlob::version_partition`, written for keychains under
/// `~/Library/Keychains` since macOS 10.11.4. Signed with real HMAC-SHA1.
pub const BLOB_VERSION_PARTITION: u32 = 0x0000_0200;

/// The version this code writes for a new keychain, matching what
/// `security create-keychain` writes outside `~/Library/Keychains`.
pub const BLOB_VERSION: u32 = BLOB_VERSION_MACOS_10_0;

/// 3DES block size, and so the IV size for the item and database blobs.
pub const BLOCK_SIZE: usize = 8;

/// 3DES-EDE3 key length.
pub const KEY_LEN: usize = 24;

/// PBKDF2 salt length in a `DbBlob`.
pub const SALT_LEN: usize = 20;

/// PBKDF2 iteration count. Fixed by the format, and by today's standards far
/// too low — see the security notes in `README.md`.
pub const PBKDF2_ITERATIONS: u32 = 1000;

/// `sizeof(DbBlob)`: the fixed part, before the public ACL.
pub const DB_BLOB_LEN: usize = 92;

/// `sizeof(KeyBlob)`: the fixed part, before the public ACL.
pub const KEY_BLOB_LEN: usize = 136;

/// The fixed IV Apple's key wrapping uses for its first pass. From
/// `libsecurity_keychain`'s `KeyItem.cpp`; not a nonce, and not secret.
pub const MAGIC_CMS_IV: [u8; 8] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

/// Bytes that mark an item's secure-storage group.
pub const SSGP_MAGIC: &[u8; 4] = b"ssgp";

/// A secret that is zeroed when dropped.
pub use crate::secret::SecretBytes;

/// Derive the master key from a keychain password.
pub fn master_key(password: &[u8], salt: &[u8]) -> SecretBytes {
    let mut key = [0u8; KEY_LEN];
    pbkdf2::pbkdf2::<Hmac<Sha1>>(password, salt, PBKDF2_ITERATIONS, &mut key)
        .expect("PBKDF2 output length is valid");
    SecretBytes::new(key.as_slice())
}

/// 3DES-CBC decrypt, then strip and verify the padding.
///
/// The padding is the CSSM variant: every byte holds the pad length, which is
/// 1..=8. A bad pad byte is how a wrong password shows up, so it is reported as
/// a distinct error rather than as garbage.
pub fn decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if key.len() != KEY_LEN {
        return Err(Error::Crypto("3DES key must be 24 bytes"));
    }
    if iv.len() != BLOCK_SIZE {
        return Err(Error::Crypto("3DES IV must be 8 bytes"));
    }
    if data.is_empty() || !data.len().is_multiple_of(BLOCK_SIZE) {
        return Err(Error::Crypto(
            "ciphertext length is not a multiple of the block size",
        ));
    }

    let mut buffer = data.to_vec();
    Decryptor::new_from_slices(key, iv)
        .map_err(|_| Error::Crypto("invalid 3DES key or IV"))?
        .decrypt_padded_mut::<NoPadding>(&mut buffer)
        .map_err(|_| Error::Crypto("3DES decryption failed"))?;

    let pad = *buffer.last().expect("non-empty") as usize;
    if pad == 0 || pad > BLOCK_SIZE || pad > buffer.len() {
        return Err(Error::WrongPassword);
    }
    if buffer[buffer.len() - pad..]
        .iter()
        .any(|byte| *byte as usize != pad)
    {
        return Err(Error::WrongPassword);
    }
    buffer.truncate(buffer.len() - pad);
    Ok(buffer)
}

/// 3DES-CBC encrypt with the same padding scheme [`decrypt`] expects.
pub fn encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if key.len() != KEY_LEN {
        return Err(Error::Crypto("3DES key must be 24 bytes"));
    }
    if iv.len() != BLOCK_SIZE {
        return Err(Error::Crypto("3DES IV must be 8 bytes"));
    }

    // A full block of padding is added when the input is already aligned, so
    // that the length is always recoverable.
    let pad = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
    let mut buffer = Vec::with_capacity(data.len() + pad);
    buffer.extend_from_slice(data);
    buffer.extend(std::iter::repeat_n(pad as u8, pad));

    let length = buffer.len();
    Encryptor::new_from_slices(key, iv)
        .map_err(|_| Error::Crypto("invalid 3DES key or IV"))?
        .encrypt_padded_mut::<NoPadding>(&mut buffer, length)
        .map_err(|_| Error::Crypto("3DES encryption failed"))?;
    Ok(buffer)
}

/// Sign a blob the way `securityd` signs one at `version`.
///
/// `dbcrypto.cpp` picks `CSSM_ALGID_SHA1HMAC_LEGACY` when — and only when — the
/// blob is at [`BLOB_VERSION_MACOS_10_0`]; every other version, including the
/// partition version that keychains under `~/Library/Keychains` carry, is signed
/// with real HMAC-SHA1. Using the wrong one produces a signature `securityd`
/// rejects, so the version in the blob decides, not a compile-time choice.
pub fn sign_blob(version: u32, key: &[u8], chunks: &[&[u8]]) -> [u8; 20] {
    if version == BLOB_VERSION_MACOS_10_0 {
        return legacy_hmac_sha1(key, chunks);
    }
    let mut mac =
        <Hmac<Sha1> as hmac::Mac>::new_from_slice(key).expect("HMAC takes any key length");
    for chunk in chunks {
        hmac::Mac::update(&mut mac, chunk);
    }
    hmac::Mac::finalize(mac).into_bytes().into()
}

/// HMAC-SHA1 as Apple's `CSSM_ALGID_SHA1HMAC_LEGACY` computes it, over a list of
/// chunks.
///
/// Blobs at version [`BLOB_VERSION`] are signed with this rather than with real
/// HMAC — `securityd/src/dbcrypto.cpp` selects it for
/// `version_MacOS_10_0` and calls it "BSafe bug compatibility". The bug, in
/// `libsecurity_cryptkit/lib/HmacSha1Legacy.c`, is that `hmacLegacyUpdate`
/// computes an entire HMAC on *every* call while leaving the outer hash context
/// in place, so signing two chunks folds the first chunk's result into the
/// second's inner hash:
///
/// ```text
/// inner_1 = SHA1(k_ipad || chunk_1)
/// inner_2 = SHA1(k_opad || inner_1 || k_ipad || chunk_2)
/// mac     = SHA1(k_opad || inner_2)
/// ```
///
/// With a single chunk it degenerates to standard HMAC-SHA1. The keychain
/// signers always pass two, so this is not equivalent to HMAC and must be
/// reproduced exactly. Verified against keychains written by macOS in
/// `tests/keychain_crypto.rs`.
pub fn legacy_hmac_sha1(key: &[u8], chunks: &[&[u8]]) -> [u8; 20] {
    use sha1::Digest as _;

    // The key is XORed into a full 64-byte block; bytes past the key are the pad
    // byte itself, which is what `0x00 ^ pad` comes to.
    let mut k_ipad = [0x36u8; 64];
    let mut k_opad = [0x5cu8; 64];
    for (index, byte) in key.iter().take(64).enumerate() {
        k_ipad[index] = byte ^ 0x36;
        k_opad[index] = byte ^ 0x5c;
    }

    let mut context = Sha1::new();
    for chunk in chunks {
        context.update(k_ipad);
        context.update(chunk);
        let inner = context.finalize_reset();
        // The reference implementation reinitializes here and then starts the
        // outer hash, but never finalizes it before the next chunk.
        context.update(k_opad);
        context.update(inner);
    }
    context.finalize().into()
}

/// The fixed part of a `DbBlob`, the record that makes a keychain unlockable.
#[derive(Debug, Clone)]
pub struct DbBlob {
    pub version: u32,
    /// Offset of the encrypted region; also the end of the public ACL.
    pub start_crypto_blob: u32,
    pub total_length: u32,
    pub random_signature: [u8; 16],
    pub sequence: u32,
    pub idle_timeout: u32,
    pub lock_on_sleep: bool,
    /// The three bytes the compiler's padding of `DBParameters` leaves after
    /// `lockOnSleep`.
    ///
    /// securityd signs its own uninitialized fill here — `aa aa aa` in
    /// practice — and the signature covers it, so a rewrite that zeroed them
    /// would be writing bytes macOS did not. They are carried through instead.
    pub parameters_padding: [u8; 3],
    pub salt: [u8; SALT_LEN],
    pub iv: [u8; BLOCK_SIZE],
    /// Legacy HMAC-SHA1 of the blob, keyed by the signing key. securityd
    /// refuses to unlock a keychain whose signature does not match, so this is
    /// computed on write; see [`Self::sign`].
    pub blob_signature: [u8; 20],
    /// Public ACL, between the fixed part and the encrypted region. This one
    /// does not follow the item-ACL layout, so it is carried as bytes.
    pub public_acl: Vec<u8>,
    /// The encrypted region: the database's own keys.
    pub crypto_blob: Vec<u8>,
}

impl DbBlob {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < DB_BLOB_LEN {
            return Err(Error::format(
                "database blob is shorter than its fixed header",
            ));
        }
        let magic = be32(data, 0);
        if magic != BLOB_MAGIC {
            return Err(Error::format(format!(
                "database blob magic is 0x{magic:08x}, expected 0x{BLOB_MAGIC:08x}"
            )));
        }

        let start_crypto_blob = be32(data, 8);
        let total_length = be32(data, 12);
        if (start_crypto_blob as usize) < DB_BLOB_LEN
            || total_length < start_crypto_blob
            || total_length as usize > data.len()
        {
            return Err(Error::format("database blob offsets are inconsistent"));
        }

        Ok(Self {
            version: be32(data, 4),
            start_crypto_blob,
            total_length,
            random_signature: data[16..32].try_into().expect("16 bytes"),
            sequence: be32(data, 32),
            idle_timeout: be32(data, 36),
            lock_on_sleep: data[40] != 0,
            parameters_padding: [data[41], data[42], data[43]],
            salt: data[44..64].try_into().expect("20 bytes"),
            iv: data[64..72].try_into().expect("8 bytes"),
            blob_signature: data[72..92].try_into().expect("20 bytes"),
            public_acl: data[DB_BLOB_LEN..start_crypto_blob as usize].to_vec(),
            crypto_blob: data[start_crypto_blob as usize..total_length as usize].to_vec(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let start_crypto_blob = (DB_BLOB_LEN + self.public_acl.len()) as u32;
        let total_length = start_crypto_blob + self.crypto_blob.len() as u32;

        let mut out = Vec::with_capacity(total_length as usize);
        out.extend_from_slice(&BLOB_MAGIC.to_be_bytes());
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&start_crypto_blob.to_be_bytes());
        out.extend_from_slice(&total_length.to_be_bytes());
        out.extend_from_slice(&self.random_signature);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.idle_timeout.to_be_bytes());
        // DBParameters is { uint32 idleTimeout; uint8 lockOnSleep; }, which the
        // compiler pads to 8 bytes.
        out.push(u8::from(self.lock_on_sleep));
        out.extend_from_slice(&self.parameters_padding);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.iv);
        out.extend_from_slice(&self.blob_signature);
        out.extend_from_slice(&self.public_acl);
        out.extend_from_slice(&self.crypto_blob);
        out
    }

    /// Unlock: derive the master key and open the crypto blob.
    pub fn unlock(&self, password: &[u8]) -> Result<DbKeys> {
        let master = master_key(password, &self.salt);
        let plain = decrypt(master.as_slice(), &self.iv, &self.crypto_blob)?;
        DbKeys::parse(&plain)
    }

    /// Build the crypto blob for a set of database keys, and sign the result.
    pub fn seal(&mut self, password: &[u8], keys: &DbKeys) -> Result<()> {
        let master = master_key(password, &self.salt);
        self.crypto_blob = encrypt(master.as_slice(), &self.iv, &keys.to_bytes())?;
        self.start_crypto_blob = (DB_BLOB_LEN + self.public_acl.len()) as u32;
        self.total_length = self.start_crypto_blob + self.crypto_blob.len() as u32;
        self.sign(keys.signing_key.as_slice());
        Ok(())
    }

    /// Offset of `blobSignature` within the blob: where the first signed chunk
    /// ends.
    const SIGNATURE_OFFSET: usize = 72;

    /// The two chunks securityd signs: everything before the signature field,
    /// then the public ACL and crypto blob (skipping the signature itself and
    /// the fields between).
    fn signed_chunks(bytes: &[u8]) -> [&[u8]; 2] {
        [&bytes[..Self::SIGNATURE_OFFSET], &bytes[DB_BLOB_LEN..]]
    }

    /// Recompute `blob_signature`. Call after any change to the blob.
    pub fn sign(&mut self, signing_key: &[u8]) {
        self.blob_signature = [0u8; 20];
        let bytes = self.to_bytes();
        self.blob_signature = sign_blob(self.version, signing_key, &Self::signed_chunks(&bytes));
    }

    /// True when the stored signature matches the blob's contents.
    pub fn verify(&self, signing_key: &[u8]) -> bool {
        let bytes = self.to_bytes();
        sign_blob(self.version, signing_key, &Self::signed_chunks(&bytes)) == self.blob_signature
    }
}

/// `DbBlob::PrivateBlob`: the keys that protect everything in the keychain.
#[derive(Debug, Clone)]
pub struct DbKeys {
    /// Wraps the per-item keys.
    pub encryption_key: SecretBytes,
    /// Signs blobs. Kept so a re-serialized keychain preserves it.
    pub signing_key: SecretBytes,
    /// Private ACL, which follows the keys to the end of the blob. Opaque.
    pub private_acl: Vec<u8>,
}

impl DbKeys {
    pub fn parse(plain: &[u8]) -> Result<Self> {
        if plain.len() < KEY_LEN + 20 {
            return Err(Error::Crypto("database key blob is too short"));
        }
        Ok(Self {
            encryption_key: SecretBytes::new(&plain[..KEY_LEN]),
            signing_key: SecretBytes::new(&plain[KEY_LEN..KEY_LEN + 20]),
            private_acl: plain[KEY_LEN + 20..].to_vec(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(KEY_LEN + 20 + self.private_acl.len());
        out.extend_from_slice(self.encryption_key.as_slice());
        out.extend_from_slice(self.signing_key.as_slice());
        out.extend_from_slice(&self.private_acl);
        out
    }
}

/// The fixed part of a `KeyBlob`: one wrapped key, as stored in a key record.
#[derive(Debug, Clone)]
pub struct KeyBlob {
    pub version: u32,
    pub start_crypto_blob: u32,
    pub total_length: u32,
    pub iv: [u8; BLOCK_SIZE],
    /// The key's CSSM header.
    pub header: KeyHeader,
    /// How the key that follows was wrapped.
    pub wrapped: WrappedKeyFields,
    pub blob_signature: [u8; 20],
    /// The item ACL. Parsed when it follows the layout in [`AclBlob`], and kept
    /// as bytes when it does not, so an unfamiliar policy still round-trips.
    pub public_acl: PublicAcl,
    pub crypto_blob: Vec<u8>,
}

/// A public ACL: understood, or preserved as-is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicAcl {
    Parsed(AclBlob),
    Raw(Vec<u8>),
}

impl PublicAcl {
    pub fn parse(data: &[u8]) -> Self {
        match AclBlob::parse(data) {
            Ok(blob) if blob.to_bytes() == data => Self::Parsed(blob),
            // Anything this does not fully understand is carried unchanged
            // rather than reformatted into something subtly different.
            _ => Self::Raw(data.to_vec()),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Parsed(blob) => blob.to_bytes(),
            Self::Raw(bytes) => bytes.clone(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Parsed(blob) => blob.encoded_len(),
            Self::Raw(bytes) => bytes.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The item name the ACL names, when it was understood.
    pub fn item_name(&self) -> Option<&str> {
        match self {
            Self::Parsed(blob) => blob.item_name(),
            Self::Raw(_) => None,
        }
    }

    /// Applications the ACL restricts decryption to. Empty means either "any
    /// application" or an ACL this build did not parse.
    pub fn trusted_paths(&self) -> Vec<&str> {
        match self {
            Self::Parsed(blob) => blob.trusted_paths(),
            Self::Raw(_) => Vec::new(),
        }
    }

    /// Applications from the canonical item-access entry.
    ///
    /// `None` means the ACL was not understood; an empty slice means any
    /// application.
    pub fn trusted_applications(&self) -> Option<&[crate::acl::TrustedApplication]> {
        match self {
            Self::Parsed(blob) => blob.trusted_applications(),
            Self::Raw(_) => None,
        }
    }
}

impl KeyBlob {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < KEY_BLOB_LEN {
            return Err(Error::format("key blob is shorter than its fixed header"));
        }
        let magic = be32(data, 0);
        if magic != BLOB_MAGIC {
            return Err(Error::format(format!(
                "key blob magic is 0x{magic:08x}, expected 0x{BLOB_MAGIC:08x}"
            )));
        }

        let start_crypto_blob = be32(data, 8);
        let total_length = be32(data, 12);
        if (start_crypto_blob as usize) < KEY_BLOB_LEN
            || total_length < start_crypto_blob
            || total_length as usize > data.len()
        {
            return Err(Error::format("key blob offsets are inconsistent"));
        }

        Ok(Self {
            version: be32(data, 4),
            start_crypto_blob,
            total_length,
            iv: data[16..24].try_into().expect("8 bytes"),
            header: KeyHeader::parse(&data[24..100])?,
            wrapped: WrappedKeyFields::parse(&data[100..116])?,
            blob_signature: data[116..136].try_into().expect("20 bytes"),
            public_acl: PublicAcl::parse(&data[KEY_BLOB_LEN..start_crypto_blob as usize]),
            crypto_blob: data[start_crypto_blob as usize..total_length as usize].to_vec(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let acl = self.public_acl.to_bytes();
        let start_crypto_blob = (KEY_BLOB_LEN + acl.len()) as u32;
        let total_length = start_crypto_blob + self.crypto_blob.len() as u32;

        let mut out = Vec::with_capacity(total_length as usize);
        out.extend_from_slice(&BLOB_MAGIC.to_be_bytes());
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&start_crypto_blob.to_be_bytes());
        out.extend_from_slice(&total_length.to_be_bytes());
        out.extend_from_slice(&self.iv);
        self.header.write(&mut out);
        self.wrapped.write(&mut out);
        out.extend_from_slice(&self.blob_signature);
        out.extend_from_slice(&acl);
        out.extend_from_slice(&self.crypto_blob);
        out
    }

    /// Recover the item key this blob wraps.
    pub fn unwrap_key(&self, encryption_key: &[u8]) -> Result<SecretBytes> {
        unwrap_key(encryption_key, &self.iv, &self.crypto_blob)
    }

    /// Offset of `blobSignature` within the blob.
    const SIGNATURE_OFFSET: usize = 116;

    fn signed_chunks(bytes: &[u8]) -> [&[u8]; 2] {
        [&bytes[..Self::SIGNATURE_OFFSET], &bytes[KEY_BLOB_LEN..]]
    }

    /// Recompute `blob_signature`, the same way securityd does for a key blob.
    /// A key blob carries the database's version, so the algorithm follows it.
    pub fn sign(&mut self, signing_key: &[u8]) {
        self.blob_signature = [0u8; 20];
        let bytes = self.to_bytes();
        self.blob_signature = sign_blob(self.version, signing_key, &Self::signed_chunks(&bytes));
    }

    pub fn verify(&self, signing_key: &[u8]) -> bool {
        let bytes = self.to_bytes();
        sign_blob(self.version, signing_key, &Self::signed_chunks(&bytes)) == self.blob_signature
    }
}

/// Apple's custom key wrapping (`CSSM_KEYBLOB_WRAPPED_FORMAT_APPLE_CUSTOM`).
///
/// The wrapped form is
///
/// ```text
/// outer      = 3DES-CBC(db key, MAGIC_CMS_IV, reverse(iv || inner))
/// inner      = 3DES-CBC(db key, iv, descriptive_data_length || key)
/// ```
///
/// The IV travels inside the wrapped blob as well as in the key blob's header,
/// and the whole buffer is byte-reversed between the two passes. The descriptive
/// data is the key's private ACL, which is empty for a keychain item and for an
/// imported identity, so its length is zero.
///
/// The same scheme wraps both a 24-byte item key and a private key's PKCS#8
/// `PrivateKeyInfo`; only the payload length differs. Use [`unwrap_blob`] and
/// [`wrap_blob`] when the length is not 24.
///
/// Verified both ways against keychains written by macOS: every item key in them
/// unwraps, and re-wrapping the same key reproduces their byte layout.
pub fn unwrap_key(encryption_key: &[u8], iv: &[u8], wrapped: &[u8]) -> Result<SecretBytes> {
    let material = unwrap_blob(encryption_key, iv, wrapped)?;
    if material.as_slice().len() != KEY_LEN {
        return Err(Error::Crypto("unwrapped key is not 24 bytes"));
    }
    Ok(material)
}

/// Unwrap key material of any length: a 24-byte item key, or a private key's
/// PKCS#8 `PrivateKeyInfo`, which is what a private-key record holds.
pub fn unwrap_blob(encryption_key: &[u8], iv: &[u8], wrapped: &[u8]) -> Result<SecretBytes> {
    let mut outer = decrypt(encryption_key, &MAGIC_CMS_IV, wrapped)?;
    if outer.len() < BLOCK_SIZE + 2 * BLOCK_SIZE {
        return Err(Error::Crypto("wrapped key is too short"));
    }
    outer.reverse();

    let (embedded_iv, inner_ciphertext) = outer.split_at(BLOCK_SIZE);
    // The header IV is what securityd uses; the embedded copy should agree.
    let iv = if embedded_iv == iv { embedded_iv } else { iv };

    let inner = decrypt(encryption_key, iv, inner_ciphertext)?;
    if inner.len() < 4 {
        return Err(Error::Crypto(
            "unwrapped key has no descriptive-data length",
        ));
    }
    let descriptive_len = u32::from_be_bytes([inner[0], inner[1], inner[2], inner[3]]) as usize;
    let key_at = 4 + descriptive_len;
    if inner.len() <= key_at {
        return Err(Error::Crypto("unwrapped key is too short"));
    }
    // Everything after the descriptive data is the key: 24 bytes for an item
    // key, a PKCS#8 PrivateKeyInfo for an identity's private key.
    Ok(SecretBytes::new(&inner[key_at..]))
}

/// Apple's custom key wrapping, forwards. Inverse of [`unwrap_key`].
pub fn wrap_key(encryption_key: &[u8], iv: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.len() != KEY_LEN {
        return Err(Error::Crypto("item key must be 24 bytes"));
    }
    wrap_blob(encryption_key, iv, key)
}

/// Wrap key material of any length. Inverse of [`unwrap_blob`].
pub fn wrap_blob(encryption_key: &[u8], iv: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if iv.len() != BLOCK_SIZE {
        return Err(Error::Crypto("3DES IV must be 8 bytes"));
    }

    // No descriptive data: a keychain item's or identity's key has no private
    // ACL. macOS writes a zero length here too.
    let mut inner = Vec::with_capacity(4 + key.len());
    inner.extend_from_slice(&0u32.to_be_bytes());
    inner.extend_from_slice(key);

    let mut buffer = iv.to_vec();
    buffer.extend_from_slice(&encrypt(encryption_key, iv, &inner)?);
    buffer.reverse();
    encrypt(encryption_key, &MAGIC_CMS_IV, &buffer)
}

/// An item's encrypted secret, as stored in the record's key data.
#[derive(Debug, Clone)]
pub struct Ssgp {
    /// `ssgp` plus a 16-byte label: together, the key record's `Label`.
    pub label: [u8; 20],
    pub iv: [u8; BLOCK_SIZE],
    pub ciphertext: Vec<u8>,
}

/// Length of the fixed part of an SSGP blob.
pub const SSGP_HEADER_LEN: usize = 28;

impl Ssgp {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() <= SSGP_HEADER_LEN {
            return Err(Error::format("item has no secure-storage payload"));
        }
        if &data[..4] != SSGP_MAGIC {
            return Err(Error::format("item payload is not a secure-storage group"));
        }
        Ok(Self {
            label: data[..20].try_into().expect("20 bytes"),
            iv: data[20..28].try_into().expect("8 bytes"),
            ciphertext: data[SSGP_HEADER_LEN..].to_vec(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SSGP_HEADER_LEN + self.ciphertext.len());
        out.extend_from_slice(&self.label);
        out.extend_from_slice(&self.iv);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Build a payload for `secret` under `item_key`.
    pub fn seal(
        label: [u8; 20],
        iv: [u8; BLOCK_SIZE],
        item_key: &[u8],
        secret: &[u8],
    ) -> Result<Self> {
        Ok(Self {
            label,
            iv,
            ciphertext: encrypt(item_key, &iv, secret)?,
        })
    }

    pub fn open(&self, item_key: &[u8]) -> Result<SecretBytes> {
        Ok(SecretBytes::new(decrypt(
            item_key,
            &self.iv,
            &self.ciphertext,
        )?))
    }

    /// The label as a hex string, for messages.
    pub fn label_hex(&self) -> String {
        hex::encode(&self.label[4..])
    }
}

fn be32(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6070 test vector 3, which anchors the PBKDF2-HMAC-SHA1 primitive to
    /// a published value independent of this code.
    #[test]
    fn pbkdf2_matches_rfc_6070() {
        let mut out = [0u8; 20];
        pbkdf2::pbkdf2::<Hmac<Sha1>>(b"password", b"salt", 4096, &mut out).unwrap();
        assert_eq!(hex::encode(out), "4b007901b765489abead49d926f721d065a429c1");
    }

    /// And this pins the parameters the keychain format uses: 1000 iterations,
    /// 24 bytes of output. Cross-checked against Python's `hashlib.pbkdf2_hmac`.
    #[test]
    fn master_key_uses_the_formats_parameters() {
        let key = master_key(b"password", b"salt");
        assert_eq!(key.as_slice().len(), KEY_LEN);
        assert_eq!(
            hex::encode(key.as_slice()),
            "6e88be8bad7eae9d9e10aa061224034fed48d03fcbad968b"
        );
    }

    #[test]
    fn encrypt_then_decrypt_round_trips_with_cssm_padding() {
        let key = [0x11u8; KEY_LEN];
        let iv = [0x22u8; BLOCK_SIZE];
        for plaintext in [
            b"".to_vec(),
            b"a".to_vec(),
            b"12345678".to_vec(),  // exactly one block
            b"123456789".to_vec(), // spills into a second
            vec![0xffu8; 64],
        ] {
            let sealed = encrypt(&key, &iv, &plaintext).unwrap();
            assert_eq!(sealed.len() % BLOCK_SIZE, 0);
            assert!(sealed.len() > plaintext.len(), "padding is always added");
            assert_eq!(decrypt(&key, &iv, &sealed).unwrap(), plaintext);
        }
    }

    #[test]
    fn a_wrong_key_is_reported_as_a_wrong_password() {
        let iv = [0x22u8; BLOCK_SIZE];
        let sealed = encrypt(&[0x11u8; KEY_LEN], &iv, b"secret data here").unwrap();
        // Padding almost never validates under the wrong key.
        assert!(matches!(
            decrypt(&[0x33u8; KEY_LEN], &iv, &sealed),
            Err(Error::WrongPassword) | Err(Error::Crypto(_))
        ));
    }

    #[test]
    fn decrypt_rejects_malformed_inputs() {
        let key = [0x11u8; KEY_LEN];
        let iv = [0x22u8; BLOCK_SIZE];
        assert!(decrypt(&key, &iv, b"").is_err());
        assert!(
            decrypt(&key, &iv, b"1234567").is_err(),
            "not a block multiple"
        );
        assert!(decrypt(&key[..8], &iv, b"12345678").is_err(), "short key");
        assert!(decrypt(&key, &iv[..4], b"12345678").is_err(), "short IV");
    }

    #[test]
    fn key_wrapping_round_trips() {
        let encryption_key = [0x5au8; KEY_LEN];
        let iv = [0x77u8; BLOCK_SIZE];
        let item_key = [0xa5u8; KEY_LEN];

        let wrapped = wrap_key(&encryption_key, &iv, &item_key).unwrap();
        let unwrapped = unwrap_key(&encryption_key, &iv, &wrapped).unwrap();
        assert_eq!(unwrapped.as_slice(), item_key);
    }

    #[test]
    fn wrapped_key_has_the_layout_macos_writes() {
        let encryption_key = [0x5au8; KEY_LEN];
        let iv = [0x77u8; BLOCK_SIZE];
        let wrapped = wrap_key(&encryption_key, &iv, &[0xa5u8; KEY_LEN]).unwrap();

        // 8-byte IV plus a 32-byte inner ciphertext, padded to 48 by the outer
        // pass. macOS writes exactly this length for an item key.
        assert_eq!(wrapped.len(), 48);

        let mut outer = decrypt(&encryption_key, &MAGIC_CMS_IV, &wrapped).unwrap();
        assert_eq!(outer.len(), 40);
        outer.reverse();
        assert_eq!(
            &outer[..BLOCK_SIZE],
            &iv,
            "the IV is carried inside the blob"
        );

        let inner = decrypt(&encryption_key, &iv, &outer[BLOCK_SIZE..]).unwrap();
        assert_eq!(&inner[..4], &[0, 0, 0, 0], "descriptive data is empty");
        assert_eq!(&inner[4..], &[0xa5u8; KEY_LEN]);
    }

    #[test]
    fn wrapping_rejects_a_wrong_length_key() {
        assert!(wrap_key(&[0u8; KEY_LEN], &[0u8; BLOCK_SIZE], &[0u8; 16]).is_err());
    }

    #[test]
    fn db_blob_round_trips_through_bytes() {
        let mut blob = DbBlob {
            version: BLOB_VERSION,
            start_crypto_blob: 0,
            total_length: 0,
            random_signature: [7u8; 16],
            sequence: 3,
            idle_timeout: 300,
            lock_on_sleep: true,
            parameters_padding: [0; 3],
            salt: [9u8; SALT_LEN],
            iv: [1u8; BLOCK_SIZE],
            blob_signature: [4u8; 20],
            public_acl: vec![0xaa; 28],
            crypto_blob: Vec::new(),
        };
        let keys = DbKeys {
            encryption_key: SecretBytes::new(vec![0x13; KEY_LEN]),
            signing_key: SecretBytes::new(vec![0x14; 20]),
            private_acl: Vec::new(),
        };
        blob.seal(b"open sesame", &keys).unwrap();

        let bytes = blob.to_bytes();
        assert_eq!(bytes.len(), blob.total_length as usize);
        let parsed = DbBlob::parse(&bytes).unwrap();
        assert_eq!(parsed.start_crypto_blob as usize, DB_BLOB_LEN + 28);
        assert_eq!(parsed.public_acl, blob.public_acl);
        assert_eq!(parsed.salt, blob.salt);
        assert!(parsed.lock_on_sleep);
        assert_eq!(parsed.idle_timeout, 300);

        let opened = parsed.unlock(b"open sesame").unwrap();
        assert_eq!(
            opened.encryption_key.as_slice(),
            keys.encryption_key.as_slice()
        );
        assert_eq!(opened.signing_key.as_slice(), keys.signing_key.as_slice());

        assert!(matches!(parsed.unlock(b"wrong"), Err(Error::WrongPassword)));
    }

    /// A `DbBlob` that `security` wrote into `~/Library/Keychains`, which is why
    /// it is at the partition version. Its signature verifies only with real
    /// HMAC-SHA1; signing it the legacy way is what `securityd` would reject.
    #[test]
    fn a_partition_version_blob_is_signed_with_real_hmac() {
        let bytes = hex::decode(concat!(
            "fade07110000020000000078000000a81c5679b6a9edaa0a4753ce619fdd64b9",
            "000000000000012c01000000ec9c4b45174e6421a2723869afb9eecc31155aa0",
            "623dcb2aa7157013ffda409579631311d74c1b6ef9a5d1f5a79963e700000000",
            "00000001000000010000000000000001000000000100000040692291de02d260",
            "c740c2ba7fc7d6802b6a6b073de5ceb83da1d10afcecbd18315f365d7853670e",
            "ab5456adbb219664",
        ))
        .unwrap();

        let blob = DbBlob::parse(&bytes).unwrap();
        assert_eq!(blob.version, BLOB_VERSION_PARTITION);

        let keys = blob.unlock(b"probepw").expect("unlock");
        assert!(
            blob.verify(keys.signing_key.as_slice()),
            "partition blob signature"
        );

        // The legacy algorithm gives a different answer, so the version really is
        // what selects it.
        let chunks = [
            &bytes[..72],
            &bytes[DB_BLOB_LEN..blob.total_length as usize],
        ];
        assert_ne!(
            legacy_hmac_sha1(keys.signing_key.as_slice(), &chunks),
            blob.blob_signature
        );
        assert_eq!(
            sign_blob(BLOB_VERSION_PARTITION, keys.signing_key.as_slice(), &chunks),
            blob.blob_signature
        );
    }

    #[test]
    fn the_signature_algorithm_follows_the_blob_version() {
        let key = [0x11u8; 20];
        let chunks: [&[u8]; 2] = [b"first", b"second"];

        // Only 0x100 gets the legacy variant.
        assert_eq!(
            sign_blob(BLOB_VERSION_MACOS_10_0, &key, &chunks),
            legacy_hmac_sha1(&key, &chunks)
        );
        for version in [BLOB_VERSION_MACOS_10_1, BLOB_VERSION_PARTITION] {
            assert_ne!(
                sign_blob(version, &key, &chunks),
                legacy_hmac_sha1(&key, &chunks)
            );
        }
        // And the non-legacy path is plain HMAC over the concatenation.
        let mut expected = <Hmac<Sha1> as hmac::Mac>::new_from_slice(&key).unwrap();
        hmac::Mac::update(&mut expected, b"firstsecond");
        assert_eq!(
            sign_blob(BLOB_VERSION_PARTITION, &key, &chunks).to_vec(),
            hmac::Mac::finalize(expected).into_bytes().to_vec()
        );
    }

    #[test]
    fn db_blob_rejects_bad_magic_and_offsets() {
        let mut bytes = vec![0u8; DB_BLOB_LEN];
        assert!(DbBlob::parse(&bytes).is_err(), "zero magic");

        bytes[..4].copy_from_slice(&BLOB_MAGIC.to_be_bytes());
        // start_crypto_blob inside the fixed header is nonsense.
        bytes[8..12].copy_from_slice(&4u32.to_be_bytes());
        assert!(DbBlob::parse(&bytes).is_err());

        assert!(DbBlob::parse(&bytes[..10]).is_err(), "truncated");
    }

    #[test]
    fn ssgp_round_trips_and_carries_its_label() {
        let mut label = [0u8; 20];
        label[..4].copy_from_slice(SSGP_MAGIC);
        label[4..].copy_from_slice(&[0xab; 16]);
        let item_key = [0x3cu8; KEY_LEN];

        let ssgp = Ssgp::seal(label, [0x0fu8; BLOCK_SIZE], &item_key, b"hunter2").unwrap();
        let bytes = ssgp.to_bytes();
        assert_eq!(bytes.len(), SSGP_HEADER_LEN + ssgp.ciphertext.len());

        let parsed = Ssgp::parse(&bytes).unwrap();
        assert_eq!(parsed.label, label);
        assert_eq!(parsed.label_hex(), "ab".repeat(16));
        assert_eq!(parsed.open(&item_key).unwrap().as_slice(), b"hunter2");
    }

    #[test]
    fn ssgp_rejects_payloads_that_are_not_secure_storage() {
        assert!(Ssgp::parse(b"short").is_err());
        let mut data = vec![0u8; 40];
        data[..4].copy_from_slice(b"nope");
        assert!(Ssgp::parse(&data).is_err());
    }
}
