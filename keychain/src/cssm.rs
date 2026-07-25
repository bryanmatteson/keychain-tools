//! CSSM structures that appear inside keychain blobs, as types.
//!
//! These are the fixed-layout C structs from Apple's CDSA headers
//! (`CSSM_KEYHEADER`, `CSSM_GUID`, `CSSM_DATE`) and `KeyBlob::WrappedFields`
//! from `ssblob.h`. They are modelled field by field rather than carried as
//! opaque bytes, so a key blob written here can be compared with one macOS wrote
//! field by field, and so the values this code chooses are visible in the source
//! instead of hidden in a hex literal.

use crate::error::{Error, Result};

/// `CSSM_GUID`. Stored big-endian in a keychain, unlike the host-order form the
/// CSSM API uses in memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    pub const LEN: usize = 16;

    /// The Apple CSP, which is what wraps every item key in a keychain.
    pub const APPLE_CSP: Self = Self {
        data1: 0x8719_1ca2,
        data2: 0x0fc9,
        data3: 0x11d4,
        data4: [0x84, 0x9a, 0x00, 0x05, 0x02, 0xb5, 0x21, 0x22],
    };

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::LEN {
            return Err(Error::Crypto("GUID is truncated"));
        }
        Ok(Self {
            data1: be32(data, 0),
            data2: u16::from_be_bytes([data[4], data[5]]),
            data3: u16::from_be_bytes([data[6], data[7]]),
            data4: data[8..16].try_into().expect("8 bytes"),
        })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.data1.to_be_bytes());
        out.extend_from_slice(&self.data2.to_be_bytes());
        out.extend_from_slice(&self.data3.to_be_bytes());
        out.extend_from_slice(&self.data4);
    }
}

impl std::fmt::Display for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-",
            self.data1, self.data2, self.data3
        )?;
        for byte in &self.data4 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// `CSSM_DATE`: eight ASCII digits, `YYYYMMDD`, or all zeroes for "unset".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CssmDate(pub [u8; 8]);

impl CssmDate {
    pub const LEN: usize = 8;

    pub fn is_unset(&self) -> bool {
        self.0 == [0u8; 8]
    }
}

/// `CSSM_KEYCLASS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyClass {
    Public,
    Private,
    Session,
    SecretPart,
    Other(u32),
}

impl KeyClass {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::Public,
            1 => Self::Private,
            2 => Self::Session,
            3 => Self::SecretPart,
            other => Self::Other(other),
        }
    }

    pub fn as_u32(self) -> u32 {
        match self {
            Self::Public => 0,
            Self::Private => 1,
            Self::Session => 2,
            Self::SecretPart => 3,
            Self::Other(other) => other,
        }
    }
}

/// `CSSM_KEYBLOB_TYPE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyBlobType {
    Raw,
    Reference,
    Wrapped,
    Other(u32),
}

impl KeyBlobType {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::Raw,
            1 => Self::Reference,
            2 => Self::Wrapped,
            other => Self::Other(other),
        }
    }

    pub fn as_u32(self) -> u32 {
        match self {
            Self::Raw => 0,
            Self::Reference => 1,
            Self::Wrapped => 2,
            Self::Other(other) => other,
        }
    }
}

/// The `CSSM_ALGORITHMS` values this code needs to name.
pub mod algorithm {
    /// `CSSM_ALGID_3DES_3KEY_EDE`, the algorithm every keychain item key uses.
    pub const TRIPLE_DES_3KEY: u32 = 0x11;
    /// `CSSM_ALGID_RSA`.
    pub const RSA: u32 = 42;
    pub const NONE: u32 = 0;
}

/// `CSSM_ENCRYPT_MODE` values used here.
pub mod encrypt_mode {
    pub const NONE: u32 = 0;
    /// `CSSM_ALGMODE_CBCPadIV8`, the mode the key wrapping uses.
    pub const CBC_PAD_IV8: u32 = 6;
}

/// `CSSM_KEYATTR_FLAGS` bits.
pub mod key_attr {
    pub const PERMANENT: u32 = 0x0000_0001;
    pub const PRIVATE: u32 = 0x0000_0002;
    pub const MODIFIABLE: u32 = 0x0000_0004;
    pub const SENSITIVE: u32 = 0x0000_0008;
    pub const EXTRACTABLE: u32 = 0x0000_0010;
    pub const ALWAYS_SENSITIVE: u32 = 0x0000_0020;
    pub const NEVER_EXTRACTABLE: u32 = 0x0000_0040;
}

/// `CSSM_KEYUSE` bits.
pub mod key_usage {
    pub const ENCRYPT: u32 = 0x0000_0001;
    pub const DECRYPT: u32 = 0x0000_0002;
    /// `CSSM_KEYUSE_ANY`, which macOS records for an imported private key.
    pub const ANY: u32 = 0x8000_0000;
}

/// `CSSM_KEYBLOB_FORMAT` values used here.
pub mod key_format {
    pub const NONE: u32 = 0;
    /// `CSSM_KEYBLOB_WRAPPED_FORMAT_APPLE_CUSTOM`.
    pub const APPLE_CUSTOM: u32 = 0x64;
}

/// `CSSM_KEYHEADER`, the 76-byte header of every stored key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyHeader {
    pub header_version: u32,
    pub csp_id: Guid,
    pub blob_type: KeyBlobType,
    pub format: u32,
    pub algorithm_id: u32,
    pub key_class: KeyClass,
    pub logical_key_size_in_bits: u32,
    /// `CSSM_KEYATTR_FLAGS`.
    pub key_attr: u32,
    /// `CSSM_KEYUSE`.
    pub key_usage: u32,
    pub start_date: CssmDate,
    pub end_date: CssmDate,
    pub wrap_algorithm_id: u32,
    pub wrap_mode: u32,
    pub reserved: u32,
}

impl KeyHeader {
    pub const LEN: usize = 76;

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::LEN {
            return Err(Error::Crypto("key header is truncated"));
        }
        Ok(Self {
            header_version: be32(data, 0),
            csp_id: Guid::parse(&data[4..20])?,
            blob_type: KeyBlobType::from_u32(be32(data, 20)),
            format: be32(data, 24),
            algorithm_id: be32(data, 28),
            key_class: KeyClass::from_u32(be32(data, 32)),
            logical_key_size_in_bits: be32(data, 36),
            key_attr: be32(data, 40),
            key_usage: be32(data, 44),
            start_date: CssmDate(data[48..56].try_into().expect("8 bytes")),
            end_date: CssmDate(data[56..64].try_into().expect("8 bytes")),
            wrap_algorithm_id: be32(data, 64),
            wrap_mode: be32(data, 68),
            reserved: be32(data, 72),
        })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.header_version.to_be_bytes());
        self.csp_id.write(out);
        out.extend_from_slice(&self.blob_type.as_u32().to_be_bytes());
        out.extend_from_slice(&self.format.to_be_bytes());
        out.extend_from_slice(&self.algorithm_id.to_be_bytes());
        out.extend_from_slice(&self.key_class.as_u32().to_be_bytes());
        out.extend_from_slice(&self.logical_key_size_in_bits.to_be_bytes());
        out.extend_from_slice(&self.key_attr.to_be_bytes());
        out.extend_from_slice(&self.key_usage.to_be_bytes());
        out.extend_from_slice(&self.start_date.0);
        out.extend_from_slice(&self.end_date.0);
        out.extend_from_slice(&self.wrap_algorithm_id.to_be_bytes());
        out.extend_from_slice(&self.wrap_mode.to_be_bytes());
        out.extend_from_slice(&self.reserved.to_be_bytes());
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        self.write(&mut out);
        out
    }

    /// The header macOS writes for a wrapped item key: a 192-bit 3DES session
    /// key from the Apple CSP that may only encrypt and decrypt its item.
    ///
    /// securityd checks these bits before it will use the key, so they are the
    /// values `security` writes, not a plausible-looking set.
    /// `key_size_matches_apples_header` pins the whole header to a keychain macOS
    /// wrote.
    pub fn item_key() -> Self {
        Self {
            header_version: 2,
            csp_id: Guid::APPLE_CSP,
            blob_type: KeyBlobType::Wrapped,
            format: key_format::NONE,
            algorithm_id: algorithm::TRIPLE_DES_3KEY,
            key_class: KeyClass::Session,
            logical_key_size_in_bits: 192,
            // Both EXTRACTABLE and NEVER_EXTRACTABLE are set, which is what
            // macOS writes; the record attributes carry the effective values.
            key_attr: key_attr::PERMANENT
                | key_attr::SENSITIVE
                | key_attr::EXTRACTABLE
                | key_attr::NEVER_EXTRACTABLE,
            key_usage: key_usage::ENCRYPT | key_usage::DECRYPT,
            start_date: CssmDate::default(),
            end_date: CssmDate::default(),
            wrap_algorithm_id: algorithm::NONE,
            wrap_mode: encrypt_mode::NONE,
            reserved: 0,
        }
    }
}

impl KeyHeader {
    /// The header macOS writes for an imported RSA private key.
    ///
    /// The bits are the ones `security import` writes: permanent, sensitive,
    /// always sensitive, extractable, and usable for anything.
    ///
    /// `key_size` is recorded in the record's attributes as well; the header
    /// carries the logical size.
    pub fn private_key(key_size_in_bits: u32) -> Self {
        Self {
            algorithm_id: algorithm::RSA,
            key_class: KeyClass::Private,
            logical_key_size_in_bits: key_size_in_bits,
            // Permanent, sensitive and extractable: an imported key.
            key_attr: key_attr::PERMANENT
                | key_attr::SENSITIVE
                | key_attr::EXTRACTABLE
                | key_attr::ALWAYS_SENSITIVE,
            key_usage: key_usage::ANY,
            ..Self::item_key()
        }
    }
}

/// `KeyBlob::WrappedFields`: how the key that follows was wrapped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedKeyFields {
    pub blob_type: u32,
    pub blob_format: u32,
    pub wrap_algorithm: u32,
    pub wrap_mode: u32,
}

impl WrappedKeyFields {
    pub const LEN: usize = 16;

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::LEN {
            return Err(Error::Crypto("wrapped-key fields are truncated"));
        }
        Ok(Self {
            blob_type: be32(data, 0),
            blob_format: be32(data, 4),
            wrap_algorithm: be32(data, 8),
            wrap_mode: be32(data, 12),
        })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.blob_type.to_be_bytes());
        out.extend_from_slice(&self.blob_format.to_be_bytes());
        out.extend_from_slice(&self.wrap_algorithm.to_be_bytes());
        out.extend_from_slice(&self.wrap_mode.to_be_bytes());
    }

    /// What macOS records for an item key wrapped in its custom format.
    pub fn item_key() -> Self {
        Self {
            blob_type: 3,
            blob_format: key_format::APPLE_CUSTOM,
            wrap_algorithm: algorithm::TRIPLE_DES_3KEY,
            wrap_mode: encrypt_mode::CBC_PAD_IV8,
        }
    }
}

fn be32(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_round_trips_and_prints() {
        let mut bytes = Vec::new();
        Guid::APPLE_CSP.write(&mut bytes);
        assert_eq!(bytes.len(), Guid::LEN);
        assert_eq!(Guid::parse(&bytes).unwrap(), Guid::APPLE_CSP);
        assert_eq!(
            Guid::APPLE_CSP.to_string(),
            "87191ca2-0fc9-11d4-849a000502b52122"
        );
    }

    #[test]
    fn key_header_round_trips() {
        let header = KeyHeader::item_key();
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), KeyHeader::LEN);
        assert_eq!(KeyHeader::parse(&bytes).unwrap(), header);
    }

    /// The exact bytes macOS writes for an item key's header, transcribed from a
    /// keychain created by `security add-generic-password`.
    #[test]
    fn item_key_header_matches_the_bytes_macos_writes() {
        assert_eq!(
            hex::encode(KeyHeader::item_key().to_bytes()),
            concat!(
                "00000002",                         // header version
                "87191ca20fc911d4849a000502b52122", // Apple CSP GUID
                "00000002",                         // blob type: wrapped
                "00000000",                         // format
                "00000011",                         // 3DES-3KEY
                "00000002",                         // key class: session
                "000000c0",                         // 192 bits
                "00000059",                         // key attributes
                "00000003",                         // usage: encrypt | decrypt
                "0000000000000000",                 // start date
                "0000000000000000",                 // end date
                "00000000",                         // wrap algorithm
                "00000000",                         // wrap mode
                "00000000",                         // reserved
            )
        );
    }

    #[test]
    fn key_header_holds_the_values_a_keychain_item_key_needs() {
        let header = KeyHeader::item_key();
        assert_eq!(header.blob_type, KeyBlobType::Wrapped);
        assert_eq!(header.key_class, KeyClass::Session);
        assert_eq!(header.algorithm_id, algorithm::TRIPLE_DES_3KEY);
        assert_eq!(header.logical_key_size_in_bits, 192);
        assert!(header.start_date.is_unset() && header.end_date.is_unset());
    }

    #[test]
    fn wrapped_fields_round_trip() {
        let fields = WrappedKeyFields::item_key();
        let mut bytes = Vec::new();
        fields.write(&mut bytes);
        assert_eq!(bytes.len(), WrappedKeyFields::LEN);
        assert_eq!(WrappedKeyFields::parse(&bytes).unwrap(), fields);
        assert_eq!(fields.blob_format, key_format::APPLE_CUSTOM);
    }

    #[test]
    fn enums_round_trip_through_their_wire_values() {
        for value in 0..=4 {
            assert_eq!(KeyClass::from_u32(value).as_u32(), value);
            assert_eq!(KeyBlobType::from_u32(value).as_u32(), value);
        }
        assert_eq!(KeyClass::from_u32(99), KeyClass::Other(99));
    }

    #[test]
    fn truncated_input_is_an_error_not_a_panic() {
        assert!(Guid::parse(&[0u8; 8]).is_err());
        assert!(KeyHeader::parse(&[0u8; 40]).is_err());
        assert!(WrappedKeyFields::parse(&[0u8; 4]).is_err());
    }
}
