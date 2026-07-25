//! Reading and writing macOS `.keychain` database files directly.
//!
//! This is the CDSA-era keychain format — the one `security create-keychain`
//! still writes on macOS 26 — parsed and produced without the Security
//! framework, so it works on any host and needs no entitlements.
//!
//! * [`mod@format`] is the `kych` container: tables, records, attribute values.
//! * [`schema`] is the self-describing schema every keychain carries.
//! * [`crypto`] is the encryption the container specification omits.
//! * [`db`] ties them together: open, unlock, query, decrypt.
//! * [`mod@write`] creates keychains and adds items.
//! * [`edit`] updates, deletes, re-seals and re-authorizes what is already there.
//!
//! See `README.md` for the format notes and the security caveats.

pub mod access;
pub mod acl;
pub mod apple_schema;
pub mod crypto;
pub mod cssm;
pub mod db;
pub mod der;
pub mod edit;
pub mod error;
pub mod format;
pub mod index;
pub mod locator;
pub mod output;
pub mod pkcs12;
pub mod records;
pub mod schema;
pub mod secret;
pub mod write;

pub use access::{AccessDecision, AccessDefault, AccessMode, AccessPolicy};
pub use acl::{AclBlob, TrustedApplication};
pub use db::{Info, Item, KeychainFile, Query};
pub use edit::{ItemChanges, Settings, StoredIdentity};
pub use error::{Error, Result};
pub use format::{Keychain, Record, Value};
pub use locator::{KeychainLocator, SYSTEM_KEYCHAIN};
pub use pkcs12::{
    Identity as Pkcs12Identity, decode as decode_pkcs12, decode_identity, encode as encode_pkcs12,
    is_combined_pem,
};
pub use schema::{AttributeFormat, RecordType, Schema};
pub use write::{CreateOptions, NewIdentity, NewItem, create, now_timestamp};

/// Reading an application's designated requirement out of its code signature.
///
/// Needed to name a trusted application in an item's ACL: the ACL embeds the
/// application's requirement blob verbatim. Gated behind the `trust-apps`
/// feature, which pulls in the `macho-codesign` crate; without it, a requirement
/// can still be supplied as bytes (`csreq -b` output).
pub mod requirement;
