//! Typed records: the attribute sets stored for an item and for its key.
//!
//! Attribute values reach the file as a positional list ordered by the relation's
//! schema, which is easy to get subtly wrong and impossible to read. These
//! structs name every field, carry the values macOS writes, and lower themselves
//! into the relation's order at the end.
//!
//! The values are not invented. `securityd` queries a key record for attributes
//! such as `KeyCreator` and `Alias`, and returns `errSecNoSuchAttr` when one is
//! absent — so a key record has to carry the whole set, empty values included.
//! `tests/keychain_records.rs` checks each field against a key record written by
//! macOS.

use crate::cssm::Guid;
use crate::format::Value;
use crate::schema::Relation;

/// Assigns values to a relation's attributes by name.
struct AttributeWriter<'r> {
    relation: &'r Relation,
    values: Vec<Option<Value>>,
}

impl<'r> AttributeWriter<'r> {
    fn new(relation: &'r Relation) -> Self {
        Self {
            relation,
            values: vec![None; relation.attributes.len()],
        }
    }

    /// Set an attribute. Names the relation does not have are ignored: schemas
    /// differ between macOS versions, and a missing optional attribute is not a
    /// reason to fail a write.
    fn set(&mut self, name: &str, value: Value) -> &mut Self {
        if let Some(index) = self.relation.index_of(name) {
            self.values[index] = Some(value);
        }
        self
    }

    fn flag(&mut self, name: &str, value: bool) -> &mut Self {
        self.set(name, Value::Uint32(u32::from(value)))
    }

    fn finish(self) -> Vec<Option<Value>> {
        self.values
    }
}

/// The attribute set of the symmetric key that protects one item.
///
/// Every field here holds the value macOS writes for an item key. Two are worth
/// pointing out because they look wrong:
///
/// * `key_class` is `17`, the symmetric-key *relation* id, not a
///   `CSSM_KEYCLASS` constant.
/// * `print_name` is the 20-byte `ssgp` label rather than a readable name.
#[derive(Debug, Clone)]
pub struct ItemKeyRecord {
    pub key_class: u32,
    pub print_name: Vec<u8>,
    pub alias: Vec<u8>,
    pub permanent: bool,
    pub private: bool,
    pub modifiable: bool,
    /// The label shared with the item's `ssgp` payload; how the two are linked.
    pub label: [u8; 20],
    pub application_tag: Vec<u8>,
    /// The CSP that created the key, as a braced GUID string with a terminator.
    pub key_creator: Vec<u8>,
    /// `CSSM_ALGID_3DES_3KEY_EDE`.
    pub key_type: u32,
    pub key_size_in_bits: u32,
    pub effective_key_size: u32,
    /// Eight zero bytes for "unset", stored as a blob rather than a date.
    pub start_date: Vec<u8>,
    pub end_date: Vec<u8>,
    pub sensitive: bool,
    pub always_sensitive: bool,
    pub extractable: bool,
    pub never_extractable: bool,
    pub encrypt: bool,
    pub decrypt: bool,
    pub derive: bool,
    pub sign: bool,
    pub verify: bool,
    pub sign_recover: bool,
    pub verify_recover: bool,
    pub wrap: bool,
    pub unwrap: bool,
}

/// `KeyClass` as stored in a symmetric-key record: the relation id.
pub const KEY_CLASS_SYMMETRIC: u32 = 0x11;

/// `CSSM_ALGID_3DES_3KEY_EDE`, as stored in `KeyType`.
pub const KEY_TYPE_3DES_3KEY: u32 = 0x11;

impl ItemKeyRecord {
    /// The record macOS writes for the key of a password item.
    pub fn for_item_key(label: [u8; 20]) -> Self {
        Self {
            key_class: KEY_CLASS_SYMMETRIC,
            print_name: label.to_vec(),
            alias: Vec::new(),
            permanent: true,
            private: false,
            modifiable: false,
            label,
            application_tag: Vec::new(),
            key_creator: format!("{{{}}}\0", Self::creator_guid()).into_bytes(),
            key_type: KEY_TYPE_3DES_3KEY,
            key_size_in_bits: 192,
            effective_key_size: 192,
            start_date: vec![0u8; 8],
            end_date: vec![0u8; 8],
            // The key may encrypt and decrypt its item, and nothing else. It is
            // sensitive and never leaves the keychain in the clear.
            sensitive: true,
            always_sensitive: true,
            extractable: false,
            never_extractable: true,
            encrypt: true,
            decrypt: true,
            derive: false,
            sign: false,
            verify: false,
            sign_recover: false,
            verify_recover: false,
            wrap: false,
            unwrap: false,
        }
    }

    /// The Apple CSP GUID, formatted the way `KeyCreator` spells it.
    fn creator_guid() -> String {
        let guid = Guid::APPLE_CSP;
        format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
            guid.data1,
            guid.data2,
            guid.data3,
            guid.data4[0],
            guid.data4[1],
            guid.data4[2..]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    }

    /// Lower into the relation's attribute order.
    pub fn to_attributes(&self, relation: &Relation) -> Vec<Option<Value>> {
        let mut writer = AttributeWriter::new(relation);
        writer
            .set("KeyClass", Value::Uint32(self.key_class))
            .set("PrintName", Value::Blob(self.print_name.clone()))
            .set("Alias", Value::Blob(self.alias.clone()))
            .flag("Permanent", self.permanent)
            .flag("Private", self.private)
            .flag("Modifiable", self.modifiable)
            .set("Label", Value::Blob(self.label.to_vec()))
            .set("ApplicationTag", Value::Blob(self.application_tag.clone()))
            .set("KeyCreator", Value::Blob(self.key_creator.clone()))
            .set("KeyType", Value::Uint32(self.key_type))
            .set("KeySizeInBits", Value::Uint32(self.key_size_in_bits))
            .set("EffectiveKeySize", Value::Uint32(self.effective_key_size))
            .set("StartDate", Value::Blob(self.start_date.clone()))
            .set("EndDate", Value::Blob(self.end_date.clone()))
            .flag("Sensitive", self.sensitive)
            .flag("AlwaysSensitive", self.always_sensitive)
            .flag("Extractable", self.extractable)
            .flag("NeverExtractable", self.never_extractable)
            .flag("Encrypt", self.encrypt)
            .flag("Decrypt", self.decrypt)
            .flag("Derive", self.derive)
            .flag("Sign", self.sign)
            .flag("Verify", self.verify)
            .flag("SignRecover", self.sign_recover)
            .flag("VerifyRecover", self.verify_recover)
            .flag("Wrap", self.wrap)
            .flag("Unwrap", self.unwrap);
        writer.finish()
    }
}

/// The attribute set of a password item.
#[derive(Debug, Clone, Default)]
pub struct PasswordRecord {
    /// `cdat` and `mdat`, as `YYYYMMDDhhmmssZ`.
    pub created: String,
    pub modified: String,
    /// `PrintName`: what Keychain Access shows.
    pub print_name: String,
    /// `desc`, the "kind".
    pub description: Option<String>,
    /// `icmt`, a free-text comment.
    pub comment: Option<String>,
    /// `acct`
    pub account: Option<String>,
    /// `svce`, generic items.
    pub service: Option<String>,
    /// `gena`, generic items.
    pub generic: Option<Vec<u8>>,
    /// `srvr`, internet and AppleShare items.
    pub server: Option<String>,
    /// `sdmn`, internet items.
    pub security_domain: Option<String>,
    /// `path`, internet items.
    pub path: Option<String>,
    /// `port`, internet items.
    pub port: Option<u32>,
    /// `ptcl`, internet and AppleShare items: a four-char code held as an integer.
    pub protocol: Option<[u8; 4]>,
    /// `atyp`, internet items: a four-char code held as a blob.
    pub auth_type: Option<[u8; 4]>,
    /// `vlme`, AppleShare items.
    pub volume: Option<String>,
    /// `addr`, AppleShare items.
    pub address: Option<String>,
    /// `ssig`, AppleShare items.
    pub signature: Option<String>,
}

/// Attributes macOS always stores on a password item, empty when unset. Which of
/// them a record actually has depends on its relation: `gena` exists only on
/// generic items, `sdmn` only on internet and AppleShare items.
///
/// The distinction between "absent" and "present but empty" is not cosmetic: an
/// item that omits one of these is invisible to `security find-internet-password`
/// and to `security dump-keychain`.
const ALWAYS_PRESENT: [&str; 4] = ["desc", "icmt", "sdmn", "gena"];

impl PasswordRecord {
    pub fn to_attributes(&self, relation: &Relation) -> Vec<Option<Value>> {
        let mut writer = AttributeWriter::new(relation);
        writer
            .set("cdat", Value::Date(date_field(&self.created)))
            .set("mdat", Value::Date(date_field(&self.modified)))
            .set(
                "PrintName",
                Value::Blob(self.print_name.as_bytes().to_vec()),
            );

        let mut text = |name: &str, value: &Option<String>| match value {
            Some(value) => {
                writer.set(name, Value::Blob(value.as_bytes().to_vec()));
            }
            None if ALWAYS_PRESENT.contains(&name) => {
                writer.set(name, Value::Blob(Vec::new()));
            }
            None => {}
        };
        text("desc", &self.description);
        text("icmt", &self.comment);
        text("acct", &self.account);
        text("svce", &self.service);
        text("srvr", &self.server);
        text("sdmn", &self.security_domain);
        text("path", &self.path);
        text("vlme", &self.volume);
        text("addr", &self.address);
        text("ssig", &self.signature);

        writer.set(
            "gena",
            Value::Blob(self.generic.clone().unwrap_or_default()),
        );
        if let Some(port) = self.port {
            writer.set("port", Value::Uint32(port));
        }
        if let Some(protocol) = self.protocol {
            writer.set("ptcl", Value::Uint32(u32::from_be_bytes(protocol)));
        }
        if let Some(auth_type) = self.auth_type {
            writer.set("atyp", Value::Blob(auth_type.to_vec()));
        }
        writer.finish()
    }
}

/// `CertType` for an X.509 v3 certificate (`CSSM_CERT_X_509v3`).
pub const CERT_TYPE_X509_V3: u32 = 1;

/// `CertEncoding` for DER (`CSSM_CERT_ENCODING_DER`).
pub const CERT_ENCODING_DER: u32 = 3;

/// `KeyClass` as stored in a private-key record: the relation id, matching the
/// way a symmetric-key record stores `17`.
pub const KEY_CLASS_PRIVATE: u32 = 0x10;

/// `CSSM_ALGID_RSA`, as stored in a private key's `KeyType`.
pub const KEY_TYPE_RSA: u32 = 42;

/// The attribute set of a certificate record.
///
/// Every field except the two format tags is a copy of bytes from the
/// certificate itself; see [`crate::der`]. The record's key data is the
/// certificate DER, stored in the clear — a certificate is public.
#[derive(Debug, Clone)]
pub struct CertificateRecord {
    pub cert_type: u32,
    pub cert_encoding: u32,
    /// `PrintName` and `Alias`, which macOS sets to the same label.
    pub print_name: String,
    pub alias: Vec<u8>,
    pub subject: Vec<u8>,
    pub issuer: Vec<u8>,
    pub serial_number: Vec<u8>,
    /// Absent when the certificate carries no such extension.
    pub subject_key_identifier: Option<Vec<u8>>,
    /// SHA-1 of the public key bits: the value that links this certificate to
    /// its private key, whose `Label` holds the same 20 bytes.
    pub public_key_hash: [u8; 20],
}

impl CertificateRecord {
    /// The record macOS writes for an imported certificate.
    pub fn for_certificate(label: &str, certificate: &crate::der::Certificate<'_>) -> Self {
        Self {
            cert_type: CERT_TYPE_X509_V3,
            cert_encoding: CERT_ENCODING_DER,
            print_name: label.to_string(),
            alias: label.as_bytes().to_vec(),
            subject: certificate.subject.to_vec(),
            issuer: certificate.issuer.to_vec(),
            serial_number: certificate.serial_number.to_vec(),
            subject_key_identifier: certificate.subject_key_identifier.map(<[u8]>::to_vec),
            public_key_hash: certificate.public_key_hash(),
        }
    }

    pub fn to_attributes(&self, relation: &Relation) -> Vec<Option<Value>> {
        let mut writer = AttributeWriter::new(relation);
        writer
            .set("CertType", Value::Uint32(self.cert_type))
            .set("CertEncoding", Value::Uint32(self.cert_encoding))
            .set(
                "PrintName",
                Value::Blob(self.print_name.as_bytes().to_vec()),
            )
            .set("Alias", Value::Blob(self.alias.clone()))
            .set("Subject", Value::Blob(self.subject.clone()))
            .set("Issuer", Value::Blob(self.issuer.clone()))
            .set("SerialNumber", Value::Blob(self.serial_number.clone()))
            .set("PublicKeyHash", Value::Blob(self.public_key_hash.to_vec()));
        if let Some(identifier) = &self.subject_key_identifier {
            writer.set("SubjectKeyIdentifier", Value::Blob(identifier.clone()));
        }
        writer.finish()
    }
}

/// The attribute set of a private-key record.
///
/// The usage flags are all set, which is what macOS writes for a key imported
/// from a PKCS#12 bundle: the key may sign, decrypt, unwrap and derive.
#[derive(Debug, Clone)]
pub struct PrivateKeyRecord {
    pub key_class: u32,
    pub print_name: String,
    pub alias: Vec<u8>,
    pub permanent: bool,
    pub private: bool,
    pub modifiable: bool,
    /// The public key hash, shared with the certificate's `PublicKeyHash`.
    pub label: [u8; 20],
    pub application_tag: Vec<u8>,
    pub key_creator: Vec<u8>,
    pub key_type: u32,
    pub key_size_in_bits: u32,
    pub effective_key_size: u32,
    pub start_date: Vec<u8>,
    pub end_date: Vec<u8>,
    pub sensitive: bool,
    pub always_sensitive: bool,
    pub extractable: bool,
    pub never_extractable: bool,
    pub encrypt: bool,
    pub decrypt: bool,
    pub derive: bool,
    pub sign: bool,
    pub verify: bool,
    pub sign_recover: bool,
    pub verify_recover: bool,
    pub wrap: bool,
    pub unwrap: bool,
}

impl PrivateKeyRecord {
    /// The record macOS writes for an RSA private key imported alongside its
    /// certificate.
    pub fn for_private_key(label: &str, public_key_hash: [u8; 20], key_size_in_bits: u32) -> Self {
        Self {
            key_class: KEY_CLASS_PRIVATE,
            print_name: label.to_string(),
            alias: Vec::new(),
            permanent: true,
            private: false,
            modifiable: false,
            label: public_key_hash,
            application_tag: Vec::new(),
            key_creator: ItemKeyRecord::for_item_key([0u8; 20]).key_creator,
            key_type: KEY_TYPE_RSA,
            key_size_in_bits,
            effective_key_size: key_size_in_bits,
            start_date: vec![0u8; 8],
            end_date: vec![0u8; 8],
            sensitive: true,
            always_sensitive: true,
            // An imported key is extractable: that is how it got in, and macOS
            // records it that way.
            extractable: true,
            never_extractable: false,
            encrypt: true,
            decrypt: true,
            derive: true,
            sign: true,
            verify: true,
            sign_recover: true,
            verify_recover: true,
            wrap: true,
            unwrap: true,
        }
    }

    pub fn to_attributes(&self, relation: &Relation) -> Vec<Option<Value>> {
        let mut writer = AttributeWriter::new(relation);
        writer
            .set("KeyClass", Value::Uint32(self.key_class))
            .set(
                "PrintName",
                Value::Blob(self.print_name.as_bytes().to_vec()),
            )
            .set("Alias", Value::Blob(self.alias.clone()))
            .flag("Permanent", self.permanent)
            .flag("Private", self.private)
            .flag("Modifiable", self.modifiable)
            .set("Label", Value::Blob(self.label.to_vec()))
            .set("ApplicationTag", Value::Blob(self.application_tag.clone()))
            .set("KeyCreator", Value::Blob(self.key_creator.clone()))
            .set("KeyType", Value::Uint32(self.key_type))
            .set("KeySizeInBits", Value::Uint32(self.key_size_in_bits))
            .set("EffectiveKeySize", Value::Uint32(self.effective_key_size))
            .set("StartDate", Value::Blob(self.start_date.clone()))
            .set("EndDate", Value::Blob(self.end_date.clone()))
            .flag("Sensitive", self.sensitive)
            .flag("AlwaysSensitive", self.always_sensitive)
            .flag("Extractable", self.extractable)
            .flag("NeverExtractable", self.never_extractable)
            .flag("Encrypt", self.encrypt)
            .flag("Decrypt", self.decrypt)
            .flag("Derive", self.derive)
            .flag("Sign", self.sign)
            .flag("Verify", self.verify)
            .flag("SignRecover", self.sign_recover)
            .flag("VerifyRecover", self.verify_recover)
            .flag("Wrap", self.wrap)
            .flag("Unwrap", self.unwrap);
        writer.finish()
    }
}

/// A date attribute: the timestamp plus the NUL the format includes.
fn date_field(timestamp: &str) -> Vec<u8> {
    format!("{timestamp}\0").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{AttributeDef, AttributeFormat, RecordType};

    fn relation(names: &[&str]) -> Relation {
        Relation {
            record_type: RecordType::SYMMETRIC_KEY,
            name: None,
            attributes: names
                .iter()
                .enumerate()
                .map(|(index, name)| AttributeDef {
                    id: index as u32,
                    name: (*name).to_string(),
                    format: AttributeFormat::Blob,
                })
                .collect(),
        }
    }

    #[test]
    fn key_creator_is_a_braced_guid_string() {
        let record = ItemKeyRecord::for_item_key([0u8; 20]);
        assert_eq!(
            record.key_creator,
            b"{87191ca2-0fc9-11d4-849a-000502b52122}\0".to_vec(),
            "must match the string macOS stores"
        );
        assert_eq!(record.key_creator.len(), 39);
    }

    #[test]
    fn key_record_lowers_every_attribute_the_relation_declares() {
        let names = [
            "KeyClass",
            "PrintName",
            "Alias",
            "Permanent",
            "Private",
            "Modifiable",
            "Label",
            "ApplicationTag",
            "KeyCreator",
            "KeyType",
            "KeySizeInBits",
            "EffectiveKeySize",
            "StartDate",
            "EndDate",
            "Sensitive",
            "AlwaysSensitive",
            "Extractable",
            "NeverExtractable",
            "Encrypt",
            "Decrypt",
            "Derive",
            "Sign",
            "Verify",
            "SignRecover",
            "VerifyRecover",
            "Wrap",
            "Unwrap",
        ];
        let relation = relation(&names);
        let mut label = [0u8; 20];
        label[..4].copy_from_slice(b"ssgp");
        let values = ItemKeyRecord::for_item_key(label).to_attributes(&relation);

        assert_eq!(values.len(), names.len());
        for (index, name) in names.iter().enumerate() {
            assert!(
                values[index].is_some(),
                "{name} must have a value: securityd asks for it"
            );
        }
        assert_eq!(values[0], Some(Value::Uint32(KEY_CLASS_SYMMETRIC)));
        assert_eq!(values[1], Some(Value::Blob(label.to_vec())));
        assert_eq!(
            values[2],
            Some(Value::Blob(Vec::new())),
            "Alias is present but empty"
        );
        assert_eq!(
            values[12],
            Some(Value::Blob(vec![0u8; 8])),
            "unset dates are eight zeroes"
        );
    }

    #[test]
    fn unknown_attribute_names_are_skipped_not_fatal() {
        let relation = relation(&["KeyClass", "Label"]);
        let values = ItemKeyRecord::for_item_key([1u8; 20]).to_attributes(&relation);
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], Some(Value::Uint32(KEY_CLASS_SYMMETRIC)));
    }

    #[test]
    fn attributes_macos_always_writes_are_present_even_when_empty() {
        let relation = relation(&[
            "cdat",
            "mdat",
            "desc",
            "icmt",
            "PrintName",
            "acct",
            "svce",
            "gena",
            "port",
        ]);
        let record = PasswordRecord {
            created: "20260725123456Z".into(),
            modified: "20260725123456Z".into(),
            print_name: "myservice".into(),
            account: Some("alice".into()),
            service: Some("myservice".into()),
            ..PasswordRecord::default()
        };
        let values = record.to_attributes(&relation);

        assert_eq!(values[0], Some(Value::Date(b"20260725123456Z\0".to_vec())));
        // desc, icmt and gena are stored empty rather than omitted; an item that
        // omits them is invisible to the Security framework.
        assert_eq!(values[2], Some(Value::Blob(Vec::new())));
        assert_eq!(values[3], Some(Value::Blob(Vec::new())));
        assert_eq!(values[7], Some(Value::Blob(Vec::new())));
        assert_eq!(values[4], Some(Value::Blob(b"myservice".to_vec())));
        assert_eq!(values[5], Some(Value::Blob(b"alice".to_vec())));
        // A port is genuinely absent on a generic item.
        assert_eq!(values[8], None);
    }

    #[test]
    fn class_specific_always_present_attributes_follow_the_relation() {
        // An internet relation has sdmn but no gena, and vice versa.
        let internet = relation(&["cdat", "mdat", "PrintName", "sdmn", "srvr"]);
        let values = PasswordRecord {
            server: Some("h".into()),
            ..PasswordRecord::default()
        }
        .to_attributes(&internet);
        assert_eq!(
            values[3],
            Some(Value::Blob(Vec::new())),
            "sdmn present but empty"
        );

        let generic = relation(&["cdat", "mdat", "PrintName", "gena", "svce"]);
        let values = PasswordRecord {
            service: Some("s".into()),
            ..PasswordRecord::default()
        }
        .to_attributes(&generic);
        assert_eq!(
            values[3],
            Some(Value::Blob(Vec::new())),
            "gena present but empty"
        );
    }

    #[test]
    fn internet_attributes_are_encoded_in_their_formats() {
        let relation = relation(&[
            "cdat",
            "mdat",
            "PrintName",
            "srvr",
            "path",
            "port",
            "ptcl",
            "atyp",
        ]);
        let record = PasswordRecord {
            created: "20260725123456Z".into(),
            modified: "20260725123456Z".into(),
            print_name: "example.com".into(),
            server: Some("example.com".into()),
            path: Some("/login".into()),
            port: Some(8080),
            protocol: Some(*b"http"),
            auth_type: Some(*b"dflt"),
            ..PasswordRecord::default()
        };
        let values = record.to_attributes(&relation);

        assert_eq!(values[5], Some(Value::Uint32(8080)));
        // The protocol is an integer holding a four-char code; the auth type is
        // the same code as bytes. That asymmetry is the format's, not a slip.
        assert_eq!(values[6], Some(Value::Uint32(u32::from_be_bytes(*b"http"))));
        assert_eq!(values[7], Some(Value::Blob(b"dflt".to_vec())));
    }
}
