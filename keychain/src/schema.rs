//! Relations and attributes — the schema a keychain carries about itself.
//!
//! A keychain is a CSSM database: four schema tables describe every other
//! table's attributes, so a reader does not have to hard-code the layout of
//! password or key records. Only the four schema relations themselves need
//! built-in definitions, to bootstrap.
//!
//! Two things matter and are not obvious:
//!
//! * A record's attribute-offset array follows the order attributes are
//!   *defined in the schema table*, not attribute-id order. Sorting by id
//!   silently misreads every password record.
//! * Password relations name most attributes by four-char code in the
//!   `AttributeID` (`acct`, `svce`, `srvr`), leaving `AttributeName` empty;
//!   `PrintName` and `Alias` are the exceptions, named by string.

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::format::{Record, Table, Value, trim_nul};

/// A CSSM relation identifier (`CSSM_DB_RECORDTYPE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordType(pub u32);

impl RecordType {
    pub const SCHEMA_INFO: Self = Self(0x0000_0000);
    pub const SCHEMA_INDEXES: Self = Self(0x0000_0001);
    pub const SCHEMA_ATTRIBUTES: Self = Self(0x0000_0002);
    pub const SCHEMA_PARSING_MODULE: Self = Self(0x0000_0003);

    pub const CERT: Self = Self(0x0000_000b);
    pub const CRL: Self = Self(0x0000_000c);
    pub const POLICY: Self = Self(0x0000_000d);
    pub const GENERIC: Self = Self(0x0000_000e);
    pub const PUBLIC_KEY: Self = Self(0x0000_000f);
    pub const PRIVATE_KEY: Self = Self(0x0000_0010);
    pub const SYMMETRIC_KEY: Self = Self(0x0000_0011);

    pub const GENERIC_PASSWORD: Self = Self(0x8000_0000);
    pub const INTERNET_PASSWORD: Self = Self(0x8000_0001);
    pub const APPLESHARE_PASSWORD: Self = Self(0x8000_0002);
    pub const USER_TRUST: Self = Self(0x8000_0003);
    pub const X509_CRL: Self = Self(0x8000_0004);
    pub const UNLOCK_REFERRAL: Self = Self(0x8000_0005);
    pub const EXTENDED_ATTRIBUTE: Self = Self(0x8000_0006);
    pub const X509_CERTIFICATE: Self = Self(0x8000_1000);
    pub const METADATA: Self = Self(0x8000_8000);

    /// True for application-specific relations, which set the high bit.
    pub fn is_application_specific(self) -> bool {
        self.0 & 0x8000_0000 != 0
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::SCHEMA_INFO => "CSSM_DL_DB_SCHEMA_INFO",
            Self::SCHEMA_INDEXES => "CSSM_DL_DB_SCHEMA_INDEXES",
            Self::SCHEMA_ATTRIBUTES => "CSSM_DL_DB_SCHEMA_ATTRIBUTES",
            Self::SCHEMA_PARSING_MODULE => "CSSM_DL_DB_SCHEMA_PARSING_MODULE",
            Self::CERT => "CSSM_DL_DB_RECORD_CERT",
            Self::CRL => "CSSM_DL_DB_RECORD_CRL",
            Self::POLICY => "CSSM_DL_DB_RECORD_POLICY",
            Self::GENERIC => "CSSM_DL_DB_RECORD_GENERIC",
            Self::PUBLIC_KEY => "CSSM_DL_DB_RECORD_PUBLIC_KEY",
            Self::PRIVATE_KEY => "CSSM_DL_DB_RECORD_PRIVATE_KEY",
            Self::SYMMETRIC_KEY => "CSSM_DL_DB_RECORD_SYMMETRIC_KEY",
            Self::GENERIC_PASSWORD => "CSSM_DL_DB_RECORD_GENERIC_PASSWORD",
            Self::INTERNET_PASSWORD => "CSSM_DL_DB_RECORD_INTERNET_PASSWORD",
            Self::APPLESHARE_PASSWORD => "CSSM_DL_DB_RECORD_APPLESHARE_PASSWORD",
            Self::USER_TRUST => "CSSM_DL_DB_RECORD_USER_TRUST",
            Self::X509_CRL => "CSSM_DL_DB_RECORD_X509_CRL",
            Self::UNLOCK_REFERRAL => "CSSM_DL_DB_RECORD_UNLOCK_REFERRAL",
            Self::EXTENDED_ATTRIBUTE => "CSSM_DL_DB_RECORD_EXTENDED_ATTRIBUTE",
            Self::X509_CERTIFICATE => "CSSM_DL_DB_RECORD_X509_CERTIFICATE",
            Self::METADATA => "CSSM_DL_DB_RECORD_METADATA",
            _ => "unknown",
        }
    }

    /// Short name for the CLI: `generic`, `internet`, `appleshare`.
    pub fn short_name(self) -> Option<&'static str> {
        match self {
            Self::GENERIC_PASSWORD => Some("generic"),
            Self::INTERNET_PASSWORD => Some("internet"),
            Self::APPLESHARE_PASSWORD => Some("appleshare"),
            _ => None,
        }
    }
}

/// `CSSM_DB_ATTRIBUTE_FORMAT`: how an attribute value is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeFormat {
    String,
    Sint32,
    Uint32,
    BigNum,
    Real,
    TimeDate,
    Blob,
    MultiUint32,
    Complex,
    /// A value this build does not know; treated as a blob.
    Unknown(u32),
}

impl AttributeFormat {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::String,
            1 => Self::Sint32,
            2 => Self::Uint32,
            3 => Self::BigNum,
            4 => Self::Real,
            5 => Self::TimeDate,
            6 => Self::Blob,
            7 => Self::MultiUint32,
            8 => Self::Complex,
            other => Self::Unknown(other),
        }
    }

    pub fn as_u32(self) -> u32 {
        match self {
            Self::String => 0,
            Self::Sint32 => 1,
            Self::Uint32 => 2,
            Self::BigNum => 3,
            Self::Real => 4,
            Self::TimeDate => 5,
            Self::Blob => 6,
            Self::MultiUint32 => 7,
            Self::Complex => 8,
            Self::Unknown(other) => other,
        }
    }
}

/// One attribute of a relation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeDef {
    pub id: u32,
    /// Display name: the schema's string name, else the four-char code of `id`.
    pub name: String,
    pub format: AttributeFormat,
}

#[derive(Debug, Clone)]
pub struct Relation {
    pub record_type: RecordType,
    /// `RelationName` from the schema, when the file records one.
    pub name: Option<String>,
    /// Attributes in schema order, which is the record's attribute order.
    pub attributes: Vec<AttributeDef>,
}

impl Relation {
    /// Position of an attribute by name or four-char code, case-insensitively.
    pub fn index_of(&self, name: &str) -> Option<usize> {
        self.attributes
            .iter()
            .position(|attr| attr.name.eq_ignore_ascii_case(name))
    }
}

/// The schema of one keychain.
#[derive(Debug, Clone, Default)]
pub struct Schema {
    relations: BTreeMap<RecordType, Relation>,
}

impl Schema {
    /// Built-in definitions for the four schema relations, enough to read the
    /// schema tables and learn everything else.
    pub fn bootstrap() -> Self {
        let uint32 = AttributeFormat::Uint32;
        let string = AttributeFormat::String;
        let blob = AttributeFormat::Blob;

        let mut relations = BTreeMap::new();
        let mut add = |record_type: RecordType, attrs: &[(&str, AttributeFormat)]| {
            relations.insert(
                record_type,
                Relation {
                    record_type,
                    name: Some(record_type.name().to_string()),
                    attributes: attrs
                        .iter()
                        .enumerate()
                        .map(|(index, (name, format))| AttributeDef {
                            id: index as u32,
                            name: (*name).to_string(),
                            format: *format,
                        })
                        .collect(),
                },
            );
        };

        add(
            RecordType::SCHEMA_INFO,
            &[("RelationID", uint32), ("RelationName", string)],
        );
        add(
            RecordType::SCHEMA_INDEXES,
            &[
                ("RelationID", uint32),
                ("IndexID", uint32),
                ("AttributeID", uint32),
                ("IndexType", uint32),
                ("IndexedDataLocation", uint32),
            ],
        );
        add(
            RecordType::SCHEMA_ATTRIBUTES,
            &[
                ("RelationID", uint32),
                ("AttributeID", uint32),
                ("AttributeNameFormat", uint32),
                ("AttributeName", string),
                ("AttributeNameID", blob),
                ("AttributeFormat", uint32),
            ],
        );
        add(
            RecordType::SCHEMA_PARSING_MODULE,
            &[
                ("RelationID", uint32),
                ("AttributeID", uint32),
                ("ModuleID", blob),
                ("AddinVersion", string),
                ("SSID", uint32),
                ("SubserviceType", uint32),
            ],
        );

        Self { relations }
    }

    /// Read the schema out of a keychain's own schema tables.
    pub fn from_tables(tables: &[Table]) -> Result<Self> {
        let bootstrap = Self::bootstrap();
        let find =
            |record_type: RecordType| tables.iter().find(|table| table.record_type == record_type);

        // Relation names, when present.
        let mut names: BTreeMap<RecordType, String> = BTreeMap::new();
        if let Some(table) = find(RecordType::SCHEMA_INFO) {
            for record in table.records() {
                let Some(id) = record.attribute(0).and_then(Value::as_u32) else {
                    continue;
                };
                if let Some(name) = record.attribute(1).and_then(Value::as_bytes) {
                    let name = String::from_utf8_lossy(trim_nul(name)).into_owned();
                    if !name.is_empty() {
                        names.insert(RecordType(id), name);
                    }
                }
            }
        }

        let attributes_table = find(RecordType::SCHEMA_ATTRIBUTES)
            .ok_or(Error::MissingTable("CSSM_DL_DB_SCHEMA_ATTRIBUTES"))?;

        let mut relations: BTreeMap<RecordType, Relation> = BTreeMap::new();
        for record in attributes_table.records() {
            let relation_id = record
                .attribute(0)
                .and_then(Value::as_u32)
                .ok_or_else(|| Error::format("schema attribute record has no RelationID"))?;
            let attribute_id = record
                .attribute(1)
                .and_then(Value::as_u32)
                .ok_or_else(|| Error::format("schema attribute record has no AttributeID"))?;
            let format =
                AttributeFormat::from_u32(record.attribute(5).and_then(Value::as_u32).unwrap_or(6));

            let named = record
                .attribute(3)
                .and_then(Value::as_bytes)
                .map(|bytes| String::from_utf8_lossy(trim_nul(bytes)).into_owned())
                .filter(|name| !name.is_empty());
            let name = named
                .or_else(|| {
                    record
                        .attribute(4)
                        .and_then(Value::as_bytes)
                        .map(|bytes| String::from_utf8_lossy(trim_nul(bytes)).into_owned())
                        .filter(|name| !name.is_empty())
                })
                .unwrap_or_else(|| attribute_name_from_id(attribute_id));

            let record_type = RecordType(relation_id);
            relations
                .entry(record_type)
                .or_insert_with(|| Relation {
                    record_type,
                    name: names.get(&record_type).cloned(),
                    attributes: Vec::new(),
                })
                .attributes
                .push(AttributeDef {
                    id: attribute_id,
                    name,
                    format,
                });
        }

        // The schema tables describe themselves inconsistently across macOS
        // versions; the built-in definitions are authoritative for them.
        for (record_type, relation) in bootstrap.relations {
            relations.insert(record_type, relation);
        }

        // Relations with no attribute records still exist as tables.
        for table in tables {
            relations
                .entry(table.record_type)
                .or_insert_with(|| Relation {
                    record_type: table.record_type,
                    name: names.get(&table.record_type).cloned(),
                    attributes: Vec::new(),
                });
        }

        Ok(Self { relations })
    }

    pub fn relation(&self, record_type: RecordType) -> Option<&Relation> {
        self.relations.get(&record_type)
    }

    pub fn relations(&self) -> impl Iterator<Item = &Relation> {
        self.relations.values()
    }

    /// Attribute formats in record order. Empty when the relation is unknown,
    /// which makes such a record parse as having no attributes.
    pub fn attribute_formats(&self, record_type: RecordType) -> Vec<AttributeFormat> {
        self.relations
            .get(&record_type)
            .map(|relation| relation.attributes.iter().map(|attr| attr.format).collect())
            .unwrap_or_default()
    }

    /// Look up a value on a record by attribute name.
    pub fn attribute<'r>(
        &self,
        record_type: RecordType,
        record: &'r Record,
        name: &str,
    ) -> Option<&'r Value> {
        let index = self.relation(record_type)?.index_of(name)?;
        record.attribute(index)
    }

    /// Every named attribute of a record that has a value.
    pub fn named_attributes<'r>(
        &self,
        record_type: RecordType,
        record: &'r Record,
    ) -> Vec<(&str, &'r Value)> {
        let Some(relation) = self.relation(record_type) else {
            return Vec::new();
        };
        relation
            .attributes
            .iter()
            .enumerate()
            .filter_map(|(index, attr)| {
                record
                    .attribute(index)
                    .map(|value| (attr.name.as_str(), value))
            })
            .collect()
    }
}

/// Render an attribute id as its four-char code when that is printable.
fn attribute_name_from_id(id: u32) -> String {
    let bytes = id.to_be_bytes();
    if bytes.iter().all(|byte| (0x20..0x7f).contains(byte)) {
        String::from_utf8_lossy(&bytes).into_owned()
    } else {
        format!("attr{id}")
    }
}

/// Four-char code as a big-endian integer, for building attribute ids.
pub const fn four_char_code(code: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_types_report_their_names_and_kind() {
        assert_eq!(
            RecordType::GENERIC_PASSWORD.name(),
            "CSSM_DL_DB_RECORD_GENERIC_PASSWORD"
        );
        assert!(RecordType::GENERIC_PASSWORD.is_application_specific());
        assert!(!RecordType::SYMMETRIC_KEY.is_application_specific());
        assert_eq!(RecordType::INTERNET_PASSWORD.short_name(), Some("internet"));
        assert_eq!(RecordType::SYMMETRIC_KEY.short_name(), None);
        assert_eq!(RecordType(0x1234).name(), "unknown");
    }

    #[test]
    fn attribute_formats_round_trip() {
        for value in 0..=8 {
            assert_eq!(AttributeFormat::from_u32(value).as_u32(), value);
        }
        assert_eq!(AttributeFormat::from_u32(99), AttributeFormat::Unknown(99));
        assert_eq!(AttributeFormat::from_u32(99).as_u32(), 99);
    }

    #[test]
    fn bootstrap_schema_describes_the_four_schema_relations() {
        let schema = Schema::bootstrap();
        assert_eq!(schema.attribute_formats(RecordType::SCHEMA_INFO).len(), 2);
        assert_eq!(
            schema.attribute_formats(RecordType::SCHEMA_INDEXES).len(),
            5
        );
        assert_eq!(
            schema
                .attribute_formats(RecordType::SCHEMA_ATTRIBUTES)
                .len(),
            6
        );
        assert_eq!(
            schema
                .attribute_formats(RecordType::SCHEMA_PARSING_MODULE)
                .len(),
            6
        );
        // Unknown relations yield no attributes rather than a guess.
        assert!(
            schema
                .attribute_formats(RecordType::GENERIC_PASSWORD)
                .is_empty()
        );
    }

    #[test]
    fn attribute_names_fall_back_to_four_char_codes() {
        assert_eq!(attribute_name_from_id(four_char_code(b"acct")), "acct");
        assert_eq!(attribute_name_from_id(four_char_code(b"svce")), "svce");
        assert_eq!(attribute_name_from_id(0), "attr0");
        assert_eq!(attribute_name_from_id(7), "attr7");
    }

    #[test]
    fn four_char_codes_are_big_endian() {
        assert_eq!(four_char_code(b"acct"), 0x6163_6374);
        assert_eq!(four_char_code(b"svce").to_be_bytes(), *b"svce");
    }

    #[test]
    fn attribute_lookup_is_case_insensitive() {
        let relation = Relation {
            record_type: RecordType::GENERIC_PASSWORD,
            name: None,
            attributes: vec![
                AttributeDef {
                    id: 0,
                    name: "acct".into(),
                    format: AttributeFormat::Blob,
                },
                AttributeDef {
                    id: 1,
                    name: "PrintName".into(),
                    format: AttributeFormat::Blob,
                },
            ],
        };
        assert_eq!(relation.index_of("acct"), Some(0));
        assert_eq!(relation.index_of("ACCT"), Some(0));
        assert_eq!(relation.index_of("printname"), Some(1));
        assert_eq!(relation.index_of("nope"), None);
    }
}
