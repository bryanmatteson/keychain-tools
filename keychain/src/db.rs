//! Opening, unlocking, and querying a keychain database.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::crypto::{self, DbBlob, DbKeys, KeyBlob, SSGP_MAGIC, SecretBytes, Ssgp};
use crate::error::{Error, Result};
use crate::format::{Keychain, Record, Value, trim_nul};
use crate::query::{Expression, class_name};
use crate::schema::{RecordType, Schema};
use base64::Engine as _;

/// A keychain database, optionally unlocked.
pub struct KeychainFile {
    path: Option<PathBuf>,
    keychain: Keychain,
    schema: Schema,
    /// Present once a password has been accepted.
    keys: Option<DbKeys>,
    /// Item keys by their 20-byte `ssgp` label, populated on unlock.
    item_keys: BTreeMap<[u8; 20], SecretBytes>,
}

impl KeychainFile {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let bytes = std::fs::read(&path).map_err(|source| Error::reading(&path, source))?;
        let mut file = Self::from_bytes(&bytes)?;
        file.path = Some(path);
        Ok(file)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let keychain = Keychain::parse(bytes)?;
        let schema = keychain.schema()?;
        Ok(Self {
            path: None,
            keychain,
            schema,
            keys: None,
            item_keys: BTreeMap::new(),
        })
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn keychain(&self) -> &Keychain {
        &self.keychain
    }

    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    pub fn is_unlocked(&self) -> bool {
        self.keys.is_some()
    }

    /// The database blob, which holds the salt and the encrypted database keys.
    pub fn db_blob(&self) -> Result<DbBlob> {
        let table = self
            .keychain
            .table(RecordType::METADATA)
            .ok_or(Error::MissingTable("CSSM_DL_DB_RECORD_METADATA"))?;
        let record = table
            .records()
            .next()
            .ok_or_else(|| Error::format("metadata table has no record"))?;
        DbBlob::parse(&record.key_data)
    }

    /// Derive the database keys from a password and unwrap every item key.
    pub fn unlock(&mut self, password: &[u8]) -> Result<()> {
        let keys = self.db_blob()?.unlock(password)?;
        self.item_keys = self.unwrap_item_keys(&keys)?;
        self.keys = Some(keys);
        Ok(())
    }

    /// Item keys, by label. A key whose blob will not unwrap is skipped rather
    /// than failing the unlock: one damaged key should not hide every item.
    fn unwrap_item_keys(&self, keys: &DbKeys) -> Result<BTreeMap<[u8; 20], SecretBytes>> {
        let mut out = BTreeMap::new();
        let Some(table) = self.keychain.table(RecordType::SYMMETRIC_KEY) else {
            return Ok(out);
        };

        for record in table.records() {
            let Some(label) = self.key_label(record) else {
                continue;
            };
            let Ok(blob) = KeyBlob::parse(&record.key_data) else {
                continue;
            };
            if let Ok(key) = blob.unwrap_key(keys.encryption_key.as_slice()) {
                out.insert(label, key);
            }
        }
        Ok(out)
    }

    /// The `Label` of a key record, when it is a secure-storage group label.
    fn key_label(&self, record: &Record) -> Option<[u8; 20]> {
        let value = self
            .schema
            .attribute(RecordType::SYMMETRIC_KEY, record, "Label")?;
        let bytes = value.as_bytes()?;
        if bytes.len() != 20 || &bytes[..4] != SSGP_MAGIC {
            return None;
        }
        Some(bytes.try_into().expect("checked length"))
    }

    /// Number of item keys recovered by [`Self::unlock`].
    pub fn item_key_count(&self) -> usize {
        self.item_keys.len()
    }

    /// Every password item in the keychain, in table order.
    pub fn items(&self) -> Vec<Item<'_>> {
        let mut items = Vec::new();
        for record_type in [
            RecordType::GENERIC_PASSWORD,
            RecordType::INTERNET_PASSWORD,
            RecordType::APPLESHARE_PASSWORD,
        ] {
            items.extend(self.items_of_type(record_type));
        }
        items
    }

    pub fn items_of_type(&self, record_type: RecordType) -> Vec<Item<'_>> {
        let Some(table) = self.keychain.table(record_type) else {
            return Vec::new();
        };
        table
            .records()
            .map(|record| Item {
                record_type,
                record,
                schema: &self.schema,
            })
            .collect()
    }

    /// Every user-facing or cryptographic record that `kc get` can query.
    pub fn queryable_items(&self) -> Vec<Item<'_>> {
        let mut items = Vec::new();
        for record_type in [
            RecordType::GENERIC_PASSWORD,
            RecordType::INTERNET_PASSWORD,
            RecordType::APPLESHARE_PASSWORD,
            RecordType::X509_CERTIFICATE,
            RecordType::CERT,
            RecordType::PRIVATE_KEY,
            RecordType::PUBLIC_KEY,
            RecordType::SYMMETRIC_KEY,
        ] {
            items.extend(self.items_of_type(record_type));
        }
        items
    }

    /// Query every supported record class with one shared typed expression.
    pub fn select(&self, expression: &Expression) -> Result<Vec<Item<'_>>> {
        self.queryable_items()
            .into_iter()
            .filter_map(|item| match expression.matches(&item) {
                Ok(true) => Some(Ok(item)),
                Ok(false) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
    }

    /// Create a mutation-safe reference to an item in this exact database
    /// revision.
    pub fn item_ref(&self, item: &Item<'_>) -> Result<ItemRef> {
        let path = self
            .path()
            .ok_or_else(|| Error::other("item references require a keychain opened from a path"))?;
        Ok(ItemRef {
            keychain: path.to_path_buf(),
            commit_version: self.keychain.commit_version.unwrap_or(0),
            record_type: item.record_type,
            record_number: item.number(),
        })
    }

    /// Validate that a reference names this database revision and still points
    /// at a record.
    pub fn resolve_ref(&self, reference: &ItemRef) -> Result<Item<'_>> {
        let path = self
            .path()
            .ok_or_else(|| Error::other("item references require a keychain opened from a path"))?;
        if path != reference.keychain {
            return Err(Error::other(format!(
                "item reference names {}, not {}",
                reference.keychain.display(),
                path.display()
            )));
        }
        let version = self.keychain.commit_version.unwrap_or(0);
        if version != reference.commit_version {
            return Err(Error::other(format!(
                "stale item reference: keychain revision is {version}, reference is {}",
                reference.commit_version
            )));
        }
        self.items_of_type(reference.record_type)
            .into_iter()
            .find(|item| item.number() == reference.record_number)
            .ok_or(Error::NoSuchItem)
    }

    /// Records of any relation, for callers that need schema-level inspection.
    pub fn records_of_type(&self, record_type: RecordType) -> Vec<&Record> {
        self.keychain
            .table(record_type)
            .map(|table| table.records().collect())
            .unwrap_or_default()
    }

    /// Decrypt an item's secret. Requires an unlocked keychain.
    pub fn secret(&self, item: &Item<'_>) -> Result<SecretBytes> {
        if self.keys.is_none() {
            return Err(Error::Locked);
        }
        let ssgp = Ssgp::parse(&item.record.key_data)?;
        let key = self
            .item_keys
            .get(&ssgp.label)
            .ok_or_else(|| Error::MissingItemKey {
                label: ssgp.label_hex(),
            })?;
        ssgp.open(key.as_slice())
    }

    /// Items matching every supplied criterion.
    pub fn find(&self, query: &Query) -> Vec<Item<'_>> {
        let candidates = match query.record_type {
            Some(record_type) => self.items_of_type(record_type),
            None => self.items(),
        };
        candidates
            .into_iter()
            .filter(|item| query.matches(item))
            .collect()
    }

    /// Exactly one match, or an error naming the ambiguity.
    pub fn find_one(&self, query: &Query) -> Result<Item<'_>> {
        let mut matches = self.find(query);
        match matches.len() {
            0 => Err(Error::NoSuchItem),
            1 => Ok(matches.remove(0)),
            _ => Err(Error::other(format!(
                "{} items match; narrow the query (accounts: {})",
                matches.len(),
                matches
                    .iter()
                    .map(|item| item.account().unwrap_or_else(|| "?".into()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    }

    /// Write the database back out.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let bytes = self.keychain.to_bytes()?;
        write_file(path, &bytes)
    }

    /// Write back to the path this was opened from.
    pub fn save_in_place(&self) -> Result<()> {
        let path = self
            .path
            .as_ref()
            .ok_or_else(|| Error::other("this keychain was not opened from a file"))?;
        self.save(path)
    }

    pub(crate) fn keychain_mut(&mut self) -> &mut Keychain {
        &mut self.keychain
    }

    /// Re-derive the cached schema from the schema tables.
    ///
    /// Needed after adding a relation: every attribute lookup goes through the
    /// cached [`Schema`], so it has to learn the new relation before records of
    /// that type can be written or read.
    pub(crate) fn reload_schema(&mut self) -> Result<()> {
        self.schema = self.keychain.schema()?;
        Ok(())
    }

    pub(crate) fn keys(&self) -> Option<&DbKeys> {
        self.keys.as_ref()
    }

    #[allow(dead_code)]
    pub(crate) fn set_path(&mut self, path: PathBuf) {
        self.path = Some(path);
    }

    pub(crate) fn remember_item_key(&mut self, label: [u8; 20], key: SecretBytes) {
        self.item_keys.insert(label, key);
    }

    /// The unwrapped key for an item, once the keychain is unlocked.
    pub(crate) fn item_key(&self, label: &[u8; 20]) -> Option<&SecretBytes> {
        self.item_keys.get(label)
    }

    /// Drop an item key that no longer has an item.
    pub(crate) fn forget_item_key(&mut self, label: &[u8; 20]) {
        self.item_keys.remove(label);
    }
}

/// Opaque, revision-bound identity for piping `kc get -o @ref` into a mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRef {
    keychain: PathBuf,
    commit_version: u32,
    record_type: RecordType,
    record_number: u32,
}

impl ItemRef {
    const PREFIX: &'static str = "kc-ref-v1:";

    pub fn encode(&self) -> String {
        let body = serde_json::json!({
            "keychain": self.keychain,
            "commit_version": self.commit_version,
            "record_type": self.record_type.0,
            "record_number": self.record_number,
        })
        .to_string();
        format!(
            "{}{}",
            Self::PREFIX,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(body)
        )
    }

    pub fn decode(encoded: &str) -> Result<Self> {
        let body = encoded
            .trim()
            .strip_prefix(Self::PREFIX)
            .ok_or_else(|| Error::other("expected a kc-ref-v1 item reference"))?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|error| Error::other(format!("invalid item reference: {error}")))?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| Error::other(format!("invalid item reference: {error}")))?;
        let keychain = value["keychain"]
            .as_str()
            .map(PathBuf::from)
            .ok_or_else(|| Error::other("item reference has no keychain path"))?;
        let commit_version = u32::try_from(
            value["commit_version"]
                .as_u64()
                .ok_or_else(|| Error::other("item reference has no commit version"))?,
        )
        .map_err(|_| Error::other("item reference commit version does not fit u32"))?;
        let record_type = u32::try_from(
            value["record_type"]
                .as_u64()
                .ok_or_else(|| Error::other("item reference has no record type"))?,
        )
        .map(RecordType)
        .map_err(|_| Error::other("item reference record type does not fit u32"))?;
        let record_number = u32::try_from(
            value["record_number"]
                .as_u64()
                .ok_or_else(|| Error::other("item reference has no record number"))?,
        )
        .map_err(|_| Error::other("item reference record number does not fit u32"))?;
        Ok(Self {
            keychain,
            commit_version,
            record_type,
            record_number,
        })
    }

    pub fn class(&self) -> Option<&'static str> {
        class_name(self.record_type)
    }

    pub fn keychain(&self) -> &Path {
        &self.keychain
    }

    pub fn commit_version(&self) -> u32 {
        self.commit_version
    }

    pub fn record_type(&self) -> RecordType {
        self.record_type
    }

    pub fn record_number(&self) -> u32 {
        self.record_number
    }
}

/// Write atomically, keeping an existing file's permissions and defaulting new
/// files to owner-only: a keychain file is worth a brute-force attempt.
fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mode = std::fs::metadata(path)
        .map(|meta| meta.permissions().mode() & 0o777)
        .unwrap_or(0o600);
    let temp = path.with_extension(format!("kc-tmp.{}", std::process::id()));

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&temp)
        .map_err(|source| Error::io(format!("could not create {}", temp.display()), source))?;
    let result = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| Error::io(format!("could not write {}", temp.display()), source));
    drop(file);

    if let Err(error) = result {
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }
    std::fs::rename(&temp, path).map_err(|source| {
        let _ = std::fs::remove_file(&temp);
        Error::io(format!("could not replace {}", path.display()), source)
    })
}

/// Attributes that hold a four-character code in an integer field.
pub const FOUR_CHAR_CODE_ATTRIBUTES: [&str; 3] = ["ptcl", "crtr", "type"];

/// A password item: a record plus the schema needed to read it.
#[derive(Clone, Copy)]
pub struct Item<'kc> {
    pub record_type: RecordType,
    pub record: &'kc Record,
    schema: &'kc Schema,
}

impl<'kc> Item<'kc> {
    pub fn number(&self) -> u32 {
        self.record.number
    }

    pub fn attribute(&self, name: &str) -> Option<&'kc Value> {
        self.schema.attribute(self.record_type, self.record, name)
    }

    /// An attribute's bytes as a string, NUL-trimmed.
    pub fn text(&self, name: &str) -> Option<String> {
        let bytes = self.attribute(name)?.as_bytes()?;
        let trimmed = trim_nul(bytes);
        if trimmed.is_empty() {
            return None;
        }
        Some(String::from_utf8_lossy(trimmed).into_owned())
    }

    pub fn number_attribute(&self, name: &str) -> Option<u32> {
        self.attribute(name)?.as_u32()
    }

    pub fn account(&self) -> Option<String> {
        self.text("acct")
    }

    pub fn service(&self) -> Option<String> {
        self.text("svce")
    }

    pub fn server(&self) -> Option<String> {
        self.text("srvr")
    }

    pub fn label(&self) -> Option<String> {
        self.text("PrintName")
    }

    pub fn path(&self) -> Option<String> {
        self.text("path")
    }

    pub fn port(&self) -> Option<u32> {
        self.number_attribute("port").filter(|port| *port != 0)
    }

    pub fn volume(&self) -> Option<String> {
        self.text("vlme")
    }

    pub fn address(&self) -> Option<String> {
        self.text("addr")
    }

    pub fn signature(&self) -> Option<String> {
        self.text("ssig")
    }

    pub fn created(&self) -> Option<String> {
        self.text("cdat")
    }

    pub fn modified(&self) -> Option<String> {
        self.text("mdat")
    }

    /// An attribute rendered the way `kc` displays it.
    ///
    /// Four-char codes are stored in integer fields (`ptcl` holds `htps` as
    /// 0x68747073); they read as text, so they are shown and matched as text.
    pub fn display_attribute(&self, name: &str) -> Option<String> {
        let value = self.attribute(name)?;
        if FOUR_CHAR_CODE_ATTRIBUTES.contains(&name)
            && let Some(number) = value.as_u32()
        {
            let bytes = number.to_be_bytes();
            if bytes.iter().all(|byte| (0x20..0x7f).contains(byte)) {
                return Some(String::from_utf8_lossy(&bytes).into_owned());
            }
        }
        Some(value.to_display_string())
    }

    /// Every attribute that has a value, in relation order.
    pub fn attributes(&self) -> Vec<(&'kc str, &'kc Value)> {
        self.schema.named_attributes(self.record_type, self.record)
    }

    /// True when the record carries an encrypted secret.
    pub fn has_secret(&self) -> bool {
        Ssgp::parse(&self.record.key_data).is_ok()
    }
}

/// Attribute-match criteria for password and identity lookups.
#[derive(Debug, Clone, Default)]
pub struct Query {
    pub record_type: Option<RecordType>,
    pub account: Option<String>,
    pub service: Option<String>,
    pub server: Option<String>,
    pub label: Option<String>,
    pub path: Option<String>,
    pub port: Option<u32>,
    pub volume: Option<String>,
    pub address: Option<String>,
    pub signature: Option<String>,
    /// `desc`, the "kind" Keychain Access shows.
    pub description: Option<String>,
    /// `icmt`, the comment.
    pub comment: Option<String>,
    /// `sdmn`, an internet item's authentication realm.
    pub security_domain: Option<String>,
    /// `gena`, a generic item's application-defined bytes.
    pub generic: Option<String>,
    /// Any other attribute, by the name the relation gives it, compared against
    /// the value as [`Item::display_attribute`] renders it. This is the escape
    /// hatch for attributes without a flag of their own.
    pub attributes: Vec<(String, String)>,
}

impl Query {
    pub fn generic() -> Self {
        Self {
            record_type: Some(RecordType::GENERIC_PASSWORD),
            ..Self::default()
        }
    }

    pub fn internet() -> Self {
        Self {
            record_type: Some(RecordType::INTERNET_PASSWORD),
            ..Self::default()
        }
    }

    pub fn appleshare() -> Self {
        Self {
            record_type: Some(RecordType::APPLESHARE_PASSWORD),
            ..Self::default()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.account.is_none()
            && self.service.is_none()
            && self.server.is_none()
            && self.label.is_none()
            && self.path.is_none()
            && self.port.is_none()
            && self.volume.is_none()
            && self.address.is_none()
            && self.signature.is_none()
            && self.description.is_none()
            && self.comment.is_none()
            && self.security_domain.is_none()
            && self.generic.is_none()
            && self.attributes.is_empty()
    }

    fn matches(&self, item: &Item<'_>) -> bool {
        let text_matches = |wanted: &Option<String>, actual: Option<String>| match wanted {
            None => true,
            Some(wanted) => actual.is_some_and(|actual| actual == *wanted),
        };

        text_matches(&self.account, item.account())
            && text_matches(&self.service, item.service())
            && text_matches(&self.server, item.server())
            && text_matches(&self.label, item.label())
            && text_matches(&self.path, item.path())
            && text_matches(&self.volume, item.volume())
            && text_matches(&self.address, item.address())
            && text_matches(&self.signature, item.signature())
            && text_matches(&self.description, item.text("desc"))
            && text_matches(&self.comment, item.text("icmt"))
            && text_matches(&self.security_domain, item.text("sdmn"))
            && text_matches(&self.generic, item.text("gena"))
            && match self.port {
                None => true,
                Some(port) => item.port() == Some(port),
            }
            && self.attributes.iter().all(|(name, wanted)| {
                item.display_attribute(name)
                    .is_some_and(|actual| actual == *wanted)
            })
    }
}

/// Summary for `kc info`.
#[derive(Debug, Clone)]
pub struct Info {
    pub version: u32,
    pub tables: Vec<(RecordType, usize)>,
    pub blob_version: u32,
    pub sequence: u32,
    pub idle_timeout: u32,
    pub lock_on_sleep: bool,
    pub salt: String,
    pub iv: String,
    pub pbkdf2_iterations: u32,
}

impl KeychainFile {
    pub fn info(&self) -> Result<Info> {
        let blob = self.db_blob()?;
        Ok(Info {
            version: self.keychain.version,
            tables: self
                .keychain
                .tables
                .iter()
                .map(|table| (table.record_type, table.record_count()))
                .collect(),
            blob_version: blob.version,
            sequence: blob.sequence,
            idle_timeout: blob.idle_timeout,
            lock_on_sleep: blob.lock_on_sleep,
            salt: hex::encode(blob.salt),
            iv: hex::encode(blob.iv),
            pbkdf2_iterations: crypto::PBKDF2_ITERATIONS,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_match_on_every_supplied_field() {
        let mut query = Query::generic();
        assert!(query.is_empty());
        query.account = Some("alice".into());
        assert!(!query.is_empty());
        assert_eq!(query.record_type, Some(RecordType::GENERIC_PASSWORD));

        let internet = Query::internet();
        assert_eq!(internet.record_type, Some(RecordType::INTERNET_PASSWORD));
    }

    #[test]
    fn parsing_rejects_garbage_before_any_crypto_happens() {
        assert!(KeychainFile::from_bytes(b"not a keychain").is_err());
    }
}
