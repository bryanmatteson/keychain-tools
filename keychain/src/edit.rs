//! Changing a keychain that already exists: updating items, deleting them,
//! rewriting an item's access control, and re-sealing the database itself.
//!
//! Everything here has the same constraint as [`crate::write`]: macOS has to
//! keep working on the file afterwards. Three of these operations are not just
//! "write different bytes" —
//!
//! * Deleting a record leaves a hole. macOS records that hole in the slot array
//!   as a free-list link rather than shrinking the array, so record numbers stay
//!   stable; see [`crate::format::Slot`].
//! * Updating an item touches two records — the item and the key that protects
//!   it — and both indexes have to follow.
//! * Changing the password re-seals the database blob, but must **not** disturb
//!   the master keys: every item key in the file is wrapped under them, so
//!   generating new ones would orphan every secret in the keychain.

use crate::acl::{AclBlob, TrustedApplication};
use crate::crypto::{self, BLOCK_SIZE, DbBlob, SALT_LEN, SecretBytes, Ssgp};
use crate::db::FOUR_CHAR_CODE_ATTRIBUTES;
use crate::db::KeychainFile;
use crate::error::{Error, Result};
use crate::format::Value;
use crate::schema::{AttributeFormat, RecordType};
use crate::secret::random_bytes;

/// What to change about an item. Every field left `None` is left alone; this is
/// a patch, not a replacement.
///
/// The distinction matters for attributes that are stored present-but-empty:
/// `Some(String::new())` clears an attribute, `None` leaves it as it was.
#[derive(Debug, Clone, Default)]
pub struct ItemChanges {
    /// `PrintName`
    pub label: Option<String>,
    /// `desc`, the "kind"
    pub description: Option<String>,
    /// `icmt`
    pub comment: Option<String>,
    /// `gena`, generic items
    pub generic: Option<Vec<u8>>,
    /// `sdmn`, internet items
    pub security_domain: Option<String>,
    /// Any other attribute, by the name its relation gives it.
    ///
    /// The identity attributes of a relation — the ones in its unique index —
    /// are rejected rather than written: changing one turns the item into a
    /// different item, which is a delete and an add, not an update.
    pub attributes: Vec<(String, Value)>,
}

impl ItemChanges {
    /// True when nothing would change.
    pub fn is_empty(&self) -> bool {
        self.label.is_none()
            && self.description.is_none()
            && self.comment.is_none()
            && self.generic.is_none()
            && self.security_domain.is_none()
            && self.attributes.is_empty()
    }

    /// The changes as (attribute name, value) pairs.
    fn pairs(&self) -> Vec<(String, Value)> {
        let mut pairs = Vec::new();
        let mut text = |name: &str, value: &Option<String>| {
            if let Some(value) = value {
                pairs.push((name.to_string(), Value::Blob(value.as_bytes().to_vec())));
            }
        };
        text("PrintName", &self.label);
        text("desc", &self.description);
        text("icmt", &self.comment);
        text("sdmn", &self.security_domain);
        if let Some(generic) = &self.generic {
            pairs.push(("gena".to_string(), Value::Blob(generic.clone())));
        }
        pairs.extend(self.attributes.iter().cloned());
        pairs
    }
}

/// The keychain's own settings, as `security set-keychain-settings` sets them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// Seconds of inactivity before the keychain locks.
    ///
    /// [`Settings::NO_TIMEOUT`] means never; there is no separate flag for it.
    pub idle_timeout: u32,
    pub lock_on_sleep: bool,
}

impl Settings {
    /// What macOS stores for "no idle timeout": `INT_MAX`, not zero.
    pub const NO_TIMEOUT: u32 = 0x7fff_ffff;

    /// True when the keychain never locks on idle.
    pub fn never_times_out(&self) -> bool {
        self.idle_timeout == Self::NO_TIMEOUT
    }

    /// Reject what securityd rejects: zero, and anything past `INT_MAX`.
    ///
    /// macOS refuses these outright and writes nothing, so accepting them here
    /// would produce a keychain its own tool would not have written.
    fn validate(&self) -> Result<()> {
        if self.idle_timeout == 0 || self.idle_timeout > Self::NO_TIMEOUT {
            return Err(Error::other(format!(
                "an idle timeout of {} is out of range; macOS accepts 1..={} \
                 seconds, where {} means never",
                self.idle_timeout,
                Self::NO_TIMEOUT,
                Self::NO_TIMEOUT
            )));
        }
        Ok(())
    }
}

impl KeychainFile {
    /// Update an item in place: its secret, its attributes, or both.
    ///
    /// The item keeps its record number, its slot, and its item key; only the
    /// encrypted payload is re-sealed, under a fresh IV. `mdat` is stamped with
    /// `timestamp` and `cdat` is left as it was.
    ///
    /// Requires an unlocked keychain when `secret` is given.
    pub fn update_item(
        &mut self,
        record_type: RecordType,
        record_number: u32,
        changes: &ItemChanges,
        secret: Option<&[u8]>,
        timestamp: &str,
    ) -> Result<()> {
        if changes.is_empty() && secret.is_none() {
            return Err(Error::other("nothing to change"));
        }

        let relation = self
            .schema()
            .relation(record_type)
            .ok_or_else(|| {
                Error::format(format!("keychain has no 0x{:08x} relation", record_type.0))
            })?
            .clone();

        // Refuse to rewrite an attribute the relation indexes as identity: the
        // result would be a different item sharing a record with the old one,
        // and a duplicate of it may already exist.
        let identity: Vec<u32> = self
            .keychain()
            .table(record_type)
            .and_then(|table| table.unique_index_attribute_ids().map(<[u32]>::to_vec))
            .unwrap_or_default();
        let mut updates = Vec::new();
        for (name, value) in changes.pairs() {
            let position = relation.index_of(&name).ok_or_else(|| {
                Error::other(format!(
                    "{} has no attribute named {name:?}",
                    record_type.name()
                ))
            })?;
            let attribute = &relation.attributes[position];
            if identity.contains(&attribute.id) {
                return Err(Error::other(format!(
                    "{name} identifies the item; change it by deleting and adding, not updating"
                )));
            }
            updates.push((position, coerce(&name, value, attribute.format)?));
        }

        // Re-seal the secret under the item's existing key, with a fresh IV.
        let payload = match secret {
            None => None,
            Some(secret) => {
                let item = self
                    .items_of_type(record_type)
                    .into_iter()
                    .find(|item| item.number() == record_number)
                    .ok_or(Error::NoSuchItem)?;
                let ssgp = Ssgp::parse(&item.record.key_data)?;
                let key = self.item_key(&ssgp.label).ok_or_else(|| {
                    if self.is_unlocked() {
                        Error::MissingItemKey {
                            label: ssgp.label_hex(),
                        }
                    } else {
                        Error::Locked
                    }
                })?;
                let mut iv = [0u8; BLOCK_SIZE];
                iv.copy_from_slice(&random_bytes(BLOCK_SIZE));
                Some(Ssgp::seal(ssgp.label, iv, key.as_slice(), secret)?.to_bytes())
            }
        };

        let modified = relation.index_of("mdat");
        let keychain = self.keychain_mut();
        keychain.bump_commit_version();
        let version = keychain.commit_version.unwrap_or(1);

        let table = keychain
            .table_mut(record_type)
            .ok_or(Error::MissingTable("item table"))?;
        let record = table
            .records_mut()
            .find(|record| record.number == record_number)
            .ok_or(Error::NoSuchItem)?;

        for (position, value) in updates {
            record.set_attribute(position, Some(value));
        }
        if let Some(position) = modified {
            record.set_attribute(position, Some(Value::Date(date_bytes(timestamp))));
        }
        if let Some(payload) = payload {
            record.key_data = payload;
        }
        record.version = version;

        table.rebuild_indexes(&relation)?;
        Ok(())
    }

    /// Delete an item and the key record that protects it.
    ///
    /// The slot keeps its place in the array — macOS never renumbers records —
    /// and both tables' indexes are rebuilt so nothing points at the hole.
    ///
    /// Returns the number of records removed: the item, plus its key when one
    /// was found.
    pub fn delete_item(&mut self, record_type: RecordType, record_number: u32) -> Result<usize> {
        let item = self
            .items_of_type(record_type)
            .into_iter()
            .find(|item| item.number() == record_number)
            .ok_or(Error::NoSuchItem)?;
        // The item names its key by the `ssgp` label the two share.
        let label = Ssgp::parse(&item.record.key_data)
            .ok()
            .map(|ssgp| ssgp.label);

        let key_record = label.and_then(|label| self.key_record_number(&label));

        let schema = self.schema().clone();
        let keychain = self.keychain_mut();

        // macOS advances the commit version once per record removed: deleting an
        // item and its key moves it by two.
        let mut removed = 0;
        {
            let table = keychain
                .table_mut(record_type)
                .ok_or(Error::MissingTable("item table"))?;
            if table.delete(record_number) {
                removed += 1;
            }
            if let Some(relation) = schema.relation(record_type) {
                table.rebuild_indexes(relation)?;
            }
        }
        if let Some(number) = key_record
            && let Some(table) = keychain.table_mut(RecordType::SYMMETRIC_KEY)
        {
            if table.delete(number) {
                removed += 1;
            }
            if let Some(relation) = schema.relation(RecordType::SYMMETRIC_KEY) {
                table.rebuild_indexes(relation)?;
            }
        }
        for _ in 0..removed {
            keychain.bump_commit_version();
        }
        if let Some(label) = label {
            self.forget_item_key(&label);
        }
        Ok(removed)
    }

    /// Delete a certificate, leaving any private key that goes with it.
    ///
    /// This is what `security delete-certificate` does: the key is left behind,
    /// orphaned, and `security find-identity` stops reporting the identity.
    /// Use [`KeychainFile::delete_identity`] to remove both halves.
    pub fn delete_certificate(&mut self, public_key_hash: &[u8]) -> Result<usize> {
        self.delete_identity_records(public_key_hash, false)
    }

    /// Delete an identity: the certificate and the private key that matches it.
    ///
    /// Returns the number of records removed.
    pub fn delete_identity(&mut self, public_key_hash: &[u8]) -> Result<usize> {
        self.delete_identity_records(public_key_hash, true)
    }

    fn delete_identity_records(
        &mut self,
        public_key_hash: &[u8],
        include_keys: bool,
    ) -> Result<usize> {
        let mut targets: Vec<(RecordType, u32)> = Vec::new();

        for record in self.records_of_type(RecordType::X509_CERTIFICATE) {
            let matches = self
                .schema()
                .attribute(RecordType::X509_CERTIFICATE, record, "PublicKeyHash")
                .and_then(Value::as_bytes)
                .is_some_and(|hash| hash == public_key_hash);
            if matches {
                targets.push((RecordType::X509_CERTIFICATE, record.number));
            }
        }
        for record_type in [RecordType::PRIVATE_KEY, RecordType::PUBLIC_KEY] {
            if !include_keys {
                break;
            }
            for record in self.records_of_type(record_type) {
                let matches = self
                    .schema()
                    .attribute(record_type, record, "Label")
                    .and_then(Value::as_bytes)
                    .is_some_and(|label| label == public_key_hash);
                if matches {
                    targets.push((record_type, record.number));
                }
            }
        }
        if targets.is_empty() {
            return Err(Error::NoSuchItem);
        }

        let schema = self.schema().clone();
        let keychain = self.keychain_mut();

        let mut removed = 0;
        for (record_type, number) in targets {
            let Some(table) = keychain.table_mut(record_type) else {
                continue;
            };
            if table.delete(number) {
                removed += 1;
            }
            if let Some(relation) = schema.relation(record_type) {
                table.rebuild_indexes(relation)?;
            }
        }
        for _ in 0..removed {
            keychain.bump_commit_version();
        }
        Ok(removed)
    }

    /// Rewrite the access control of an item's key.
    ///
    /// An empty list means any application, which is what
    /// `security add-generic-password -A` stores. The key itself is untouched:
    /// only the ACL region of its blob is replaced, and the blob re-signed.
    pub fn set_item_trust(
        &mut self,
        record_type: RecordType,
        record_number: u32,
        trusted: &[TrustedApplication],
    ) -> Result<()> {
        let item = self
            .items_of_type(record_type)
            .into_iter()
            .find(|item| item.number() == record_number)
            .ok_or(Error::NoSuchItem)?;
        let label = Ssgp::parse(&item.record.key_data)?.label;
        let number = self
            .key_record_number(&label)
            .ok_or_else(|| Error::MissingItemKey {
                label: hex::encode(label),
            })?;
        let name = item.label().unwrap_or_default();
        self.set_key_record_trust(RecordType::SYMMETRIC_KEY, number, &name, trusted)
    }

    /// Rewrite the access control of a stored private key.
    ///
    /// This is the identity equivalent of [`KeychainFile::set_item_trust`].
    pub fn set_private_key_trust(
        &mut self,
        record_number: u32,
        trusted: &[TrustedApplication],
    ) -> Result<()> {
        let record = self
            .records_of_type(RecordType::PRIVATE_KEY)
            .into_iter()
            .find(|record| record.number == record_number)
            .ok_or(Error::NoSuchItem)?;
        let name = self
            .schema()
            .attribute(RecordType::PRIVATE_KEY, record, "PrintName")
            .and_then(Value::as_bytes)
            .map(|bytes| String::from_utf8_lossy(crate::format::trim_nul(bytes)).into_owned())
            .unwrap_or_default();
        self.set_key_record_trust(RecordType::PRIVATE_KEY, record_number, &name, trusted)
    }

    /// Native ACL applications for a password item.
    ///
    /// `None` means the ACL was not in the canonical form this library models;
    /// an empty vector means any application.
    pub fn item_trusted_applications(
        &self,
        record_type: RecordType,
        record_number: u32,
    ) -> Result<Option<Vec<TrustedApplication>>> {
        let item = self
            .items_of_type(record_type)
            .into_iter()
            .find(|item| item.number() == record_number)
            .ok_or(Error::NoSuchItem)?;
        let label = Ssgp::parse(&item.record.key_data)?.label;
        let number = self
            .key_record_number(&label)
            .ok_or_else(|| Error::MissingItemKey {
                label: hex::encode(label),
            })?;
        self.key_record_trusted_applications(RecordType::SYMMETRIC_KEY, number)
    }

    /// Native ACL applications for a stored private key.
    pub fn private_key_trusted_applications(
        &self,
        record_number: u32,
    ) -> Result<Option<Vec<TrustedApplication>>> {
        self.key_record_trusted_applications(RecordType::PRIVATE_KEY, record_number)
    }

    fn key_record_trusted_applications(
        &self,
        record_type: RecordType,
        record_number: u32,
    ) -> Result<Option<Vec<TrustedApplication>>> {
        let blob = self
            .records_of_type(record_type)
            .into_iter()
            .find(|record| record.number == record_number)
            .map(|record| crypto::KeyBlob::parse(&record.key_data))
            .transpose()?
            .ok_or(Error::NoSuchItem)?;
        Ok(blob.public_acl.trusted_applications().map(<[_]>::to_vec))
    }

    fn set_key_record_trust(
        &mut self,
        record_type: RecordType,
        record_number: u32,
        fallback_name: &str,
        trusted: &[TrustedApplication],
    ) -> Result<()> {
        let keys = self.keys().ok_or(Error::Locked)?;
        let signing_key = SecretBytes::new(keys.signing_key.as_slice());

        // The ACL is replaced with this crate's canonical form, so an ACL it
        // could not parse must not be touched: rewriting one would silently
        // drop whatever macOS put there.
        let existing = self
            .records_of_type(record_type)
            .into_iter()
            .find(|record| record.number == record_number)
            .map(|record| crypto::KeyBlob::parse(&record.key_data))
            .transpose()?
            .ok_or(Error::NoSuchItem)?;
        if existing.public_acl.item_name().is_none() {
            return Err(Error::other(
                "this item's access control is in a form this build does not parse; \
                 refusing to overwrite it",
            ));
        }
        // Keep the name the ACL already carries: it is the item's name as of
        // when the key was created, and macOS does not rewrite it either.
        let name = existing
            .public_acl
            .item_name()
            .map(str::to_string)
            .unwrap_or_else(|| fallback_name.to_string());

        let acl = if trusted.is_empty() {
            AclBlob::for_item(&name)
        } else {
            AclBlob::for_item_trusting(&name, trusted.to_vec())
        };

        let keychain = self.keychain_mut();
        keychain.bump_commit_version();
        let table = keychain
            .table_mut(record_type)
            .ok_or(Error::MissingTable("key record table"))?;
        let record = table
            .records_mut()
            .find(|record| record.number == record_number)
            .ok_or(Error::NoSuchItem)?;

        let mut blob = crypto::KeyBlob::parse(&record.key_data)?;
        blob.public_acl = crypto::PublicAcl::Parsed(acl);
        blob.sign(signing_key.as_slice());
        record.key_data = blob.to_bytes();
        Ok(())
    }

    /// Change the password that protects the keychain.
    ///
    /// The database's own keys are preserved — every item key in the file is
    /// wrapped under them — so only the blob is re-sealed: a fresh salt and IV,
    /// the keys re-encrypted under the new password, and a new signature.
    /// Nothing outside the metadata record changes.
    pub fn change_password(&mut self, old: &[u8], new: &[u8]) -> Result<()> {
        let mut blob = self.db_blob()?;
        let keys = blob.unlock(old)?;

        blob.salt.copy_from_slice(&random_bytes(SALT_LEN));
        blob.iv.copy_from_slice(&random_bytes(BLOCK_SIZE));
        blob.seal(new, &keys)?;

        self.replace_db_blob(&blob)?;
        // The old derivation is stale; adopt the new one so the handle stays
        // usable and item keys stay available.
        self.unlock(new)
    }

    /// The keychain's settings, as stored in the database blob.
    pub fn settings(&self) -> Result<Settings> {
        let blob = self.db_blob()?;
        Ok(Settings {
            idle_timeout: blob.idle_timeout,
            lock_on_sleep: blob.lock_on_sleep,
        })
    }

    /// Change the keychain's settings.
    ///
    /// The settings live in the signed part of the database blob, so this needs
    /// the signing key: an unlocked keychain, or the password.
    pub fn set_settings(&mut self, settings: &Settings) -> Result<()> {
        settings.validate()?;
        let keys = self.keys().ok_or(Error::Locked)?;
        let signing_key = SecretBytes::new(keys.signing_key.as_slice());

        let mut blob = self.db_blob()?;
        blob.idle_timeout = settings.idle_timeout;
        blob.lock_on_sleep = settings.lock_on_sleep;
        blob.sign(signing_key.as_slice());
        self.replace_db_blob(&blob)
    }

    /// Write a database blob back into the metadata record.
    ///
    /// The metadata record carries a counter of its own in the fourth header
    /// word, which macOS advances by one on every re-seal, along with the
    /// container's commit version.
    fn replace_db_blob(&mut self, blob: &DbBlob) -> Result<()> {
        let bytes = blob.to_bytes();
        let keychain = self.keychain_mut();
        keychain.bump_commit_version();
        let table = keychain
            .table_mut(RecordType::METADATA)
            .ok_or(Error::MissingTable("CSSM_DL_DB_RECORD_METADATA"))?;
        let record = table
            .records_mut()
            .next()
            .ok_or_else(|| Error::format("metadata table has no record"))?;
        record.key_data = bytes;
        record.unknown3 = record.unknown3.wrapping_add(1);
        Ok(())
    }

    /// The record number of the key whose `Label` is `label`.
    fn key_record_number(&self, label: &[u8; 20]) -> Option<u32> {
        self.records_of_type(RecordType::SYMMETRIC_KEY)
            .into_iter()
            .find(|record| {
                self.schema()
                    .attribute(RecordType::SYMMETRIC_KEY, record, "Label")
                    .and_then(Value::as_bytes)
                    .is_some_and(|stored| stored == label)
            })
            .map(|record| record.number)
    }
}

/// Fit a value to the format its attribute is declared with.
///
/// Text arrives from a caller that has no schema in hand — a command line, say —
/// so `"7"` for an integer attribute arrives as bytes. Storing those bytes would
/// not fail loudly: an integer is four raw bytes and a blob is a length followed
/// by data, so `"7"` would be read back as *1*, its own length. Anything that
/// cannot be fitted is an error rather than a guess.
fn coerce(name: &str, value: Value, format: AttributeFormat) -> Result<Value> {
    let bytes = match &value {
        Value::Blob(bytes) | Value::String(bytes) => bytes.clone(),
        // Already typed by the caller: only the format has to agree.
        Value::Uint32(_) | Value::Sint32(_) => {
            return match format {
                AttributeFormat::Uint32 | AttributeFormat::Sint32 => Ok(value),
                _ => Err(Error::other(format!("{name} is not a number attribute"))),
            };
        }
        Value::Date(_) => {
            return match format {
                AttributeFormat::TimeDate => Ok(value),
                _ => Err(Error::other(format!("{name} is not a date attribute"))),
            };
        }
    };
    let text = String::from_utf8_lossy(&bytes).into_owned();

    match format {
        AttributeFormat::Blob | AttributeFormat::String => Ok(Value::Blob(bytes)),
        AttributeFormat::Uint32 | AttributeFormat::Sint32 => {
            // Some integer attributes hold a four-character code; `ptcl` reads
            // as `htps`, and that is how it is written here too.
            if FOUR_CHAR_CODE_ATTRIBUTES.contains(&name) && bytes.len() == 4 {
                let code = u32::from_be_bytes(bytes[..4].try_into().expect("four bytes"));
                return Ok(Value::Uint32(code));
            }
            let number: i64 = text.trim().parse().map_err(|_| {
                Error::other(format!(
                    "{name} is a number attribute; {text:?} is not a number"
                ))
            })?;
            match format {
                AttributeFormat::Uint32 => u32::try_from(number)
                    .map(Value::Uint32)
                    .map_err(|_| Error::other(format!("{number} does not fit {name}"))),
                _ => i32::try_from(number)
                    .map(Value::Sint32)
                    .map_err(|_| Error::other(format!("{number} does not fit {name}"))),
            }
        }
        AttributeFormat::TimeDate => {
            // The stored form is fixed: `YYYYMMDDhhmmssZ` and a NUL.
            let trimmed = text.trim_end_matches('\0');
            if trimmed.len() != 15 || !trimmed.ends_with('Z') {
                return Err(Error::other(format!(
                    "{name} is a date; expected YYYYMMDDhhmmssZ, got {trimmed:?}"
                )));
            }
            Ok(Value::Date(date_bytes(trimmed)))
        }
        other => Err(Error::other(format!(
            "{name} has attribute format {other:?}, which this build cannot write"
        ))),
    }
}

/// A timestamp as the fixed sixteen bytes a date attribute holds.
fn date_bytes(timestamp: &str) -> Vec<u8> {
    let mut bytes = timestamp.as_bytes().to_vec();
    bytes.resize(16, 0);
    bytes
}

/// A certificate stored in the keychain, and the private key that goes with it
/// when the keychain has one.
#[derive(Debug, Clone)]
pub struct StoredIdentity {
    /// `PrintName` of the certificate record.
    pub label: Option<String>,
    /// SHA-1 of the certificate's public key: what links the two records.
    pub public_key_hash: Vec<u8>,
    pub certificate_record: u32,
    /// The certificate, DER-encoded, exactly as stored.
    pub certificate: Vec<u8>,
    pub private_key_record: Option<u32>,
}

impl KeychainFile {
    /// Certificates in the keychain, paired with their private keys.
    pub fn identities(&self) -> Vec<StoredIdentity> {
        let mut key_by_label: Vec<(Vec<u8>, u32)> = Vec::new();
        for record in self.records_of_type(RecordType::PRIVATE_KEY) {
            if let Some(label) = self
                .schema()
                .attribute(RecordType::PRIVATE_KEY, record, "Label")
                .and_then(Value::as_bytes)
            {
                key_by_label.push((label.to_vec(), record.number));
            }
        }

        self.records_of_type(RecordType::X509_CERTIFICATE)
            .into_iter()
            .map(|record| {
                let public_key_hash = self
                    .schema()
                    .attribute(RecordType::X509_CERTIFICATE, record, "PublicKeyHash")
                    .and_then(Value::as_bytes)
                    .unwrap_or_default()
                    .to_vec();
                let label = self
                    .schema()
                    .attribute(RecordType::X509_CERTIFICATE, record, "PrintName")
                    .and_then(Value::as_bytes)
                    .map(|bytes| {
                        String::from_utf8_lossy(crate::format::trim_nul(bytes)).into_owned()
                    })
                    .filter(|name| !name.is_empty());
                let private_key_record = key_by_label
                    .iter()
                    .find(|(key_label, _)| *key_label == public_key_hash)
                    .map(|(_, number)| *number);
                StoredIdentity {
                    label,
                    public_key_hash,
                    certificate_record: record.number,
                    certificate: record.key_data.clone(),
                    private_key_record,
                }
            })
            .collect()
    }

    /// A stored private key, unwrapped, as a PKCS#8 `PrivateKeyInfo`.
    ///
    /// Requires an unlocked keychain. The bytes are the ones that went in: this
    /// is the reverse of [`KeychainFile::add_identity`].
    pub fn private_key_pkcs8(&self, record_number: u32) -> Result<SecretBytes> {
        let keys = self.keys().ok_or(Error::Locked)?;
        let record = self
            .records_of_type(RecordType::PRIVATE_KEY)
            .into_iter()
            .find(|record| record.number == record_number)
            .ok_or(Error::NoSuchItem)?;
        let blob = crypto::KeyBlob::parse(&record.key_data)?;
        crypto::unwrap_blob(keys.encryption_key.as_slice(), &blob.iv, &blob.crypto_blob)
    }
}
