//! Creating keychains and adding items.
//!
//! Three operations, all of which have to agree with macOS byte for byte to be
//! useful:
//!
//! * [`create`] writes a new database: the four schema tables replayed from
//!   [`apple_schema`], an empty table per record relation, and a metadata record
//!   holding a fresh `DbBlob` sealed with the caller's password.
//! * [`KeychainFile::add_password`] stores an item: a wrapped item key in the
//!   symmetric-key table and the encrypted secret in the item record.
//! * [`KeychainFile::add_identity`] stores a certificate and its private key,
//!   adding the certificate relation to the schema first if the keychain has
//!   never held one.
//!
//! Every write rebuilds the indexes of the tables it touched, because their
//! offsets are table-relative: a stale index region sends macOS into the middle
//! of a record and it reports `errSecNoSuchAttr`.

use crate::acl::{AclBlob, TrustedApplication};
use crate::apple_schema::{self, RECORD_VERSION};
use crate::crypto::{
    self, BLOB_VERSION, BLOCK_SIZE, DbBlob, DbKeys, KEY_LEN, SALT_LEN, SecretBytes, Ssgp,
};
use crate::cssm::{KeyHeader, WrappedKeyFields};
use crate::db::KeychainFile;
use crate::der;
use crate::error::{Error, Result};
use crate::format::{
    HEADER_SIZE_FIELD, Keychain, Record, Slot, Table, TableIndexes, VERSION, Value,
};
use crate::index::{Index, IndexBlob};
use crate::records::{CertificateRecord, ItemKeyRecord, PasswordRecord, PrivateKeyRecord};
use crate::schema::{AttributeFormat, RecordType, Relation, Schema};

/// Value macOS writes in a symmetric-key record's fourth header word. Its
/// meaning is unknown; most record types get `0`.
const KEY_RECORD_UNKNOWN3: u32 = 4;

/// The same word in a private-key record, where macOS writes `5`.
const PRIVATE_KEY_RECORD_UNKNOWN3: u32 = 5;

/// An identity to store: a certificate and the private key that matches it.
#[derive(Debug, Clone)]
pub struct NewIdentity {
    /// The certificate, DER-encoded.
    pub certificate: Vec<u8>,
    /// The private key as a PKCS#8 `PrivateKeyInfo`, DER-encoded.
    pub private_key: Vec<u8>,
    /// Label for both records. Defaults to the certificate's common name.
    pub label: Option<String>,
    /// Applications allowed to use the private key. Empty means any.
    pub trusted_applications: Vec<TrustedApplication>,
}

/// Settings for a new keychain. The defaults are what macOS writes.
#[derive(Debug, Clone)]
pub struct CreateOptions {
    /// Seconds of inactivity before locking. macOS writes 300.
    pub idle_timeout: u32,
    pub lock_on_sleep: bool,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            idle_timeout: 300,
            lock_on_sleep: true,
        }
    }
}

/// Build a new keychain protected by `password`.
pub fn create(password: &[u8], options: &CreateOptions) -> Result<KeychainFile> {
    let mut tables = Vec::with_capacity(apple_schema::TABLES.len());

    for template in &apple_schema::TABLES {
        let record_type = RecordType(template.relation_id);
        // Index declarations come from the template; entries are built as
        // records are added. An empty table's declarations sit right after its
        // slot array, which is where the template's offsets were measured from.
        let template_offset = crate::format::TABLE_HEADER_LEN + 4;
        let indexes = IndexBlob::parse(template.index_data, template_offset, None)
            .map(TableIndexes::Parsed)
            .unwrap_or_else(|_| TableIndexes::Raw(template.index_data.to_vec()));
        let mut table = Table {
            record_type,
            free_list_head: template.free_list,
            slots: Vec::new(),
            layout: Vec::new(),
            indexes,
        };

        match record_type {
            RecordType::SCHEMA_INFO => {
                for (number, row) in apple_schema::RELATIONS.iter().enumerate() {
                    table.slots.push(Slot::Record(schema_record(
                        number as u32,
                        vec![
                            Some(Value::Uint32(row.relation_id)),
                            row.name.map(|name| Value::String(name.to_vec())),
                        ],
                    )));
                }
            }
            RecordType::SCHEMA_INDEXES => {
                for (number, row) in apple_schema::INDEXES.iter().enumerate() {
                    table.slots.push(Slot::Record(schema_record(
                        number as u32,
                        vec![
                            Some(Value::Uint32(row.relation_id)),
                            Some(Value::Uint32(row.index_id)),
                            Some(Value::Uint32(row.attribute_id)),
                            Some(Value::Uint32(row.index_type)),
                            Some(Value::Uint32(row.indexed_data_location)),
                        ],
                    )));
                }
            }
            RecordType::SCHEMA_ATTRIBUTES => {
                for (number, row) in apple_schema::ATTRIBUTES.iter().enumerate() {
                    table.slots.push(Slot::Record(schema_record(
                        number as u32,
                        vec![
                            Some(Value::Uint32(row.relation_id)),
                            Some(Value::Uint32(row.attribute_id)),
                            Some(Value::Uint32(row.name_format)),
                            row.name.map(|name| Value::String(name.to_vec())),
                            row.name_id.map(|id| Value::Blob(id.to_vec())),
                            Some(Value::Uint32(row.format)),
                        ],
                    )));
                }
            }
            RecordType::METADATA => {
                // Filled in below, once the blob is sealed.
            }
            _ => {
                // An empty table still carries one unused slot, the way macOS
                // writes it.
                table.slots.push(Slot::Empty);
            }
        }

        tables.push(table);
    }

    // The database blob: fresh salt, IV, and keys, sealed with the password.
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&crate::secret::random_bytes(SALT_LEN));
    let mut iv = [0u8; BLOCK_SIZE];
    iv.copy_from_slice(&crate::secret::random_bytes(BLOCK_SIZE));
    let mut random_signature = [0u8; 16];
    random_signature.copy_from_slice(&crate::secret::random_bytes(16));

    let keys = DbKeys {
        encryption_key: SecretBytes::new(crate::secret::random_bytes(KEY_LEN)),
        signing_key: SecretBytes::new(crate::secret::random_bytes(20)),
        private_acl: Vec::new(),
    };

    let mut blob = DbBlob {
        version: BLOB_VERSION,
        start_crypto_blob: 0,
        total_length: 0,
        random_signature,
        sequence: 0,
        idle_timeout: options.idle_timeout,
        lock_on_sleep: options.lock_on_sleep,
        // A keychain this code creates has no uninitialized memory to leak.
        parameters_padding: [0; 3],
        salt,
        iv,
        blob_signature: [0u8; 20],
        public_acl: crate::acl::database_public_acl(),
        crypto_blob: Vec::new(),
    };
    blob.seal(password, &keys)?;

    let metadata = tables
        .iter_mut()
        .find(|table| table.record_type == RecordType::METADATA)
        .ok_or(Error::MissingTable("CSSM_DL_DB_RECORD_METADATA"))?;
    metadata.slots.push(Slot::Record(Record {
        number: 0,
        version: RECORD_VERSION,
        unknown3: 0,
        unknown5: 0,
        key_data: blob.to_bytes(),
        attributes: Vec::new(),
    }));

    let keychain = Keychain {
        version: VERSION,
        header_size: HEADER_SIZE_FIELD,
        auth_offset: 0,
        tables,
        commit_version: Some(1),
    };

    let mut file = KeychainFile::from_bytes(&keychain.to_bytes()?)?;
    file.unlock(password)?;
    Ok(file)
}

/// Store an empty value for every attribute of the unique index that has none.
///
/// An attribute a record does not have is not indexed, and an item missing from
/// its relation's unique index cannot be found through the Security framework.
/// macOS avoids that by storing the identity attributes it was given no value
/// for as zero or empty: an internet item with no port has `port` = 0 and `path`
/// = "", not no `port` at all.
fn fill_unique_key(relation: &Relation, unique: &[u32], attributes: &mut [Option<Value>]) {
    for id in unique {
        let Some(position) = relation
            .attributes
            .iter()
            .position(|attribute| attribute.id == *id)
        else {
            continue;
        };
        let Some(slot) = attributes.get_mut(position) else {
            continue;
        };
        if slot.is_some() {
            continue;
        }
        *slot = match relation.attributes[position].format {
            AttributeFormat::Sint32 => Some(Value::Sint32(0)),
            AttributeFormat::Uint32 => Some(Value::Uint32(0)),
            AttributeFormat::Blob => Some(Value::Blob(Vec::new())),
            AttributeFormat::String => Some(Value::String(Vec::new())),
            // A date is a fixed sixteen bytes, so it has no empty form; no date
            // attribute takes part in a unique index. The rest are formats no
            // password relation uses, and a guessed value would be worse than
            // none.
            _ => None,
        };
    }
}

/// The index declarations of a relation, as an index region with no entries.
///
/// One index per `IndexID`, over the attributes its rows name, in row order. The
/// `IndexType` in the schema is the inverse of the `kind` word in the region: a
/// schema type of `0` marks the relation's unique index, which the region writes
/// as `1`.
fn index_declarations(rows: &[apple_schema::IndexRow]) -> IndexBlob {
    let mut indexes: Vec<Index> = Vec::new();
    for row in rows {
        match indexes.iter_mut().find(|index| index.id == row.index_id) {
            Some(index) => index.attribute_ids.push(row.attribute_id),
            None => indexes.push(Index {
                id: row.index_id,
                kind: u32::from(row.index_type == 0),
                attribute_ids: vec![row.attribute_id],
                entries: Vec::new(),
            }),
        }
    }
    IndexBlob { indexes }
}

fn schema_record(number: u32, attributes: Vec<Option<Value>>) -> Record {
    Record {
        number,
        version: RECORD_VERSION,
        unknown3: 0,
        unknown5: 0,
        key_data: Vec::new(),
        attributes,
    }
}

/// What to store for a new password item.
#[derive(Debug, Clone, Default)]
pub struct NewItem {
    /// `PrintName`: the name Keychain Access shows. Defaults to the service or
    /// server when not set.
    pub label: Option<String>,
    /// `acct`
    pub account: Option<String>,
    /// `svce`, generic items only.
    pub service: Option<String>,
    /// `gena`, generic items only: application-defined bytes.
    pub generic: Option<Vec<u8>>,
    /// `srvr`, internet and AppleShare items.
    pub server: Option<String>,
    /// `sdmn`, internet items only: the authentication realm.
    pub security_domain: Option<String>,
    /// `path`, internet items only.
    pub path: Option<String>,
    /// `port`, internet items only.
    pub port: Option<u32>,
    /// `ptcl`, internet and AppleShare items: a four-char code such as `http`.
    pub protocol: Option<[u8; 4]>,
    /// `atyp`, internet items only: a four-char code such as `dflt`.
    pub auth_type: Option<[u8; 4]>,
    /// `vlme`, AppleShare items only.
    pub volume: Option<String>,
    /// `addr`, AppleShare items only.
    pub address: Option<String>,
    /// `ssig`, AppleShare items only.
    pub signature: Option<String>,
    /// `desc`: the "kind" shown in Keychain Access.
    pub description: Option<String>,
    /// `icmt`: free-text comment.
    pub comment: Option<String>,
    /// Applications allowed to decrypt the item. Empty means any application,
    /// which is what `security add-generic-password -A` stores.
    pub trusted_applications: Vec<TrustedApplication>,
}

impl NewItem {
    /// Lower into the stored attribute set.
    fn to_record(&self, print_name: &str, timestamp: &str) -> PasswordRecord {
        PasswordRecord {
            created: timestamp.to_string(),
            modified: timestamp.to_string(),
            print_name: print_name.to_string(),
            description: self.description.clone(),
            comment: self.comment.clone(),
            account: self.account.clone(),
            service: self.service.clone(),
            generic: self.generic.clone(),
            server: self.server.clone(),
            security_domain: self.security_domain.clone(),
            path: self.path.clone(),
            port: self.port,
            protocol: self.protocol,
            auth_type: self.auth_type,
            volume: self.volume.clone(),
            address: self.address.clone(),
            signature: self.signature.clone(),
        }
    }

    /// The name to store as `PrintName`.
    fn print_name(&self) -> String {
        self.label
            .clone()
            .or_else(|| self.service.clone())
            .or_else(|| self.server.clone())
            .or_else(|| self.volume.clone())
            .or_else(|| self.account.clone())
            .unwrap_or_default()
    }
}

impl KeychainFile {
    /// Store a password item, creating the item key that protects it.
    ///
    /// Requires an unlocked keychain: the item key is wrapped with the
    /// database's encryption key and both blobs are signed with its signing key.
    pub fn add_password(
        &mut self,
        record_type: RecordType,
        item: &NewItem,
        secret: &[u8],
        timestamp: &str,
    ) -> Result<()> {
        let keys = self.keys().ok_or(Error::Locked)?;
        let encryption_key = SecretBytes::new(keys.encryption_key.as_slice());
        let signing_key = SecretBytes::new(keys.signing_key.as_slice());

        // One fresh key per item, wrapped under the database key, exactly as
        // macOS does. The label ties the item to its key.
        let item_key = SecretBytes::new(crate::secret::random_bytes(KEY_LEN));
        let mut label = [0u8; 20];
        label[..4].copy_from_slice(crypto::SSGP_MAGIC);
        label[4..].copy_from_slice(&crate::secret::random_bytes(16));

        let print_name = item.print_name();
        let key_attributes = {
            let relation = self
                .schema()
                .relation(RecordType::SYMMETRIC_KEY)
                .ok_or(Error::MissingTable("CSSM_DL_DB_RECORD_SYMMETRIC_KEY"))?;
            ItemKeyRecord::for_item_key(label).to_attributes(relation)
        };
        let key_blob = self.wrap_item_key(
            &item_key,
            encryption_key.as_slice(),
            signing_key.as_slice(),
            &print_name,
            &item.trusted_applications,
        )?;

        let mut ssgp_iv = [0u8; BLOCK_SIZE];
        ssgp_iv.copy_from_slice(&crate::secret::random_bytes(BLOCK_SIZE));
        let ssgp = Ssgp::seal(label, ssgp_iv, item_key.as_slice(), secret)?;

        let item_attributes = {
            let relation = self.schema().relation(record_type).ok_or_else(|| {
                Error::format(format!("keychain has no 0x{:08x} relation", record_type.0))
            })?;
            let mut attributes = item
                .to_record(&print_name, timestamp)
                .to_attributes(relation);
            if let Some(table) = self.keychain().table(record_type)
                && let Some(unique) = table.unique_index_attribute_ids()
            {
                fill_unique_key(relation, unique, &mut attributes);
            }
            attributes
        };

        // macOS refuses a second item with the same unique key, and two records
        // sharing one index key would give the index two entries that cannot be
        // told apart. Refusing here keeps the file valid.
        if let Some(relation) = self.schema().relation(record_type)
            && let Some(table) = self.keychain().table(record_type)
            && table.has_record_with_unique_key(relation, &item_attributes)
        {
            return Err(Error::DuplicateItem);
        }

        // Both records are stamped with the commit version of this write, the
        // way macOS stamps them, and both go in together: an item without its
        // key is unreadable, and a key without its item is garbage.
        let keychain = self.keychain_mut();
        keychain.bump_commit_version();
        let version = keychain.commit_version.unwrap_or(1);

        let key_table = keychain
            .table_mut(RecordType::SYMMETRIC_KEY)
            .ok_or(Error::MissingTable("CSSM_DL_DB_RECORD_SYMMETRIC_KEY"))?;
        key_table.insert(Record {
            // `insert` assigns the record number: it is the slot it lands in.
            number: 0,
            version,
            unknown3: KEY_RECORD_UNKNOWN3,
            unknown5: 0,
            key_data: key_blob,
            attributes: key_attributes,
        });

        let table = keychain
            .table_mut(record_type)
            .ok_or(Error::MissingTable("password table"))?;
        table.insert(Record {
            // `insert` assigns the record number: it is the slot it lands in.
            number: 0,
            version,
            unknown3: 0,
            unknown5: 0,
            key_data: ssgp.to_bytes(),
            attributes: item_attributes,
        });

        // Both tables' indexes must be rebuilt: the records moved, so every
        // table-relative offset in the region changed, and the new records need
        // entries or the Security framework will not find them.
        let schema = self.schema().clone();
        for touched in [RecordType::SYMMETRIC_KEY, record_type] {
            let Some(relation) = schema.relation(touched) else {
                continue;
            };
            if let Some(table) = self.keychain_mut().table_mut(touched) {
                table.rebuild_indexes(relation)?;
            }
        }

        self.remember_item_key(label, item_key);
        Ok(())
    }

    /// Store an identity: the certificate in the clear, the private key wrapped.
    ///
    /// The two records are linked by the certificate's public key hash, which the
    /// key record carries as its `Label` — that is how `SecIdentity` pairs them,
    /// and how [`crate::db::KeychainFile`] and `security` both find
    /// them.
    ///
    /// Requires an unlocked keychain: the private key is wrapped with the
    /// database's encryption key, and both blobs are signed with its signing key.
    pub fn add_identity(&mut self, identity: &NewIdentity) -> Result<[u8; 20]> {
        self.ensure_relation(RecordType::X509_CERTIFICATE)?;

        let keys = self.keys().ok_or(Error::Locked)?;
        let encryption_key = SecretBytes::new(keys.encryption_key.as_slice());
        let signing_key = SecretBytes::new(keys.signing_key.as_slice());

        let certificate = der::Certificate::parse(&identity.certificate)?;
        let public_key_hash = certificate.public_key_hash();
        let label = identity
            .label
            .clone()
            .or_else(|| certificate.common_name.clone())
            .unwrap_or_else(|| hex::encode(public_key_hash));

        // The key must actually match the certificate, or the identity is a pair
        // of records that can never be used together.
        let key_info = der::PrivateKeyInfo::parse(&identity.private_key)?;
        if !key_info.is_rsa() {
            return Err(Error::other(
                "only RSA private keys are supported; an EC key would need its own \
                 KeyType and key-size handling, which is not implemented",
            ));
        }
        let key_size = key_info.rsa_key_size_in_bits()?;

        let certificate_attributes = {
            let relation = self
                .schema()
                .relation(RecordType::X509_CERTIFICATE)
                .ok_or(Error::MissingTable("CSSM_DL_DB_RECORD_X509_CERTIFICATE"))?;
            CertificateRecord::for_certificate(&label, &certificate).to_attributes(relation)
        };
        let key_attributes = {
            let relation = self
                .schema()
                .relation(RecordType::PRIVATE_KEY)
                .ok_or(Error::MissingTable("CSSM_DL_DB_RECORD_PRIVATE_KEY"))?;
            PrivateKeyRecord::for_private_key(&label, public_key_hash, key_size)
                .to_attributes(relation)
        };

        let key_blob = self.wrap_private_key(
            &identity.private_key,
            encryption_key.as_slice(),
            signing_key.as_slice(),
            &label,
            key_size,
            &identity.trusted_applications,
        )?;

        let keychain = self.keychain_mut();
        keychain.bump_commit_version();
        let version = keychain.commit_version.unwrap_or(1);

        let key_table = keychain
            .table_mut(RecordType::PRIVATE_KEY)
            .ok_or(Error::MissingTable("CSSM_DL_DB_RECORD_PRIVATE_KEY"))?;
        key_table.insert(Record {
            // `insert` assigns the record number: it is the slot it lands in.
            number: 0,
            version,
            unknown3: PRIVATE_KEY_RECORD_UNKNOWN3,
            unknown5: 0,
            key_data: key_blob,
            attributes: key_attributes,
        });

        let certificate_table = keychain
            .table_mut(RecordType::X509_CERTIFICATE)
            .ok_or(Error::MissingTable("CSSM_DL_DB_RECORD_X509_CERTIFICATE"))?;
        certificate_table.insert(Record {
            // `insert` assigns the record number: it is the slot it lands in.
            number: 0,
            version,
            unknown3: 0,
            unknown5: 0,
            // A certificate is public: it is stored unencrypted.
            key_data: identity.certificate.clone(),
            attributes: certificate_attributes,
        });

        let schema = self.schema().clone();
        for touched in [RecordType::PRIVATE_KEY, RecordType::X509_CERTIFICATE] {
            let Some(relation) = schema.relation(touched) else {
                continue;
            };
            if let Some(table) = self.keychain_mut().table_mut(touched) {
                table.rebuild_indexes(relation)?;
            }
        }
        Ok(public_key_hash)
    }

    /// Add a relation to the schema, if the keychain does not have it yet.
    ///
    /// A keychain from `security create-keychain` has no certificate table:
    /// `securityd` appends the relation's schema rows and an empty table the
    /// first time something stores a certificate. Writing a certificate record
    /// into a keychain that has no such relation would produce a file macOS
    /// cannot read, so the relation is created the same way here.
    fn ensure_relation(&mut self, record_type: RecordType) -> Result<()> {
        if self.keychain().table(record_type).is_some() {
            return Ok(());
        }
        let definition = apple_schema::ON_DEMAND_RELATIONS
            .iter()
            .find(|relation| relation.relation.relation_id == record_type.0)
            .ok_or_else(|| {
                Error::other(format!(
                    "this keychain has no {} table, and adding that relation is not supported",
                    record_type.name()
                ))
            })?;

        let keychain = self.keychain_mut();

        let info = keychain
            .table_mut(RecordType::SCHEMA_INFO)
            .ok_or(Error::MissingTable("CSSM_DL_DB_SCHEMA_INFO"))?;
        info.insert(schema_record(
            0,
            vec![
                Some(Value::Uint32(definition.relation.relation_id)),
                definition
                    .relation
                    .name
                    .map(|name| Value::String(name.to_vec())),
            ],
        ));

        let attributes = keychain
            .table_mut(RecordType::SCHEMA_ATTRIBUTES)
            .ok_or(Error::MissingTable("CSSM_DL_DB_SCHEMA_ATTRIBUTES"))?;
        for row in definition.attributes {
            attributes.insert(schema_record(
                0,
                vec![
                    Some(Value::Uint32(row.relation_id)),
                    Some(Value::Uint32(row.attribute_id)),
                    Some(Value::Uint32(row.name_format)),
                    row.name.map(|name| Value::String(name.to_vec())),
                    row.name_id.map(|id| Value::Blob(id.to_vec())),
                    Some(Value::Uint32(row.format)),
                ],
            ));
        }

        let indexes = keychain
            .table_mut(RecordType::SCHEMA_INDEXES)
            .ok_or(Error::MissingTable("CSSM_DL_DB_SCHEMA_INDEXES"))?;
        for row in definition.indexes {
            indexes.insert(schema_record(
                0,
                vec![
                    Some(Value::Uint32(row.relation_id)),
                    Some(Value::Uint32(row.index_id)),
                    Some(Value::Uint32(row.attribute_id)),
                    Some(Value::Uint32(row.index_type)),
                    Some(Value::Uint32(row.indexed_data_location)),
                ],
            ));
        }

        let table = Table {
            record_type,
            free_list_head: definition.free_list,
            // An empty table still carries one unused slot, and the free list
            // points at it.
            slots: vec![Slot::Empty],
            layout: Vec::new(),
            indexes: TableIndexes::Parsed(index_declarations(definition.indexes)),
        };
        // The tables array is ordered by record type.
        let at = keychain
            .tables
            .iter()
            .position(|existing| existing.record_type.0 > record_type.0)
            .unwrap_or(keychain.tables.len());
        keychain.tables.insert(at, table);

        self.reload_schema()
    }

    /// The key blob for a private key: the same wrapping an item key uses, over a
    /// PKCS#8 payload instead of 24 bytes.
    fn wrap_private_key(
        &self,
        private_key: &[u8],
        encryption_key: &[u8],
        signing_key: &[u8],
        label: &str,
        key_size: u32,
        trusted: &[TrustedApplication],
    ) -> Result<Vec<u8>> {
        let mut iv = [0u8; BLOCK_SIZE];
        iv.copy_from_slice(&crate::secret::random_bytes(BLOCK_SIZE));

        let mut blob = crypto::KeyBlob {
            version: BLOB_VERSION,
            start_crypto_blob: 0,
            total_length: 0,
            iv,
            header: KeyHeader::private_key(key_size),
            wrapped: WrappedKeyFields::item_key(),
            blob_signature: [0u8; 20],
            public_acl: crypto::PublicAcl::Parsed(if trusted.is_empty() {
                AclBlob::for_item(label)
            } else {
                AclBlob::for_item_trusting(label, trusted.to_vec())
            }),
            crypto_blob: crypto::wrap_blob(encryption_key, &iv, private_key)?,
        };
        blob.sign(signing_key);
        Ok(blob.to_bytes())
    }

    /// The key blob for an item key: wrapped under the database key, carrying
    /// the item's ACL, and signed.
    #[allow(clippy::too_many_arguments)]
    fn wrap_item_key(
        &self,
        item_key: &SecretBytes,
        encryption_key: &[u8],
        signing_key: &[u8],
        print_name: &str,
        trusted: &[TrustedApplication],
    ) -> Result<Vec<u8>> {
        let mut iv = [0u8; BLOCK_SIZE];
        iv.copy_from_slice(&crate::secret::random_bytes(BLOCK_SIZE));

        let mut blob = crypto::KeyBlob {
            version: BLOB_VERSION,
            start_crypto_blob: 0,
            total_length: 0,
            iv,
            header: KeyHeader::item_key(),
            wrapped: WrappedKeyFields::item_key(),
            blob_signature: [0u8; 20],
            public_acl: crypto::PublicAcl::Parsed(if trusted.is_empty() {
                AclBlob::for_item(print_name)
            } else {
                AclBlob::for_item_trusting(print_name, trusted.to_vec())
            }),
            crypto_blob: crypto::wrap_key(encryption_key, &iv, item_key.as_slice())?,
        };
        blob.sign(signing_key);
        Ok(blob.to_bytes())
    }
}

/// Format a timestamp the way keychain date attributes are written.
pub fn format_timestamp(unix_seconds: i64) -> String {
    let (days, seconds) = (
        unix_seconds.div_euclid(86_400),
        unix_seconds.rem_euclid(86_400),
    );
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (seconds / 3600, (seconds % 3600) / 60, seconds % 60);
    format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z")
}

/// Days since the epoch to a civil date (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Timestamp for right now.
pub fn now_timestamp() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    format_timestamp(seconds)
}

/// Verify a schema built by [`create`] against the file's own declarations.
pub fn schema_of_created(file: &KeychainFile) -> Result<Schema> {
    let schema = file.keychain().schema()?;
    // A created keychain must be able to describe its own password relations, or
    // nothing can be stored in it.
    for record_type in [
        RecordType::GENERIC_PASSWORD,
        RecordType::INTERNET_PASSWORD,
        RecordType::APPLESHARE_PASSWORD,
    ] {
        let relation = schema
            .relation(record_type)
            .ok_or_else(|| Error::format("created keychain is missing a password relation"))?;
        if relation.index_of("acct").is_none() {
            return Err(Error::format(
                "created keychain's password relation has no acct",
            ));
        }
    }
    Ok(schema)
}

/// Formats used by the password relations, for tests and diagnostics.
pub fn expected_format(name: &str) -> AttributeFormat {
    match name {
        "cdat" | "mdat" => AttributeFormat::TimeDate,
        "port" | "crtr" | "type" | "invi" | "nega" | "cusi" | "ptcl" => AttributeFormat::Uint32,
        "scrp" => AttributeFormat::Sint32,
        _ => AttributeFormat::Blob,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_match_the_keychain_format() {
        assert_eq!(format_timestamp(0), "19700101000000Z");
        assert_eq!(format_timestamp(1_784_982_896), "20260725123456Z");
        assert_eq!(format_timestamp(1_709_164_800), "20240229000000Z");
        assert_eq!(format_timestamp(951_782_400), "20000229000000Z");
        assert_eq!(now_timestamp().len(), 15);
        assert!(now_timestamp().ends_with('Z'));
    }

    #[test]
    fn a_created_keychain_unlocks_and_describes_itself() {
        let file = create(b"correct horse", &CreateOptions::default()).unwrap();
        assert!(file.is_unlocked());
        schema_of_created(&file).unwrap();

        let info = file.info().unwrap();
        assert_eq!(info.version, VERSION);
        assert_eq!(info.tables.len(), apple_schema::TABLES.len());
        assert_eq!(info.idle_timeout, 300);
        assert!(info.lock_on_sleep);
        assert!(file.items().is_empty());
    }

    #[test]
    fn a_created_keychain_rejects_the_wrong_password() {
        let file = create(b"right", &CreateOptions::default()).unwrap();
        let bytes = file.keychain().to_bytes().unwrap();

        let mut reopened = KeychainFile::from_bytes(&bytes).unwrap();
        assert!(matches!(
            reopened.unlock(b"wrong"),
            Err(Error::WrongPassword)
        ));
        assert!(!reopened.is_unlocked());
        reopened.unlock(b"right").unwrap();
    }

    #[test]
    fn created_keychains_differ_in_salt_and_keys() {
        let first = create(b"same password", &CreateOptions::default()).unwrap();
        let second = create(b"same password", &CreateOptions::default()).unwrap();
        assert_ne!(first.info().unwrap().salt, second.info().unwrap().salt);
        assert_ne!(first.info().unwrap().iv, second.info().unwrap().iv);
    }

    #[test]
    fn adding_an_item_stores_a_recoverable_secret() {
        let mut file = create(b"master", &CreateOptions::default()).unwrap();
        let item = NewItem {
            account: Some("alice".into()),
            service: Some("myservice".into()),
            description: Some("note kind".into()),
            ..NewItem::default()
        };
        file.add_password(
            RecordType::GENERIC_PASSWORD,
            &item,
            b"s3cr3t",
            "20260725123456Z",
        )
        .unwrap();

        // Round-trip through bytes, so this exercises the serializer too.
        let bytes = file.keychain().to_bytes().unwrap();
        let mut reopened = KeychainFile::from_bytes(&bytes).unwrap();
        reopened.unlock(b"master").unwrap();

        let items = reopened.items();
        assert_eq!(items.len(), 1);
        let stored = &items[0];
        assert_eq!(stored.account().as_deref(), Some("alice"));
        assert_eq!(stored.service().as_deref(), Some("myservice"));
        assert_eq!(stored.label().as_deref(), Some("myservice"));
        assert_eq!(stored.created().as_deref(), Some("20260725123456Z"));
        assert!(stored.has_secret());
        assert_eq!(reopened.secret(stored).unwrap().as_slice(), b"s3cr3t");
        assert_eq!(reopened.item_key_count(), 1);
    }

    #[test]
    fn each_item_gets_its_own_key() {
        let mut file = create(b"master", &CreateOptions::default()).unwrap();
        for (account, secret) in [("a", "one"), ("b", "two"), ("c", "three")] {
            let item = NewItem {
                account: Some(account.into()),
                service: Some("svc".into()),
                ..NewItem::default()
            };
            file.add_password(
                RecordType::GENERIC_PASSWORD,
                &item,
                secret.as_bytes(),
                "20260725123456Z",
            )
            .unwrap();
        }

        let bytes = file.keychain().to_bytes().unwrap();
        let mut reopened = KeychainFile::from_bytes(&bytes).unwrap();
        reopened.unlock(b"master").unwrap();
        assert_eq!(reopened.item_key_count(), 3, "one wrapped key per item");

        for (account, expected) in [("a", "one"), ("b", "two"), ("c", "three")] {
            let item = reopened
                .items()
                .into_iter()
                .find(|item| item.account().as_deref() == Some(account))
                .expect("item is present");
            assert_eq!(
                reopened.secret(&item).unwrap().as_slice(),
                expected.as_bytes()
            );
        }
    }

    #[test]
    fn internet_items_keep_their_network_attributes() {
        let mut file = create(b"master", &CreateOptions::default()).unwrap();
        let item = NewItem {
            account: Some("bob".into()),
            server: Some("example.com".into()),
            path: Some("/login".into()),
            port: Some(8080),
            protocol: Some(*b"http"),
            auth_type: Some(*b"dflt"),
            ..NewItem::default()
        };
        file.add_password(
            RecordType::INTERNET_PASSWORD,
            &item,
            b"pw",
            "20260725123456Z",
        )
        .unwrap();

        let bytes = file.keychain().to_bytes().unwrap();
        let mut reopened = KeychainFile::from_bytes(&bytes).unwrap();
        reopened.unlock(b"master").unwrap();

        let items = reopened.items_of_type(RecordType::INTERNET_PASSWORD);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].server().as_deref(), Some("example.com"));
        assert_eq!(items[0].path().as_deref(), Some("/login"));
        assert_eq!(items[0].port(), Some(8080));
        assert_eq!(items[0].label().as_deref(), Some("example.com"));
        assert_eq!(reopened.secret(&items[0]).unwrap().as_slice(), b"pw");
    }

    #[test]
    fn adding_to_a_locked_keychain_is_refused() {
        let file = create(b"master", &CreateOptions::default()).unwrap();
        let bytes = file.keychain().to_bytes().unwrap();
        let mut locked = KeychainFile::from_bytes(&bytes).unwrap();

        let result = locked.add_password(
            RecordType::GENERIC_PASSWORD,
            &NewItem::default(),
            b"secret",
            "20260725123456Z",
        );
        assert!(matches!(result, Err(Error::Locked)));
    }

    #[test]
    fn commit_version_advances_with_each_write() {
        let mut file = create(b"master", &CreateOptions::default()).unwrap();
        assert_eq!(file.keychain().commit_version, Some(1));
        file.add_password(
            RecordType::GENERIC_PASSWORD,
            &NewItem {
                account: Some("a".into()),
                ..NewItem::default()
            },
            b"x",
            "20260725123456Z",
        )
        .unwrap();
        assert_eq!(file.keychain().commit_version, Some(2));
    }
}
