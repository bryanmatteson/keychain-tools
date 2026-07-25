//! Table indexes: the sorted lookup structures in the trailing part of a table.
//!
//! Not described by the dtformats specification, and *not* opaque. Two things
//! make it impossible to treat this region as bytes to be copied:
//!
//! * Every offset in it is relative to the start of the *table*, so inserting a
//!   record moves the index region and invalidates all of them. macOS then
//!   follows a stale offset into the middle of a record and reports
//!   `errSecNoSuchAttr`.
//! * It holds one entry per record. A record with no index entry is not
//!   findable through the Security framework.
//!
//! ```text
//! region  := size, count, count x index offset
//! index   := size, id, kind, attribute count, attribute ids,
//!            entry count, entry offsets, record numbers, entries
//! entry   := payload size (excluding itself), key values
//! value   := four raw bytes for an integer attribute,
//!            else length prefix and bytes padded to four
//! ```
//!
//! Entries are sorted by key; the record-number array is in the same order, so
//! together they map a sorted key to a record. `tests/keychain_index.rs` parses
//! every index region in keychains written by macOS, re-serializes them byte for
//! byte, and checks that rebuilding an index from scratch reproduces macOS's
//! ordering.

use std::cmp::Ordering;

use crate::error::{Error, Result};
use crate::format::Value;
use crate::schema::{AttributeFormat, Relation};

/// One key value inside an index entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexValue {
    /// An integer attribute: four raw bytes, no length prefix.
    Integer(u32),
    /// Anything else: length-prefixed bytes, padded to a 4-byte boundary.
    Bytes(Vec<u8>),
}

impl IndexValue {
    /// The key form of an attribute value, given the attribute's format.
    pub fn from_value(value: Option<&Value>, format: AttributeFormat) -> Self {
        match (value, format) {
            (None, AttributeFormat::Sint32 | AttributeFormat::Uint32) => Self::Integer(0),
            (None, _) => Self::Bytes(Vec::new()),
            (Some(Value::Uint32(number)), _) => Self::Integer(*number),
            (Some(Value::Sint32(number)), _) => Self::Integer(*number as u32),
            (Some(Value::Date(bytes) | Value::String(bytes) | Value::Blob(bytes)), _) => {
                Self::Bytes(bytes.clone())
            }
        }
    }

    fn encoded_len(&self) -> usize {
        match self {
            Self::Integer(_) => 4,
            Self::Bytes(bytes) => pad4(4 + bytes.len()),
        }
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Self::Integer(number) => out.extend_from_slice(&number.to_be_bytes()),
            Self::Bytes(bytes) => {
                out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(bytes);
                out.resize(pad4(out.len()), 0);
            }
        }
    }
}

impl Ord for IndexValue {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Integer(left), Self::Integer(right)) => left.cmp(right),
            (Self::Bytes(left), Self::Bytes(right)) => left.cmp(right),
            // Mixed formats never occur within one index.
            (Self::Integer(_), Self::Bytes(_)) => Ordering::Less,
            (Self::Bytes(_), Self::Integer(_)) => Ordering::Greater,
        }
    }
}

impl PartialOrd for IndexValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// One indexed record: its key, and the record it points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub record_number: u32,
    pub key: Vec<IndexValue>,
}

impl IndexEntry {
    /// Size as stored, which excludes the size word itself.
    fn payload_len(&self) -> usize {
        self.key.iter().map(IndexValue::encoded_len).sum()
    }

    fn encoded_len(&self) -> usize {
        4 + self.payload_len()
    }
}

/// One index over one or more attributes of a relation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Index {
    /// Matches `IndexID` in the schema's index table.
    pub id: u32,
    /// Matches `IndexType`: `1` for the relation's unique index, `0` otherwise.
    pub kind: u32,
    /// The attributes indexed, by id.
    pub attribute_ids: Vec<u32>,
    /// Entries, sorted by key.
    pub entries: Vec<IndexEntry>,
}

impl Index {
    /// Words before the entry section: size, id, kind, count, ids.
    fn header_len(&self) -> usize {
        4 * (4 + self.attribute_ids.len())
    }

    fn encoded_len(&self) -> usize {
        self.header_len()
            + 4                                   // entry count
            + 8 * self.entries.len()              // offsets, then record numbers
            + self.entries.iter().map(IndexEntry::encoded_len).sum::<usize>()
    }

    /// Insert in sorted position, keeping the entry and record-number arrays in
    /// step.
    fn insert(&mut self, entry: IndexEntry) {
        let at = self
            .entries
            .iter()
            .position(|existing| existing.key > entry.key)
            .unwrap_or(self.entries.len());
        self.entries.insert(at, entry);
    }
}

/// The index region of one table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexBlob {
    pub indexes: Vec<Index>,
}

impl IndexBlob {
    /// Parse the region.
    ///
    /// `table_offset` is where the region sits within its table, which the stored
    /// offsets are measured against. `relation` supplies the attribute formats
    /// needed to tell an integer key from a length-prefixed one; without it the
    /// entries cannot be decoded.
    pub fn parse(data: &[u8], table_offset: usize, relation: Option<&Relation>) -> Result<Self> {
        let mut reader = Reader { data, at: 0 };
        let size = reader.u32()? as usize;
        if size != data.len() {
            return Err(Error::format(format!(
                "index region claims {size} bytes but has {}",
                data.len()
            )));
        }
        let count = reader.u32()? as usize;
        if count > 64 {
            return Err(Error::format(format!(
                "index region claims {count} indexes"
            )));
        }

        let mut offsets = Vec::with_capacity(count);
        for _ in 0..count {
            offsets.push(reader.u32()? as usize);
        }

        let mut indexes = Vec::with_capacity(count);
        for offset in offsets {
            let start = offset
                .checked_sub(table_offset)
                .ok_or_else(|| Error::format("index offset points before its table"))?;
            indexes.push(parse_index(data, start, table_offset, relation)?);
        }
        Ok(Self { indexes })
    }

    /// Serialize, recomputing every offset from `table_offset`.
    pub fn to_bytes(&self, table_offset: usize) -> Vec<u8> {
        let header_len = 8 + 4 * self.indexes.len();
        let mut out = Vec::with_capacity(self.encoded_len());

        out.extend_from_slice(&(self.encoded_len() as u32).to_be_bytes());
        out.extend_from_slice(&(self.indexes.len() as u32).to_be_bytes());
        let mut position = header_len;
        for index in &self.indexes {
            out.extend_from_slice(&((table_offset + position) as u32).to_be_bytes());
            position += index.encoded_len();
        }

        let mut position = header_len;
        for index in &self.indexes {
            write_index(&mut out, index, table_offset, position);
            position += index.encoded_len();
        }
        out
    }

    pub fn encoded_len(&self) -> usize {
        8 + 4 * self.indexes.len() + self.indexes.iter().map(Index::encoded_len).sum::<usize>()
    }

    /// Index a record in every index of the table.
    ///
    /// `key` maps an attribute id to that attribute's key value.
    pub fn insert_record(&mut self, record_number: u32, key: impl Fn(u32) -> IndexValue) {
        self.insert_record_where(record_number, key, |_| true);
    }

    /// Index a record only in the indexes `indexable` accepts.
    ///
    /// It is called with an index's attribute ids, and answers whether the
    /// record belongs in that index — macOS leaves a record out of an index when
    /// it has no value for an indexed attribute.
    pub fn insert_record_where(
        &mut self,
        record_number: u32,
        key: impl Fn(u32) -> IndexValue,
        indexable: impl Fn(&[u32]) -> bool,
    ) {
        for index in self
            .indexes
            .iter_mut()
            .filter(|index| indexable(&index.attribute_ids))
        {
            let values = index.attribute_ids.iter().map(|id| key(*id)).collect();
            index.insert(IndexEntry {
                record_number,
                key: values,
            });
        }
    }

    /// Drop entries for a record, and renumber the entries that referred to
    /// later records.
    pub fn remove_record(&mut self, record_number: u32) {
        for index in &mut self.indexes {
            index
                .entries
                .retain(|entry| entry.record_number != record_number);
        }
    }

    pub fn entry_count(&self) -> usize {
        self.indexes.iter().map(|index| index.entries.len()).sum()
    }

    /// Record numbers this region indexes, in key order, for the given index.
    pub fn record_numbers(&self, index_id: u32) -> Option<Vec<u32>> {
        self.indexes
            .iter()
            .find(|index| index.id == index_id)
            .map(|index| {
                index
                    .entries
                    .iter()
                    .map(|entry| entry.record_number)
                    .collect()
            })
    }
}

fn parse_index(
    data: &[u8],
    start: usize,
    table_offset: usize,
    relation: Option<&Relation>,
) -> Result<Index> {
    let mut reader = Reader { data, at: start };
    let size = reader.u32()? as usize;
    let id = reader.u32()?;
    let kind = reader.u32()?;
    let attribute_count = reader.u32()? as usize;
    if attribute_count > 32 {
        return Err(Error::format(format!(
            "index claims {attribute_count} attributes"
        )));
    }
    let mut attribute_ids = Vec::with_capacity(attribute_count);
    for _ in 0..attribute_count {
        attribute_ids.push(reader.u32()?);
    }

    let formats: Vec<AttributeFormat> = attribute_ids
        .iter()
        .map(|id| format_of(relation, *id))
        .collect();

    let entry_count = reader.u32()? as usize;
    let mut entry_offsets = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        entry_offsets.push(reader.u32()? as usize);
    }
    let mut record_numbers = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        record_numbers.push(reader.u32()?);
    }

    let mut entries = Vec::with_capacity(entry_count);
    for (offset, record_number) in entry_offsets.into_iter().zip(record_numbers) {
        let at = offset
            .checked_sub(table_offset)
            .ok_or_else(|| Error::format("index entry offset points before its table"))?;
        entries.push(parse_entry(data, at, record_number, &formats)?);
    }

    let index = Index {
        id,
        kind,
        attribute_ids,
        entries,
    };
    if index.encoded_len() != size {
        return Err(Error::format(format!(
            "index {id} claims {size} bytes but parses as {}",
            index.encoded_len()
        )));
    }
    Ok(index)
}

/// The format of an attribute, defaulting to a length-prefixed blob when the
/// relation is unknown. Getting this wrong misreads every key in the index, so
/// the caller is expected to pass the relation.
fn format_of(relation: Option<&Relation>, attribute_id: u32) -> AttributeFormat {
    relation
        .and_then(|relation| {
            relation
                .attributes
                .iter()
                .find(|attribute| attribute.id == attribute_id)
        })
        .map(|attribute| attribute.format)
        .unwrap_or(AttributeFormat::Blob)
}

fn parse_entry(
    data: &[u8],
    at: usize,
    record_number: u32,
    formats: &[AttributeFormat],
) -> Result<IndexEntry> {
    let mut reader = Reader { data, at };
    let payload = reader.u32()? as usize;
    let mut key = Vec::with_capacity(formats.len());
    for format in formats {
        key.push(match format {
            AttributeFormat::Sint32 | AttributeFormat::Uint32 => IndexValue::Integer(reader.u32()?),
            _ => IndexValue::Bytes(reader.value()?),
        });
    }
    let entry = IndexEntry { record_number, key };
    if entry.payload_len() != payload {
        return Err(Error::format(format!(
            "index entry claims {payload} bytes but parses as {}",
            entry.payload_len()
        )));
    }
    Ok(entry)
}

fn write_index(out: &mut Vec<u8>, index: &Index, table_offset: usize, position: usize) {
    out.extend_from_slice(&(index.encoded_len() as u32).to_be_bytes());
    out.extend_from_slice(&index.id.to_be_bytes());
    out.extend_from_slice(&index.kind.to_be_bytes());
    out.extend_from_slice(&(index.attribute_ids.len() as u32).to_be_bytes());
    for id in &index.attribute_ids {
        out.extend_from_slice(&id.to_be_bytes());
    }

    out.extend_from_slice(&(index.entries.len() as u32).to_be_bytes());
    let mut entry_position = position + index.header_len() + 4 + 8 * index.entries.len();
    for entry in &index.entries {
        out.extend_from_slice(&((table_offset + entry_position) as u32).to_be_bytes());
        entry_position += entry.encoded_len();
    }
    for entry in &index.entries {
        out.extend_from_slice(&entry.record_number.to_be_bytes());
    }
    for entry in &index.entries {
        out.extend_from_slice(&(entry.payload_len() as u32).to_be_bytes());
        for value in &entry.key {
            value.write(out);
        }
    }
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn u32(&mut self) -> Result<u32> {
        let bytes = self
            .data
            .get(self.at..self.at + 4)
            .ok_or_else(|| Error::format("index region ends mid-word"))?;
        self.at += 4;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn value(&mut self) -> Result<Vec<u8>> {
        let len = self.u32()? as usize;
        let bytes = self
            .data
            .get(self.at..self.at + len)
            .ok_or_else(|| Error::format("index value runs past the region"))?
            .to_vec();
        self.at += pad4(4 + len) - 4;
        Ok(bytes)
    }
}

fn pad4(len: usize) -> usize {
    (len + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{AttributeDef, RecordType};

    fn bytes(text: &str) -> IndexValue {
        IndexValue::Bytes(text.as_bytes().to_vec())
    }

    fn sample() -> IndexBlob {
        IndexBlob {
            indexes: vec![
                Index {
                    id: 0,
                    kind: 1,
                    attribute_ids: vec![u32::from_be_bytes(*b"acct"), u32::from_be_bytes(*b"svce")],
                    entries: vec![
                        IndexEntry {
                            record_number: 0,
                            key: vec![bytes("alice"), bytes("myservice")],
                        },
                        IndexEntry {
                            record_number: 1,
                            key: vec![bytes("carol"), bytes("other")],
                        },
                    ],
                },
                Index {
                    id: 3,
                    kind: 0,
                    attribute_ids: vec![u32::from_be_bytes(*b"port")],
                    entries: vec![
                        IndexEntry {
                            record_number: 1,
                            key: vec![IndexValue::Integer(80)],
                        },
                        IndexEntry {
                            record_number: 0,
                            key: vec![IndexValue::Integer(8080)],
                        },
                    ],
                },
            ],
        }
    }

    fn relation() -> Relation {
        Relation {
            record_type: RecordType::GENERIC_PASSWORD,
            name: None,
            attributes: vec![
                AttributeDef {
                    id: u32::from_be_bytes(*b"acct"),
                    name: "acct".into(),
                    format: AttributeFormat::Blob,
                },
                AttributeDef {
                    id: u32::from_be_bytes(*b"svce"),
                    name: "svce".into(),
                    format: AttributeFormat::Blob,
                },
                AttributeDef {
                    id: u32::from_be_bytes(*b"port"),
                    name: "port".into(),
                    format: AttributeFormat::Uint32,
                },
            ],
        }
    }

    #[test]
    fn round_trips_at_any_table_offset() {
        let blob = sample();
        for table_offset in [0, 32, 492, 4096] {
            let encoded = blob.to_bytes(table_offset);
            assert_eq!(encoded.len(), blob.encoded_len());
            assert_eq!(
                IndexBlob::parse(&encoded, table_offset, Some(&relation())).unwrap(),
                blob
            );
        }
    }

    #[test]
    fn offsets_follow_the_regions_position_in_the_table() {
        let blob = sample();
        let low = blob.to_bytes(100);
        let high = blob.to_bytes(200);
        assert_eq!(low.len(), high.len(), "only the offsets differ");
        assert_ne!(low, high, "a moved region must renumber its offsets");
    }

    #[test]
    fn integer_keys_are_stored_raw_and_blob_keys_length_prefixed() {
        let blob = IndexBlob {
            indexes: vec![Index {
                id: 0,
                kind: 1,
                attribute_ids: vec![u32::from_be_bytes(*b"port"), u32::from_be_bytes(*b"acct")],
                entries: vec![IndexEntry {
                    record_number: 7,
                    key: vec![IndexValue::Integer(8080), bytes("bob")],
                }],
            }],
        };
        // 4 raw bytes for the integer, 4 + 4 (padded from 3) for the blob.
        assert_eq!(blob.indexes[0].entries[0].payload_len(), 4 + 8);

        let encoded = blob.to_bytes(0);
        assert_eq!(
            IndexBlob::parse(&encoded, 0, Some(&relation())).unwrap(),
            blob
        );
    }

    #[test]
    fn empty_indexes_have_no_entry_arrays() {
        let blob = IndexBlob {
            indexes: vec![Index {
                id: 0,
                kind: 1,
                attribute_ids: vec![u32::from_be_bytes(*b"acct")],
                entries: Vec::new(),
            }],
        };
        // region header 8 + one offset 4 + index header 20 + entry count 4
        assert_eq!(blob.encoded_len(), 36);
        let encoded = blob.to_bytes(32);
        assert_eq!(
            IndexBlob::parse(&encoded, 32, Some(&relation())).unwrap(),
            blob
        );
    }

    #[test]
    fn insert_keeps_keys_sorted_and_record_numbers_aligned() {
        let mut blob = IndexBlob {
            indexes: vec![Index {
                id: 0,
                kind: 1,
                attribute_ids: vec![u32::from_be_bytes(*b"acct")],
                entries: Vec::new(),
            }],
        };

        for (number, account) in [(0u32, "carol"), (1, "alice"), (2, "bob")] {
            blob.insert_record(number, |_| bytes(account));
        }

        let entries = &blob.indexes[0].entries;
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.key[0].clone())
                .collect::<Vec<_>>(),
            vec![bytes("alice"), bytes("bob"), bytes("carol")]
        );
        // The record numbers travel with their keys, not with insertion order.
        assert_eq!(blob.record_numbers(0).unwrap(), vec![1, 2, 0]);
    }

    #[test]
    fn remove_drops_only_that_records_entries() {
        let mut blob = sample();
        assert_eq!(blob.entry_count(), 4);
        blob.remove_record(0);
        assert_eq!(blob.entry_count(), 2);
        assert!(
            blob.indexes
                .iter()
                .all(|index| index.entries.iter().all(|entry| entry.record_number != 0))
        );
    }

    #[test]
    fn absent_values_index_as_empty_or_zero() {
        assert_eq!(
            IndexValue::from_value(None, AttributeFormat::Blob),
            IndexValue::Bytes(Vec::new())
        );
        assert_eq!(
            IndexValue::from_value(None, AttributeFormat::Uint32),
            IndexValue::Integer(0)
        );
        assert_eq!(
            IndexValue::from_value(Some(&Value::Uint32(5)), AttributeFormat::Uint32),
            IndexValue::Integer(5)
        );
        assert_eq!(
            IndexValue::from_value(Some(&Value::Blob(b"x".to_vec())), AttributeFormat::Blob),
            IndexValue::Bytes(b"x".to_vec())
        );
    }

    #[test]
    fn malformed_regions_are_rejected() {
        assert!(IndexBlob::parse(&[], 0, None).is_err());
        let mut encoded = sample().to_bytes(0);
        encoded[3] = 0xff;
        assert!(IndexBlob::parse(&encoded, 0, Some(&relation())).is_err());
    }
}
