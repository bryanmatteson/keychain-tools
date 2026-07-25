//! The `kych` container: file header, tables, records, attribute values.
//!
//! Layout per the
//! [dtformats specification](https://github.com/libyal/dtformats/blob/main/documentation/MacOS%20keychain%20database%20file%20format.asciidoc),
//! with the details it leaves open (`[yellow-background]*Unknown*` fields,
//! padding, value encodings) pinned down against keychains written by macOS.
//! Everything is big-endian.
//!
//! ```text
//! file header (20 bytes)
//! tables array: size, count, count x offset
//!   table: header (28 bytes), slot array, records, index data
//!     record: header (24 bytes), attribute offsets, key data, attribute values
//! ```
//!
//! The model keeps every field, including the ones whose meaning is unknown and
//! the opaque per-table index data, so that parsing and re-serializing a
//! macOS-written keychain reproduces it byte for byte. That round trip is the
//! test that this understanding of the layout is complete — see
//! `tests/keychain_roundtrip.rs`.

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::index::{IndexBlob, IndexValue};
use crate::schema::{AttributeFormat, RecordType, Relation, Schema};

pub const SIGNATURE: &[u8; 4] = b"kych";

/// Combined major/minor version: major 1, minor 0.
pub const VERSION: u32 = 0x0001_0000;

/// Value of the header's size field, which is 4 less than the header itself.
pub const HEADER_SIZE_FIELD: u32 = 16;

pub const HEADER_LEN: usize = 20;
pub const TABLE_HEADER_LEN: usize = 28;
pub const RECORD_HEADER_LEN: usize = 24;

/// Attribute offsets carry a set low bit; mask it off to get the real offset.
const ATTRIBUTE_OFFSET_FLAG: u32 = 1;

/// A record slot whose low bit is set is not a record offset: it is a link in
/// the table's free list, which macOS uses to allocate record numbers. Reading
/// one as an offset lands in the middle of a record — the login keychain has 231
/// of them in its certificate table alone.
const SLOT_FREE_FLAG: u32 = 1;

/// A parsed keychain database.
#[derive(Debug, Clone)]
pub struct Keychain {
    pub version: u32,
    /// Header size field (`16` in every observed file).
    pub header_size: u32,
    /// Purpose unknown; `0` in every observed file.
    pub auth_offset: u32,
    /// Tables in file order. Order is preserved because the file's table offset
    /// array is written in this order.
    pub tables: Vec<Table>,
    /// A `u32` that follows the tables array, outside its declared size. macOS
    /// writes `1` for a fresh keychain and increments it once per committed
    /// write, so it reads as a commit counter. Preserved, and bumped by
    /// [`Self::bump_commit_version`] when this code modifies the database.
    /// `None` for a file that has no such trailer.
    pub commit_version: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Table {
    pub record_type: RecordType,
    /// Head of the table's free list: a link to the highest free slot, or `0`
    /// when every slot holds a record.
    ///
    /// A link is `(28 + 4 * slot) | 1` — the offset of that slot's entry in the
    /// slot array, with the low bit set to tell it from a record offset. The
    /// slot it points at holds a link to the next free slot down, and the lowest
    /// one holds `0`. That is why a fresh, empty table carries `0x1d`: one slot,
    /// free, at `28 + 0`.
    pub free_list_head: u32,
    /// Record slots in file order. A slot's index is the record number it holds.
    pub slots: Vec<Slot>,
    /// Slot indexes in the order their records are laid out in the file.
    ///
    /// Not the slot order: macOS appends a new record at the end of the records
    /// region even when it reuses a low-numbered slot, so a keychain that has
    /// been deleted from and added to has the two orders diverge. Preserving it
    /// is what keeps a re-serialized file byte-identical to the one read.
    pub(crate) layout: Vec<usize>,
    /// The table's index region.
    pub indexes: TableIndexes,
}

/// One entry of a table's record-slot array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Slot {
    /// A live record.
    Record(Record),
    /// A free-list link, preserved verbatim: its low bit is set, and the rest is
    /// macOS's bookkeeping for reusing this record number.
    Free(u32),
    /// Never used, written as zero.
    Empty,
}

impl Slot {
    pub fn record(&self) -> Option<&Record> {
        match self {
            Self::Record(record) => Some(record),
            _ => None,
        }
    }

    pub fn record_mut(&mut self) -> Option<&mut Record> {
        match self {
            Self::Record(record) => Some(record),
            _ => None,
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }
}

/// A table's index region: understood, or preserved as-is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableIndexes {
    Parsed(IndexBlob),
    /// Kept verbatim because it did not parse. Such a table must not be
    /// modified: its offsets are relative to the table and would go stale.
    Raw(Vec<u8>),
}

impl TableIndexes {
    /// Serialize, with offsets measured from `table_offset` — the position of
    /// the region within its table.
    pub fn to_bytes(&self, table_offset: usize) -> Vec<u8> {
        match self {
            Self::Parsed(blob) => blob.to_bytes(table_offset),
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

    pub fn blob(&self) -> Option<&IndexBlob> {
        match self {
            Self::Parsed(blob) => Some(blob),
            Self::Raw(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Record number, unique within the table.
    pub number: u32,
    /// The database's commit version at the moment the record was written.
    /// macOS stamps both records of an added item with the same value, so the
    /// highest record version in a file equals its
    /// [`Keychain::commit_version`].
    pub version: u32,
    /// Purpose unknown. `0` in every observed record except symmetric-key
    /// records, where macOS writes `4`.
    pub unknown3: u32,
    /// Purpose unknown; `0` in every observed record.
    pub unknown5: u32,
    /// The record's data: an SSGP blob for password items, a key blob for key
    /// records, a `DbBlob` for the metadata record.
    pub key_data: Vec<u8>,
    /// Attribute values, in the relation's schema order. `None` is an absent
    /// value, written as a zero offset.
    pub attributes: Vec<Option<Value>>,
}

/// An attribute value, in the format the schema declares for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Length-prefixed, NUL-terminator optional.
    String(Vec<u8>),
    Sint32(i32),
    Uint32(u32),
    /// Fixed 16 bytes, `YYYYMMDDhhmmssZ` plus a NUL. Not length-prefixed.
    Date(Vec<u8>),
    /// Length-prefixed bytes. Also used for `BIG_NUM`, `MULTI_UINT32`,
    /// `COMPLEX`, and `REAL`, which are not interpreted further.
    Blob(Vec<u8>),
}

impl Value {
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::String(bytes) | Self::Blob(bytes) | Self::Date(bytes) => Some(bytes),
            _ => None,
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Self::Uint32(value) => Some(*value),
            Self::Sint32(value) => Some(*value as u32),
            _ => None,
        }
    }

    /// Printable rendering: text when the bytes are valid UTF-8, else hex.
    pub fn to_display_string(&self) -> String {
        match self {
            Self::Sint32(value) => value.to_string(),
            Self::Uint32(value) => value.to_string(),
            Self::Date(bytes) | Self::String(bytes) | Self::Blob(bytes) => {
                let trimmed = trim_nul(bytes);
                match std::str::from_utf8(trimmed) {
                    Ok(text) if trimmed.iter().all(|b| !b.is_ascii_control()) => text.to_string(),
                    _ => format!("0x{}", hex::encode(trimmed)),
                }
            }
        }
    }

    fn encoded_len(&self) -> usize {
        match self {
            Self::Sint32(_) | Self::Uint32(_) => 4,
            Self::Date(_) => 16,
            Self::String(bytes) | Self::Blob(bytes) => pad4(4 + bytes.len()),
        }
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Self::Sint32(value) => out.extend_from_slice(&value.to_be_bytes()),
            Self::Uint32(value) => out.extend_from_slice(&value.to_be_bytes()),
            Self::Date(bytes) => {
                let mut field = [0u8; 16];
                let take = bytes.len().min(16);
                field[..take].copy_from_slice(&bytes[..take]);
                out.extend_from_slice(&field);
            }
            Self::String(bytes) | Self::Blob(bytes) => {
                out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(bytes);
                out.resize(pad4(out.len()), 0);
            }
        }
    }
}

pub fn trim_nul(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|b| *b == 0) {
        Some(end) => &bytes[..end],
        None => bytes,
    }
}

fn pad4(len: usize) -> usize {
    (len + 3) & !3
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// Bounds-checked big-endian reader over the file image.
struct Cursor<'a> {
    data: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn u32(&self, at: usize) -> Result<u32> {
        let end = at.checked_add(4).ok_or_else(|| Error::truncated(at, 4))?;
        let bytes = self
            .data
            .get(at..end)
            .ok_or_else(|| Error::truncated(at, 4))?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn bytes(&self, at: usize, len: usize) -> Result<&'a [u8]> {
        let end = at
            .checked_add(len)
            .ok_or_else(|| Error::truncated(at, len))?;
        self.data
            .get(at..end)
            .ok_or_else(|| Error::truncated(at, len))
    }
}

impl Keychain {
    /// Parse a keychain image. The schema is read from the file itself.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let cursor = Cursor { data };

        if data.len() < HEADER_LEN {
            return Err(Error::truncated(0, HEADER_LEN));
        }
        if &data[..4] != SIGNATURE {
            return Err(Error::NotAKeychain);
        }

        let version = cursor.u32(4)?;
        let header_size = cursor.u32(8)?;
        let tables_offset = cursor.u32(12)? as usize;
        let auth_offset = cursor.u32(16)?;

        // The declared tables-array size is not trusted for bounds: table
        // offsets are read individually and each table is checked on its own.
        // It does locate the commit-version trailer, which sits just past it.
        let tables_size = cursor.u32(tables_offset)? as usize;
        let commit_version = cursor.u32(tables_offset + tables_size).ok();

        let table_count = cursor.u32(tables_offset + 4)? as usize;
        let mut table_offsets = Vec::with_capacity(table_count);
        for index in 0..table_count {
            table_offsets.push(cursor.u32(tables_offset + 8 + index * 4)? as usize);
        }

        // The schema lives in the file's own tables, so read the schema tables
        // first — with the built-in definitions for those four relations — and
        // only then parse everything with the schema the file declares. Parsing
        // an unknown relation would misplace its key data, so it is not attempted.
        let bootstrap = Schema::bootstrap();
        let mut schema_tables = Vec::new();
        for offset in &table_offsets {
            let at = tables_offset + offset;
            let record_type = RecordType(cursor.u32(at + 4)?);
            if bootstrap.relation(record_type).is_some() {
                schema_tables.push(Table::parse(&cursor, at, &bootstrap)?);
            }
        }
        let schema = Schema::from_tables(&schema_tables)?;

        let mut tables = Vec::with_capacity(table_count);
        for offset in &table_offsets {
            tables.push(Table::parse(&cursor, tables_offset + offset, &schema)?);
        }

        Ok(Self {
            version,
            header_size,
            auth_offset,
            tables,
            commit_version,
        })
    }

    /// The schema this file declares.
    pub fn schema(&self) -> Result<Schema> {
        Schema::from_tables(&self.tables)
    }

    /// Record another committed write, the way macOS does.
    pub fn bump_commit_version(&mut self) {
        self.commit_version = Some(self.commit_version.unwrap_or(0) + 1);
    }

    pub fn table(&self, record_type: RecordType) -> Option<&Table> {
        self.tables
            .iter()
            .find(|table| table.record_type == record_type)
    }

    pub fn table_mut(&mut self, record_type: RecordType) -> Option<&mut Table> {
        self.tables
            .iter_mut()
            .find(|table| table.record_type == record_type)
    }

    /// Serialize back to a file image.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut tables = Vec::with_capacity(self.tables.len());
        for table in &self.tables {
            tables.push(table.to_bytes()?);
        }

        // Tables array: size, count, offsets, then the tables themselves.
        let array_header = 8 + 4 * tables.len();
        let mut offsets = Vec::with_capacity(tables.len());
        let mut running = array_header;
        for table in &tables {
            offsets.push(running as u32);
            running += table.len();
        }

        let mut out = Vec::with_capacity(HEADER_LEN + running);
        out.extend_from_slice(SIGNATURE);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.header_size.to_be_bytes());
        out.extend_from_slice(&(HEADER_LEN as u32).to_be_bytes());
        out.extend_from_slice(&self.auth_offset.to_be_bytes());

        out.extend_from_slice(&(running as u32).to_be_bytes());
        out.extend_from_slice(&(tables.len() as u32).to_be_bytes());
        for offset in offsets {
            out.extend_from_slice(&offset.to_be_bytes());
        }
        for table in tables {
            out.extend_from_slice(&table);
        }
        if let Some(commit_version) = self.commit_version {
            out.extend_from_slice(&commit_version.to_be_bytes());
        }
        Ok(out)
    }
}

impl Table {
    fn parse(cursor: &Cursor<'_>, at: usize, schema: &Schema) -> Result<Self> {
        let _size = cursor.u32(at)?;
        let record_type = RecordType(cursor.u32(at + 4)?);
        let _record_count = cursor.u32(at + 8)?;
        let _records_offset = cursor.u32(at + 12)?;
        let indexes_offset = cursor.u32(at + 16)? as usize;
        let free_list_head = cursor.u32(at + 20)?;
        let slot_count = cursor.u32(at + 24)? as usize;
        if slot_count > 1 << 20 {
            return Err(Error::format(format!(
                "table 0x{:08x} claims {slot_count} record slots",
                record_type.0
            )));
        }

        let mut slots = Vec::with_capacity(slot_count);
        let mut layout: Vec<(usize, usize)> = Vec::new();
        for index in 0..slot_count {
            let offset = cursor.u32(at + TABLE_HEADER_LEN + index * 4)?;
            if offset == 0 {
                slots.push(Slot::Empty);
                continue;
            }
            if offset & SLOT_FREE_FLAG != 0 {
                slots.push(Slot::Free(offset));
                continue;
            }
            layout.push((offset as usize, index));
            let offset = offset as usize;
            if offset < TABLE_HEADER_LEN || offset >= indexes_offset {
                return Err(Error::format(format!(
                    "table 0x{:08x} slot {index} points to {offset}, outside its records",
                    record_type.0
                )));
            }
            slots.push(Slot::Record(Record::parse(
                cursor,
                at + offset,
                record_type,
                schema,
            )?));
        }

        let size = _size as usize;
        if indexes_offset > size {
            return Err(Error::format(format!(
                "table 0x{:08x} index offset {indexes_offset} is past its {size}-byte extent",
                record_type.0
            )));
        }
        let index_data = cursor.bytes(at + indexes_offset, size - indexes_offset)?;

        // Parsing needs the relation, for the attribute formats the index keys
        // are encoded in. A region that does not parse is kept verbatim.
        let relation = schema.relation(record_type);
        let indexes = match IndexBlob::parse(index_data, indexes_offset, relation) {
            Ok(blob) if blob.to_bytes(indexes_offset) == index_data => TableIndexes::Parsed(blob),
            _ => TableIndexes::Raw(index_data.to_vec()),
        };

        // Records are laid out in the file in this order, which is not
        // necessarily slot order.
        layout.sort_unstable();

        Ok(Self {
            record_type,
            free_list_head,
            slots,
            layout: layout.into_iter().map(|(_, index)| index).collect(),
            indexes,
        })
    }

    /// The free-list link that points at slot `index`.
    ///
    /// Links are table-relative offsets into the slot array with the low bit
    /// set, which is what distinguishes them from a record offset.
    fn free_link(index: usize) -> u32 {
        (TABLE_HEADER_LEN + 4 * index) as u32 | SLOT_FREE_FLAG
    }

    /// Rebuild the free list from the slots that are actually free.
    ///
    /// macOS threads the list through the slot array itself: the table header
    /// holds a link to the highest free slot, that slot holds a link to the next
    /// one down, and the lowest holds zero. The chain is a function of which
    /// slots are free, not of the order they were freed in — two keychains that
    /// reached the same state by opposite deletion orders are byte-identical.
    fn rebuild_free_list(&mut self) {
        let mut head = 0u32;
        for index in 0..self.slots.len() {
            if self.slots[index].record().is_some() {
                continue;
            }
            self.slots[index] = if head == 0 {
                Slot::Empty
            } else {
                Slot::Free(head)
            };
            head = Self::free_link(index);
        }
        self.free_list_head = head;
    }

    /// The slot the next insert should take: the head of the free list.
    fn free_head(&self) -> Option<usize> {
        (0..self.slots.len())
            .rev()
            .find(|index| self.slots[*index].record().is_none())
    }

    /// Live records, skipping free and empty slots.
    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.slots.iter().filter_map(Slot::record)
    }

    pub fn records_mut(&mut self) -> impl Iterator<Item = &mut Record> {
        self.slots.iter_mut().filter_map(Slot::record_mut)
    }

    pub fn record_count(&self) -> usize {
        self.records().count()
    }

    /// Lowest unused record number. macOS numbers records from 0 upward.
    pub fn next_record_number(&self) -> u32 {
        self.records()
            .map(|record| record.number)
            .max()
            .map_or(0, |max| max + 1)
    }

    /// Store a record, taking the head of the free list when there is one.
    ///
    /// The record's number is the slot it lands in — that is what a record
    /// number *is* here — so it is assigned rather than taken from the caller,
    /// and returned. The record's bytes go at the end of the records region, the
    /// way macOS appends them, however low the reused slot number is.
    pub fn insert(&mut self, mut record: Record) -> u32 {
        let index = match self.free_head() {
            Some(index) => index,
            None => {
                self.slots.push(Slot::Empty);
                self.slots.len() - 1
            }
        };
        record.number = index as u32;
        self.slots[index] = Slot::Record(record);
        self.layout.push(index);
        self.rebuild_free_list();
        index as u32
    }

    /// Delete a record, freeing its slot the way macOS frees one.
    ///
    /// The slot keeps its place unless it is the last one, in which case the
    /// array loses exactly that entry — trailing free slots below it are left
    /// alone, and the array never shrinks below one slot. Surviving records keep
    /// their numbers: index entries refer to records by number, and macOS never
    /// renumbers.
    ///
    /// Returns whether a record was there to delete.
    pub fn delete(&mut self, number: u32) -> bool {
        let Some(position) = self
            .slots
            .iter()
            .position(|slot| slot.record().is_some_and(|record| record.number == number))
        else {
            return false;
        };

        self.slots[position] = Slot::Empty;
        self.layout.retain(|index| *index != position);
        if position + 1 == self.slots.len() && self.slots.len() > 1 {
            self.slots.pop();
        }
        self.rebuild_free_list();

        if let TableIndexes::Parsed(blob) = &mut self.indexes {
            blob.remove_record(number);
        }
        true
    }

    /// The attributes of the table's unique index, by id.
    ///
    /// `None` when this build could not parse the index region, or the table
    /// declares no unique index.
    pub fn unique_index_attribute_ids(&self) -> Option<&[u32]> {
        self.indexes
            .blob()?
            .indexes
            .iter()
            .find(|index| index.kind == 1)
            .map(|index| index.attribute_ids.as_slice())
    }

    /// True when a record already has the same key as `attributes` under the
    /// table's unique index.
    ///
    /// The unique index is the one the region marks `kind == 1`; the attributes
    /// it names are the relation's notion of identity, which is what macOS
    /// refuses a duplicate of. A table whose index region this build could not
    /// parse answers `false`: it cannot tell, and refusing a write macOS would
    /// accept is worse than allowing it.
    pub fn has_record_with_unique_key(
        &self,
        relation: &Relation,
        attributes: &[Option<Value>],
    ) -> bool {
        let Some(blob) = self.indexes.blob() else {
            return false;
        };
        let Some(unique) = blob.indexes.iter().find(|index| index.kind == 1) else {
            return false;
        };
        // Attributes are stored in relation order, so an attribute id becomes a
        // position in the record.
        let positions: Vec<usize> = unique
            .attribute_ids
            .iter()
            .filter_map(|id| {
                relation
                    .attributes
                    .iter()
                    .position(|attribute| attribute.id == *id)
            })
            .collect();
        if positions.len() != unique.attribute_ids.len() {
            return false;
        }

        let key_of = |values: &[Option<Value>]| -> Vec<Option<Value>> {
            positions
                .iter()
                .map(|position| values.get(*position).cloned().flatten())
                .collect()
        };
        let wanted = key_of(attributes);
        self.records()
            .any(|record| key_of(&record.attributes) == wanted)
    }

    /// Rebuild every index from the table's records.
    ///
    /// Rebuilding rather than patching keeps the indexes consistent with the
    /// records by construction; `tests/keychain_index.rs` checks that a rebuild
    /// reproduces the entries and the ordering macOS wrote.
    pub fn rebuild_indexes(&mut self, relation: &Relation) -> Result<()> {
        let TableIndexes::Parsed(blob) = &mut self.indexes else {
            return Err(Error::format(format!(
                "table 0x{:08x} has an index region this build cannot rewrite",
                self.record_type.0
            )));
        };

        // Attribute id -> (position in the record, format).
        let positions: Vec<(u32, usize, AttributeFormat)> = relation
            .attributes
            .iter()
            .enumerate()
            .map(|(position, attribute)| (attribute.id, position, attribute.format))
            .collect();

        for index in &mut blob.indexes {
            index.entries.clear();
        }
        for record in self.slots.iter().filter_map(Slot::record) {
            let position_of = |attribute_id: u32| -> Option<usize> {
                positions
                    .iter()
                    .find(|(id, _, _)| *id == attribute_id)
                    .map(|(_, position, _)| *position)
            };
            let key = |attribute_id: u32| -> IndexValue {
                match positions.iter().find(|(id, _, _)| *id == attribute_id) {
                    Some((_, position, format)) => {
                        IndexValue::from_value(record.attribute(*position), *format)
                    }
                    None => IndexValue::Bytes(Vec::new()),
                }
            };
            // macOS does not index a record under an attribute it does not
            // have: an absent value is not an empty one.
            blob.insert_record_where(record.number, key, |attribute_ids: &[u32]| -> bool {
                attribute_ids.iter().all(|id| {
                    position_of(*id).is_some_and(|position| record.attribute(position).is_some())
                })
            });
        }
        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let records_offset = TABLE_HEADER_LEN + 4 * self.slots.len();
        let mut slot_offsets = vec![0u32; self.slots.len()];
        for (index, slot) in self.slots.iter().enumerate() {
            if let Slot::Free(link) = slot {
                slot_offsets[index] = *link;
            }
        }

        // Records go out in layout order, each slot's offset recorded as it is
        // placed. A slot missing from the layout — one added without going
        // through `insert` — is appended after the rest.
        let mut order: Vec<usize> = self
            .layout
            .iter()
            .copied()
            .filter(|index| {
                self.slots
                    .get(*index)
                    .is_some_and(|slot| slot.record().is_some())
            })
            .collect();
        for (index, slot) in self.slots.iter().enumerate() {
            if slot.record().is_some() && !order.contains(&index) {
                order.push(index);
            }
        }

        let mut bodies = Vec::with_capacity(order.len());
        let mut running = records_offset;
        for index in &order {
            let Some(Slot::Record(record)) = self.slots.get(*index) else {
                continue;
            };
            let bytes = record.to_bytes()?;
            slot_offsets[*index] = running as u32;
            running += bytes.len();
            bodies.push(bytes);
        }
        let records: Vec<Option<Vec<u8>>> = bodies.into_iter().map(Some).collect();
        let indexes_offset = running;
        let index_data = self.indexes.to_bytes(indexes_offset);
        let size = indexes_offset + index_data.len();

        let mut out = Vec::with_capacity(size);
        out.extend_from_slice(&(size as u32).to_be_bytes());
        out.extend_from_slice(&self.record_type.0.to_be_bytes());
        out.extend_from_slice(&(self.record_count() as u32).to_be_bytes());
        out.extend_from_slice(&(records_offset as u32).to_be_bytes());
        out.extend_from_slice(&(indexes_offset as u32).to_be_bytes());
        out.extend_from_slice(&self.free_list_head.to_be_bytes());
        out.extend_from_slice(&(self.slots.len() as u32).to_be_bytes());
        for offset in slot_offsets {
            out.extend_from_slice(&offset.to_be_bytes());
        }
        for record in records.into_iter().flatten() {
            out.extend_from_slice(&record);
        }
        out.extend_from_slice(&index_data);
        Ok(out)
    }
}

impl Record {
    fn parse(
        cursor: &Cursor<'_>,
        at: usize,
        record_type: RecordType,
        schema: &Schema,
    ) -> Result<Self> {
        let size = cursor.u32(at)? as usize;
        let number = cursor.u32(at + 4)?;
        let version = cursor.u32(at + 8)?;
        let unknown3 = cursor.u32(at + 12)?;
        let key_data_size = cursor.u32(at + 16)? as usize;
        let unknown5 = cursor.u32(at + 20)?;

        let formats = schema.attribute_formats(record_type);
        let mut attributes = Vec::with_capacity(formats.len());
        let mut offsets = Vec::with_capacity(formats.len());
        for index in 0..formats.len() {
            offsets.push(cursor.u32(at + RECORD_HEADER_LEN + index * 4)?);
        }

        let key_data_at = at + RECORD_HEADER_LEN + 4 * formats.len();
        let key_data = cursor.bytes(key_data_at, key_data_size)?.to_vec();

        for (offset, format) in offsets.iter().zip(&formats) {
            if *offset == 0 {
                attributes.push(None);
                continue;
            }
            let value_at = at + (*offset & !ATTRIBUTE_OFFSET_FLAG) as usize;
            if value_at >= at + size {
                return Err(Error::format(format!(
                    "record {number} in table 0x{:08x} points an attribute past its extent",
                    record_type.0
                )));
            }
            attributes.push(Some(read_value(cursor, value_at, *format)?));
        }

        Ok(Self {
            number,
            version,
            unknown3,
            unknown5,
            key_data,
            attributes,
        })
    }

    pub fn attribute(&self, index: usize) -> Option<&Value> {
        self.attributes.get(index).and_then(Option::as_ref)
    }

    /// Set or clear an attribute by its position in the relation.
    ///
    /// Out-of-range positions are ignored rather than panicking: a record built
    /// against a shorter relation is a schema problem, not a caller error.
    pub fn set_attribute(&mut self, index: usize, value: Option<Value>) {
        if let Some(slot) = self.attributes.get_mut(index) {
            *slot = value;
        }
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let count = self.attributes.len();
        let header_and_offsets = RECORD_HEADER_LEN + 4 * count;
        let key_data_len = pad4(self.key_data.len());

        // Values follow the key data, in attribute order, each padded to 4.
        let mut offsets = Vec::with_capacity(count);
        let mut running = header_and_offsets + key_data_len;
        for attribute in &self.attributes {
            match attribute {
                Some(value) => {
                    offsets.push(running as u32 | ATTRIBUTE_OFFSET_FLAG);
                    running += value.encoded_len();
                }
                None => offsets.push(0),
            }
        }
        let size = running;

        let mut out = Vec::with_capacity(size);
        out.extend_from_slice(&(size as u32).to_be_bytes());
        out.extend_from_slice(&self.number.to_be_bytes());
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.unknown3.to_be_bytes());
        out.extend_from_slice(&(self.key_data.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.unknown5.to_be_bytes());
        for offset in offsets {
            out.extend_from_slice(&offset.to_be_bytes());
        }
        out.extend_from_slice(&self.key_data);
        out.resize(header_and_offsets + key_data_len, 0);
        for value in self.attributes.iter().flatten() {
            value.write(&mut out);
        }

        debug_assert_eq!(
            out.len(),
            size,
            "record serialization disagreed with its own layout"
        );
        Ok(out)
    }
}

fn read_value(cursor: &Cursor<'_>, at: usize, format: AttributeFormat) -> Result<Value> {
    Ok(match format {
        AttributeFormat::Sint32 => Value::Sint32(cursor.u32(at)? as i32),
        AttributeFormat::Uint32 => Value::Uint32(cursor.u32(at)?),
        AttributeFormat::TimeDate => Value::Date(cursor.bytes(at, 16)?.to_vec()),
        AttributeFormat::String => {
            let len = cursor.u32(at)? as usize;
            Value::String(cursor.bytes(at + 4, len)?.to_vec())
        }
        // Blob, and the formats this does not interpret.
        _ => {
            let len = cursor.u32(at)? as usize;
            Value::Blob(cursor.bytes(at + 4, len)?.to_vec())
        }
    })
}

/// Group the live records of every table by record type.
pub fn records_by_type(keychain: &Keychain) -> BTreeMap<RecordType, Vec<&Record>> {
    let mut out = BTreeMap::new();
    for table in &keychain.tables {
        out.insert(table.record_type, table.records().collect());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_rounds_up_to_four() {
        assert_eq!(pad4(0), 0);
        assert_eq!(pad4(1), 4);
        assert_eq!(pad4(4), 4);
        assert_eq!(pad4(13), 16);
    }

    #[test]
    fn rejects_files_that_are_not_keychains() {
        assert!(matches!(
            Keychain::parse(b"not a keychain at all!!!"),
            Err(Error::NotAKeychain)
        ));
        assert!(matches!(
            Keychain::parse(b"kych"),
            Err(Error::Truncated { .. })
        ));
    }

    #[test]
    fn value_encoding_lengths_match_the_layout_rules() {
        assert_eq!(Value::Uint32(7).encoded_len(), 4);
        assert_eq!(Value::Date(b"20260725095125Z\0".to_vec()).encoded_len(), 16);
        // 4-byte length prefix, then the bytes padded to a 4-byte boundary.
        assert_eq!(Value::Blob(b"alice".to_vec()).encoded_len(), 12);
        assert_eq!(Value::Blob(b"myservice".to_vec()).encoded_len(), 16);
        assert_eq!(Value::Blob(Vec::new()).encoded_len(), 4);
    }

    #[test]
    fn values_serialize_with_prefix_and_padding() {
        let mut out = Vec::new();
        Value::Blob(b"alice".to_vec()).write(&mut out);
        assert_eq!(out, b"\x00\x00\x00\x05alice\0\0\0");

        let mut out = Vec::new();
        Value::Date(b"20260725095125Z\0".to_vec()).write(&mut out);
        assert_eq!(out.len(), 16);
        assert_eq!(&out, b"20260725095125Z\0");

        // A date shorter than the field is zero-filled, not length-prefixed.
        let mut out = Vec::new();
        Value::Date(b"2026".to_vec()).write(&mut out);
        assert_eq!(out, b"2026\0\0\0\0\0\0\0\0\0\0\0\0");
    }

    #[test]
    fn display_prefers_text_and_falls_back_to_hex() {
        assert_eq!(
            Value::Blob(b"alice\0".to_vec()).to_display_string(),
            "alice"
        );
        assert_eq!(Value::Uint32(8080).to_display_string(), "8080");
        assert_eq!(Value::Blob(vec![0xff, 0xfe]).to_display_string(), "0xfffe");
        assert_eq!(
            Value::Date(b"20260725095125Z\0".to_vec()).to_display_string(),
            "20260725095125Z"
        );
    }

    #[test]
    fn trim_nul_stops_at_the_first_terminator() {
        assert_eq!(trim_nul(b"abc\0def"), b"abc");
        assert_eq!(trim_nul(b"abc"), b"abc");
        assert_eq!(trim_nul(b"\0"), b"");
    }

    #[test]
    fn a_freed_slot_is_the_next_one_allocated() {
        let record = |number| Record {
            number,
            version: 0,
            unknown3: 0,
            unknown5: 0,
            key_data: Vec::new(),
            attributes: vec![None],
        };
        let mut table = Table {
            record_type: RecordType::GENERIC_PASSWORD,
            free_list_head: 0,
            slots: vec![
                Slot::Record(record(0)),
                Slot::Empty,
                Slot::Record(record(2)),
            ],
            layout: vec![0, 2],
            indexes: TableIndexes::Parsed(IndexBlob {
                indexes: Vec::new(),
            }),
        };

        assert_eq!(table.record_count(), 2);

        // The hole is filled, and the record takes that slot's number.
        assert_eq!(table.insert(record(99)), 1);
        assert_eq!(table.slots.len(), 3, "the hole was reused");
        assert_eq!(table.slots[1].record().map(|record| record.number), Some(1));
        assert_eq!(table.free_list_head, 0, "no free slots left");

        // With none left, the array grows.
        assert_eq!(table.insert(record(99)), 3);
        assert_eq!(table.slots.len(), 4);
    }

    #[test]
    fn the_free_list_is_a_chain_through_the_slot_array() {
        let record = |number| Record {
            number,
            version: 0,
            unknown3: 0,
            unknown5: 0,
            key_data: Vec::new(),
            attributes: vec![None],
        };
        let mut table = Table {
            record_type: RecordType::GENERIC_PASSWORD,
            free_list_head: 0,
            slots: (0..4).map(|number| Slot::Record(record(number))).collect(),
            layout: vec![0, 1, 2, 3],
            indexes: TableIndexes::Parsed(IndexBlob {
                indexes: Vec::new(),
            }),
        };

        // Freeing two slots threads a chain: the header points at the highest
        // free slot, that slot points at the next one down, the lowest holds
        // zero. These are the values macOS writes.
        assert!(table.delete(2));
        assert!(table.delete(0));
        assert_eq!(table.free_list_head, (TABLE_HEADER_LEN as u32 + 8) | 1);
        assert_eq!(table.slots[2], Slot::Free(TABLE_HEADER_LEN as u32 | 1));
        assert_eq!(table.slots[0], Slot::Empty);

        // Freeing order does not matter: the chain is a function of which slots
        // are free.
        let mut other = Table {
            record_type: RecordType::GENERIC_PASSWORD,
            free_list_head: 0,
            slots: (0..4).map(|number| Slot::Record(record(number))).collect(),
            layout: vec![0, 1, 2, 3],
            indexes: TableIndexes::Parsed(IndexBlob {
                indexes: Vec::new(),
            }),
        };
        assert!(other.delete(0));
        assert!(other.delete(2));
        assert_eq!(other.slots, table.slots);
        assert_eq!(other.free_list_head, table.free_list_head);

        // Deleting the last slot shortens the array instead, but never past one
        // slot, and never trims the free slots below it.
        assert!(table.delete(3));
        assert_eq!(table.slots.len(), 3);
        assert_eq!(table.record_count(), 1);
        assert!(table.delete(1));
        assert_eq!(table.slots.len(), 3, "slot 1 is not the last one");
        assert_eq!(table.record_count(), 0);
    }

    #[test]
    fn records_keep_their_place_in_the_file_when_a_slot_is_reused() {
        let record = |number, data: &[u8]| Record {
            number,
            version: 0,
            unknown3: 0,
            unknown5: 0,
            key_data: data.to_vec(),
            attributes: vec![None],
        };
        let mut table = Table {
            record_type: RecordType::GENERIC_PASSWORD,
            free_list_head: 0,
            slots: vec![
                Slot::Record(record(0, b"first")),
                Slot::Record(record(1, b"second")),
                Slot::Record(record(2, b"third")),
            ],
            layout: vec![0, 1, 2],
            indexes: TableIndexes::Parsed(IndexBlob {
                indexes: Vec::new(),
            }),
        };

        // Free a middle slot and reuse it: the new record's bytes belong at the
        // END of the records region, not where the old one sat, which is what
        // macOS does and what makes a re-read file byte-identical.
        table.delete(1);
        table.insert(record(0, b"fourth"));
        assert_eq!(table.layout, vec![0, 2, 1]);

        let bytes = table.to_bytes().unwrap();
        let offset = |slot: usize| {
            let at = TABLE_HEADER_LEN + slot * 4;
            u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap())
        };
        assert!(
            offset(1) > offset(2),
            "the reused slot's record is last in the file"
        );
    }
}
