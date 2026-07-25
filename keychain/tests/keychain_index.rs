//! Index-region tests.
//!
//! Two properties matter, and both are checked against macOS's own output:
//!
//! * Parsing and re-serializing an index region is byte-identical, so the model
//!   accounts for every field, including the table-relative offsets.
//! * Rebuilding a region from the table's records reproduces macOS's entries
//!   *and their order*. Order matters because the Security framework searches
//!   these structures.

mod common;

use common::*;
use keychain::format::TableIndexes;
use keychain::{Keychain, KeychainFile};

/// Where a table's index region sits, which its offsets are measured against.
fn index_offset(table: &keychain::format::Table) -> usize {
    let mut position = keychain::format::TABLE_HEADER_LEN + 4 * table.slots.len();
    for record in table.records() {
        position += serialized_record_len(record);
    }
    position
}

/// Mirrors the record layout in `format.rs`.
fn serialized_record_len(record: &keychain::Record) -> usize {
    use keychain::Value;
    let mut len = keychain::format::RECORD_HEADER_LEN
        + 4 * record.attributes.len()
        + ((record.key_data.len() + 3) & !3);
    for value in record.attributes.iter().flatten() {
        len += match value {
            Value::Sint32(_) | Value::Uint32(_) => 4,
            Value::Date(_) => 16,
            Value::String(bytes) | Value::Blob(bytes) => (4 + bytes.len() + 3) & !3,
        };
    }
    len
}

/// Parsing only yields [`TableIndexes::Parsed`] when re-serializing the region
/// reproduces the original bytes exactly, so this asserts the round trip.
#[test]
fn every_index_region_round_trips_byte_for_byte() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("idx-roundtrip");

    let empty = dir.join("empty.keychain");
    create_with_security(&empty, "pw");
    let populated = populated_keychain(&dir, "full.keychain", "pw");

    let mut checked = 0;
    let mut with_entries = 0;
    for path in [empty, populated] {
        let bytes = std::fs::read(&path).expect("read");
        let keychain = Keychain::parse(&bytes).expect("parse");

        for table in &keychain.tables {
            let TableIndexes::Parsed(blob) = &table.indexes else {
                panic!(
                    "index region of {} did not survive a round trip",
                    table.record_type.name()
                );
            };
            // And the serializer agrees with the length the model computes.
            let offset = index_offset(table);
            assert_eq!(blob.to_bytes(offset).len(), blob.encoded_len());
            if blob.entry_count() > 0 {
                with_entries += 1;
            }
            checked += 1;
        }
    }
    assert!(
        checked >= 20,
        "expected every table of both keychains, got {checked}"
    );
    assert!(
        with_entries >= 3,
        "the populated keychain should have populated indexes"
    );
}

#[test]
fn rebuilding_reproduces_the_entries_and_order_macos_wrote() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("idx-rebuild");
    // Five generic items, so the sort order is actually exercised.
    let path = dir.join("k.keychain");
    create_with_security(&path, "pw");
    for (account, service) in [
        ("u", "delta"),
        ("u", "alpha"),
        ("u", "charlie"),
        ("u", "bravo"),
        ("z", "alpha"),
    ] {
        add_generic_with_security(&path, account, service, &format!("secret-{service}"));
    }
    add_internet_with_security(&path, "bob", "example.com", "inet");

    let bytes = std::fs::read(&path).expect("read");
    let file = KeychainFile::from_bytes(&bytes).expect("open");
    let schema = file.schema().clone();
    let mut keychain = Keychain::parse(&bytes).expect("parse");

    let mut with_entries = 0;
    for table in &mut keychain.tables {
        let Some(relation) = schema.relation(table.record_type) else {
            continue;
        };
        let before = table.indexes.clone();
        table.rebuild_indexes(relation).expect("rebuild");

        if let TableIndexes::Parsed(blob) = &table.indexes
            && blob.entry_count() > 0
        {
            with_entries += 1;
        }
        assert_eq!(
            before,
            table.indexes,
            "rebuilt index region of {} differs from what macOS wrote",
            table.record_type.name()
        );
    }
    assert!(
        with_entries >= 3,
        "the keys, generic and internet tables should have entries"
    );
}

#[test]
fn index_entries_point_at_the_records_they_describe() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("idx-entries");
    let path = dir.join("k.keychain");
    create_with_security(&path, "pw");
    for service in ["charlie", "alpha", "bravo"] {
        add_generic_with_security(&path, "u", service, "s");
    }

    let bytes = std::fs::read(&path).expect("read");
    let keychain = Keychain::parse(&bytes).expect("parse");
    let table = keychain
        .table(keychain::RecordType::GENERIC_PASSWORD)
        .expect("table");
    let TableIndexes::Parsed(blob) = &table.indexes else {
        panic!("index region was not understood");
    };

    // The `svce` index sorts by service, so its record numbers come back in
    // alphabetical order of service rather than insertion order.
    let svce = u32::from_be_bytes(*b"svce");
    let index = blob
        .indexes
        .iter()
        .find(|index| index.attribute_ids == vec![svce])
        .expect("an index on svce");
    let services: Vec<String> = index
        .entries
        .iter()
        .map(|entry| match &entry.key[0] {
            keychain::index::IndexValue::Bytes(bytes) => {
                String::from_utf8_lossy(bytes).into_owned()
            }
            other => panic!("unexpected key {other:?}"),
        })
        .collect();
    assert_eq!(services, vec!["alpha", "bravo", "charlie"]);

    // Every entry's record number is a live record in the table.
    let numbers: Vec<u32> = table.records().map(|record| record.number).collect();
    for entry in &index.entries {
        assert!(
            numbers.contains(&entry.record_number),
            "entry points at a missing record"
        );
    }
}
