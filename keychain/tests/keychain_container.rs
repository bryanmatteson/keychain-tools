//! Container-format tests against keychains written by macOS.
//!
//! The central one is [`reserializing_a_macos_keychain_is_byte_identical`]: if
//! parsing and rewriting a real keychain reproduces it exactly, then every field
//! in the model is accounted for — including the ones whose meaning is unknown,
//! the padding, and the index regions.

mod common;

use common::*;
use keychain::format::TableIndexes;
use keychain::{Keychain, KeychainFile, RecordType};

#[test]
fn reserializing_a_macos_keychain_is_byte_identical() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("roundtrip");

    // An empty keychain, and one with items of both classes.
    let empty = dir.join("empty.keychain");
    create_with_security(&empty, "pw-empty");
    let populated = populated_keychain(&dir, "full.keychain", "pw-full");

    for path in [empty, populated] {
        let bytes = std::fs::read(&path).expect("read keychain");
        let keychain = Keychain::parse(&bytes).expect("parse");
        let rewritten = keychain.to_bytes().expect("serialize");

        assert_eq!(
            rewritten.len(),
            bytes.len(),
            "{} changed length on re-serialization",
            path.display()
        );
        let first_difference = bytes.iter().zip(&rewritten).position(|(a, b)| a != b);
        assert_eq!(
            first_difference,
            None,
            "{} differs at byte {:?}",
            path.display(),
            first_difference
        );
    }
}

#[test]
fn header_and_tables_match_the_specification() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("header");
    let path = dir.join("k.keychain");
    create_with_security(&path, "pw");

    let bytes = std::fs::read(&path).expect("read");
    assert_eq!(&bytes[..4], b"kych");

    let keychain = Keychain::parse(&bytes).expect("parse");
    assert_eq!(keychain.version, keychain::format::VERSION);
    assert_eq!(keychain.header_size, keychain::format::HEADER_SIZE_FIELD);
    assert_eq!(keychain.auth_offset, 0);
    // A fresh keychain is at commit 1.
    assert_eq!(keychain.commit_version, Some(1));

    // The relations macOS creates, including the metadata table that holds the
    // database blob.
    for record_type in [
        RecordType::SCHEMA_INFO,
        RecordType::SCHEMA_INDEXES,
        RecordType::SCHEMA_ATTRIBUTES,
        RecordType::SCHEMA_PARSING_MODULE,
        RecordType::PUBLIC_KEY,
        RecordType::PRIVATE_KEY,
        RecordType::SYMMETRIC_KEY,
        RecordType::GENERIC_PASSWORD,
        RecordType::INTERNET_PASSWORD,
        RecordType::APPLESHARE_PASSWORD,
        RecordType::METADATA,
    ] {
        assert!(
            keychain.table(record_type).is_some(),
            "missing table {}",
            record_type.name()
        );
    }
    assert_eq!(
        keychain.table(RecordType::METADATA).unwrap().record_count(),
        1
    );
    assert_eq!(
        keychain
            .table(RecordType::GENERIC_PASSWORD)
            .unwrap()
            .record_count(),
        0
    );
}

#[test]
fn the_schema_is_read_from_the_file_itself() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("schema");
    let path = dir.join("k.keychain");
    create_with_security(&path, "pw");
    let file = KeychainFile::open(&path).expect("open");
    let schema = file.schema();

    // Attribute order is schema order, not attribute-id order: `cdat` first and
    // `PrintName` eighth. Reading them in id order silently misparses records.
    let generic = schema
        .relation(RecordType::GENERIC_PASSWORD)
        .expect("generic relation");
    let names: Vec<&str> = generic
        .attributes
        .iter()
        .map(|attribute| attribute.name.as_str())
        .collect();
    assert_eq!(
        names,
        vec![
            "cdat",
            "mdat",
            "desc",
            "icmt",
            "crtr",
            "type",
            "scrp",
            "PrintName",
            "Alias",
            "invi",
            "nega",
            "cusi",
            "prot",
            "acct",
            "svce",
            "gena"
        ]
    );

    let internet = schema
        .relation(RecordType::INTERNET_PASSWORD)
        .expect("internet relation");
    assert_eq!(internet.attributes.len(), 20);
    assert_eq!(internet.index_of("srvr"), Some(15));
    assert_eq!(internet.index_of("port"), Some(18));

    // Keys are described too, with string names rather than four-char codes.
    let keys = schema
        .relation(RecordType::SYMMETRIC_KEY)
        .expect("key relation");
    assert_eq!(keys.attributes.len(), 27);
    assert_eq!(keys.index_of("Label"), Some(6));
}

#[test]
fn records_and_attributes_decode_to_what_security_stored() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("records");
    let path = populated_keychain(&dir, "k.keychain", "pw");
    let file = KeychainFile::open(&path).expect("open");

    let generic = file.items_of_type(RecordType::GENERIC_PASSWORD);
    assert_eq!(generic.len(), 2);
    let alice = generic
        .iter()
        .find(|item| item.account().as_deref() == Some("alice"))
        .expect("alice is present");
    assert_eq!(alice.service().as_deref(), Some("myservice"));
    assert_eq!(alice.label().as_deref(), Some("myservice"));
    assert!(
        alice
            .created()
            .is_some_and(|date| date.len() == 15 && date.ends_with('Z'))
    );
    assert!(
        alice.has_secret(),
        "the record carries an encrypted payload"
    );

    let internet = file.items_of_type(RecordType::INTERNET_PASSWORD);
    assert_eq!(internet.len(), 1);
    assert_eq!(internet[0].server().as_deref(), Some("example.com"));
    assert_eq!(internet[0].port(), Some(8080));
    assert_eq!(internet[0].path().as_deref(), Some("/login"));
}

#[test]
fn every_index_region_in_a_real_keychain_is_understood() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("indexes");
    let path = populated_keychain(&dir, "k.keychain", "pw");
    let bytes = std::fs::read(&path).expect("read");
    let keychain = Keychain::parse(&bytes).expect("parse");

    for table in &keychain.tables {
        assert!(
            matches!(table.indexes, TableIndexes::Parsed(_)),
            "index region of {} was not understood",
            table.record_type.name()
        );
    }
}
