//! Crypto tests against keychains written by macOS: unlocking, blob signatures,
//! key unwrapping, and item secrets.
//!
//! The secrets are compared with what `security find-…-password -w` reports for
//! the same item, so a passing run means this implementation and macOS agree on
//! the whole chain from password to plaintext.

mod common;

use common::*;
use keychain::acl::{AclBlob, AclEntry};
use keychain::crypto::{self, KeyBlob};
use keychain::{Error, KeychainFile, RecordType};

#[test]
fn unlocking_recovers_the_same_secrets_security_reports() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("secrets");
    let path = populated_keychain(&dir, "k.keychain", "master-pw");
    let as_str = path.to_str().expect("utf-8 path");

    let mut file = KeychainFile::open(&path).expect("open");
    file.unlock(b"master-pw").expect("unlock");
    assert!(file.is_unlocked());
    assert_eq!(file.item_key_count(), 3, "one wrapped key per item");

    for (account, service) in [("alice", "myservice"), ("carol", "other")] {
        let expected = security_ok(&[
            "find-generic-password",
            "-a",
            account,
            "-s",
            service,
            "-w",
            as_str,
        ]);
        let item = file
            .items_of_type(RecordType::GENERIC_PASSWORD)
            .into_iter()
            .find(|item| item.account().as_deref() == Some(account))
            .expect("item is present");
        let secret = file.secret(&item).expect("decrypt");
        assert_eq!(String::from_utf8_lossy(secret.as_slice()), expected);
    }

    let expected = security_ok(&[
        "find-internet-password",
        "-a",
        "bob",
        "-s",
        "example.com",
        "-w",
        as_str,
    ]);
    let item = file.items_of_type(RecordType::INTERNET_PASSWORD).remove(0);
    assert_eq!(
        String::from_utf8_lossy(file.secret(&item).expect("decrypt").as_slice()),
        expected
    );
}

#[test]
fn the_wrong_password_is_reported_as_such() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("wrongpw");
    let path = dir.join("k.keychain");
    create_with_security(&path, "correct-pw");

    let mut file = KeychainFile::open(&path).expect("open");
    assert!(matches!(
        file.unlock(b"incorrect-pw"),
        Err(Error::WrongPassword)
    ));
    assert!(!file.is_unlocked());
    // And the right one still works afterwards.
    file.unlock(b"correct-pw").expect("unlock");
}

#[test]
fn secrets_cannot_be_read_from_a_locked_keychain() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("locked");
    let path = populated_keychain(&dir, "k.keychain", "pw");
    let file = KeychainFile::open(&path).expect("open");

    // Attributes are readable without the password; secrets are not.
    let items = file.items();
    assert_eq!(items.len(), 3);
    assert!(matches!(file.secret(&items[0]), Err(Error::Locked)));
}

#[test]
fn every_blob_signature_macos_wrote_verifies() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("signatures");
    let path = populated_keychain(&dir, "k.keychain", "pw");

    let mut file = KeychainFile::open(&path).expect("open");
    let blob = file.db_blob().expect("database blob");
    let keys = blob.unlock(b"pw").expect("unlock");

    // The database blob, and every key blob, are signed with the legacy
    // HMAC-SHA1 variant. Getting that wrong makes macOS refuse to unlock.
    assert!(
        blob.verify(keys.signing_key.as_slice()),
        "database blob signature"
    );

    file.unlock(b"pw").expect("unlock");
    let key_records = file.records_of_type(RecordType::SYMMETRIC_KEY);
    assert_eq!(key_records.len(), 3);
    for record in key_records {
        let key_blob = KeyBlob::parse(&record.key_data).expect("key blob");
        assert!(
            key_blob.verify(keys.signing_key.as_slice()),
            "key blob {} signature",
            record.number
        );
    }
}

#[test]
fn key_blobs_hold_the_header_and_acl_this_build_writes() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("keyblob");
    let path = populated_keychain(&dir, "k.keychain", "pw");
    let file = KeychainFile::open(&path).expect("open");

    for record in file.records_of_type(RecordType::SYMMETRIC_KEY) {
        let blob = KeyBlob::parse(&record.key_data).expect("key blob");

        // The header macOS writes is the one `KeyHeader::item_key` produces.
        assert_eq!(blob.header, keychain::cssm::KeyHeader::item_key());
        assert_eq!(blob.wrapped, keychain::cssm::WrappedKeyFields::item_key());

        // And its ACL parses into the structure this build generates, naming the
        // item the key belongs to. The two authorization entries are compared as
        // a set: macOS writes them in either order.
        let item_name = blob.public_acl.item_name().expect("ACL was understood");
        assert!(!item_name.is_empty());

        let written = AclBlob::parse(&blob.public_acl.to_bytes()).expect("parse ACL");
        let generated = AclBlob::for_item(item_name);
        assert_eq!(
            written.owner, generated.owner,
            "owner entry for {item_name}"
        );
        assert_eq!(
            sorted_authorizations(&written),
            sorted_authorizations(&generated),
            "authorization entries for {item_name}"
        );
    }
}

/// ACL entries, ordered by their authorization tags so two ACLs can be compared
/// regardless of the order macOS happened to write them in.
fn sorted_authorizations(blob: &AclBlob) -> Vec<AclEntry> {
    let mut entries = blob.entries.clone();
    entries.sort_by_key(|entry| {
        entry
            .authorization
            .as_ref()
            .map(|authorization| authorization.tags().to_vec())
    });
    entries
}

#[test]
fn the_key_derivation_parameters_are_the_formats() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("kdf");
    let path = dir.join("k.keychain");
    create_with_security(&path, "pw");

    let file = KeychainFile::open(&path).expect("open");
    let blob = file.db_blob().expect("database blob");
    assert_eq!(blob.version, crypto::BLOB_VERSION);
    assert_eq!(blob.salt.len(), crypto::SALT_LEN);
    assert_eq!(blob.iv.len(), crypto::BLOCK_SIZE);
    assert_ne!(blob.salt, [0u8; crypto::SALT_LEN], "the salt is random");

    let info = file.info().expect("info");
    assert_eq!(info.pbkdf2_iterations, 1000, "fixed by the format");

    // The derived keys are a 24-byte 3DES key and a 20-byte signing key.
    let keys = blob.unlock(b"pw").expect("unlock");
    assert_eq!(keys.encryption_key.as_slice().len(), crypto::KEY_LEN);
    assert_eq!(keys.signing_key.as_slice().len(), 20);
}
