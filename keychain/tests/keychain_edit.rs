//! Mutating a keychain that already exists: update, delete, re-key, re-seal.
//!
//! These check the library's own invariants. Whether macOS accepts the result is
//! checked in `kc-cli/tests/kc_mutations.rs`, which drives `security` against the
//! files these operations produce.

mod common;

use common::TempDir;

use keychain::acl::TrustedApplication;
use keychain::crypto::KeyBlob;
use keychain::edit::{ItemChanges, Settings};
use keychain::write::{CreateOptions, NewItem, create, now_timestamp};
use keychain::{KeychainFile, RecordType, Value};

/// A keychain with two generic items, at `path`.
fn populated(path: &std::path::Path, password: &str) -> KeychainFile {
    let mut file = create(password.as_bytes(), &CreateOptions::default()).expect("create");
    for (account, secret) in [("alice", "first"), ("carol", "second")] {
        let item = NewItem {
            account: Some(account.to_string()),
            service: Some("svc".to_string()),
            description: Some("token".to_string()),
            ..NewItem::default()
        };
        file.add_password(
            RecordType::GENERIC_PASSWORD,
            &item,
            secret.as_bytes(),
            &now_timestamp(),
        )
        .expect("add");
    }
    file.save(path).expect("save");
    let mut reopened = KeychainFile::open(path).expect("open");
    reopened.unlock(password.as_bytes()).expect("unlock");
    reopened
}

fn item_number(file: &KeychainFile, account: &str) -> u32 {
    file.items()
        .into_iter()
        .find(|item| item.account().as_deref() == Some(account))
        .expect("the item is there")
        .number()
}

fn secret_of(file: &KeychainFile, account: &str) -> String {
    let item = file
        .items()
        .into_iter()
        .find(|item| item.account().as_deref() == Some(account))
        .expect("the item is there");
    String::from_utf8(file.secret(&item).expect("decrypt").as_slice().to_vec()).expect("utf-8")
}

#[test]
fn an_update_keeps_the_item_and_replaces_only_what_was_asked_for() {
    let dir = TempDir::new("edit-update");
    let path = dir.join("k.keychain");
    let mut file = populated(&path, "pw");

    let number = item_number(&file, "alice");
    let before = file
        .items()
        .into_iter()
        .find(|item| item.number() == number)
        .map(|item| {
            (
                item.text("cdat"),
                item.text("mdat"),
                item.record.key_data.clone(),
            )
        })
        .expect("item");

    let changes = ItemChanges {
        label: Some("renamed".to_string()),
        comment: Some("a note".to_string()),
        ..ItemChanges::default()
    };
    file.update_item(
        RecordType::GENERIC_PASSWORD,
        number,
        &changes,
        Some(b"rotated"),
        "20260101120000Z",
    )
    .expect("update");

    let item = file
        .items()
        .into_iter()
        .find(|item| item.number() == number)
        .expect("still there");
    assert_eq!(item.label().as_deref(), Some("renamed"));
    assert_eq!(item.text("icmt").as_deref(), Some("a note"));
    // Untouched attributes stay as they were.
    assert_eq!(item.account().as_deref(), Some("alice"));
    assert_eq!(item.service().as_deref(), Some("svc"));
    assert_eq!(item.text("desc").as_deref(), Some("token"));
    // `cdat` is when it was created; `mdat` is when it was changed.
    assert_eq!(item.text("cdat"), before.0);
    assert_eq!(item.text("mdat").as_deref(), Some("20260101120000Z"));
    assert_ne!(item.text("mdat"), before.1);

    // The secret is re-sealed under the same item key, with a different IV.
    assert_eq!(secret_of(&file, "alice"), "rotated");
    assert_ne!(item.record.key_data, before.2, "the payload was rewritten");
    assert_eq!(
        item.record.key_data[..20],
        before.2[..20],
        "the ssgp label — and so the item key — is unchanged"
    );

    // The other item is untouched, and the file still round-trips.
    assert_eq!(secret_of(&file, "carol"), "second");
    file.save(&path).expect("save");
    let mut reopened = KeychainFile::open(&path).expect("reopen");
    reopened.unlock(b"pw").expect("unlock");
    assert_eq!(secret_of(&reopened, "alice"), "rotated");
}

#[test]
fn an_update_can_change_attributes_without_the_password() {
    let dir = TempDir::new("edit-locked-update");
    let path = dir.join("k.keychain");
    populated(&path, "pw");

    // Attributes are in the clear: renaming an item needs no key material.
    let mut locked = KeychainFile::open(&path).expect("open");
    assert!(!locked.is_unlocked());
    let number = item_number(&locked, "alice");
    locked
        .update_item(
            RecordType::GENERIC_PASSWORD,
            number,
            &ItemChanges {
                label: Some("renamed while locked".to_string()),
                ..ItemChanges::default()
            },
            None,
            &now_timestamp(),
        )
        .expect("update");
    locked.save(&path).expect("save");

    let reopened = KeychainFile::open(&path).expect("reopen");
    assert!(
        reopened
            .items()
            .iter()
            .any(|item| item.label().as_deref() == Some("renamed while locked"))
    );

    // But a new secret does need it.
    let mut locked = KeychainFile::open(&path).expect("open");
    let error = locked
        .update_item(
            RecordType::GENERIC_PASSWORD,
            number,
            &ItemChanges::default(),
            Some(b"nope"),
            &now_timestamp(),
        )
        .expect_err("a locked keychain cannot re-seal a secret");
    assert!(matches!(error, keychain::Error::Locked), "{error}");
}

#[test]
fn an_update_refuses_to_rewrite_the_attributes_that_identify_the_item() {
    let dir = TempDir::new("edit-identity-attrs");
    let path = dir.join("k.keychain");
    let mut file = populated(&path, "pw");
    let number = item_number(&file, "alice");

    // `acct` is part of the generic relation's unique index: changing it would
    // silently turn this record into a different item, possibly a duplicate of
    // one that already exists.
    let error = file
        .update_item(
            RecordType::GENERIC_PASSWORD,
            number,
            &ItemChanges {
                attributes: vec![("acct".to_string(), Value::Blob(b"mallory".to_vec()))],
                ..ItemChanges::default()
            },
            None,
            &now_timestamp(),
        )
        .expect_err("identity attributes are refused");
    assert!(error.to_string().contains("identifies the item"), "{error}");

    let error = file
        .update_item(
            RecordType::GENERIC_PASSWORD,
            number,
            &ItemChanges {
                attributes: vec![("nonsense".to_string(), Value::Blob(Vec::new()))],
                ..ItemChanges::default()
            },
            None,
            &now_timestamp(),
        )
        .expect_err("unknown attributes are refused");
    assert!(error.to_string().contains("no attribute named"), "{error}");
}

#[test]
fn deleting_an_item_takes_its_key_and_its_index_entries_with_it() {
    let dir = TempDir::new("edit-delete");
    let path = dir.join("k.keychain");
    let mut file = populated(&path, "pw");

    let number = item_number(&file, "alice");
    let keys_before = file.records_of_type(RecordType::SYMMETRIC_KEY).len();
    let removed = file
        .delete_item(RecordType::GENERIC_PASSWORD, number)
        .expect("delete");
    assert_eq!(removed, 2, "the item and its key");

    assert!(
        file.items()
            .iter()
            .all(|item| item.account().as_deref() != Some("alice"))
    );
    assert_eq!(
        file.records_of_type(RecordType::SYMMETRIC_KEY).len(),
        keys_before - 1,
        "the item key is gone too"
    );

    // No index anywhere still points at the deleted record.
    let table = file
        .keychain()
        .table(RecordType::GENERIC_PASSWORD)
        .expect("table");
    let blob = table.indexes.blob().expect("parsed indexes");
    for index in &blob.indexes {
        assert!(
            index
                .entries
                .iter()
                .all(|entry| entry.record_number != number),
            "index {} still refers to the deleted record",
            index.id
        );
    }
    // The slot stays in place and joins the free list: record numbers never
    // shift, and the header points at the highest free slot.
    assert!(
        table.slots[number as usize].record().is_none(),
        "the slot should be free"
    );
    let highest_free = (0..table.slots.len())
        .rev()
        .find(|index| table.slots[*index].record().is_none())
        .expect("a free slot");
    assert_eq!(
        table.free_list_head,
        (28 + 4 * highest_free as u32) | 1,
        "the free-list head points at the highest free slot"
    );

    // The survivor is still readable, and the file round-trips.
    assert_eq!(secret_of(&file, "carol"), "second");
    file.save(&path).expect("save");
    let mut reopened = KeychainFile::open(&path).expect("reopen");
    reopened.unlock(b"pw").expect("unlock");
    assert_eq!(reopened.items().len(), 1);
    assert_eq!(secret_of(&reopened, "carol"), "second");

    // Deleting what is not there says so.
    let error = reopened
        .delete_item(RecordType::GENERIC_PASSWORD, number)
        .expect_err("already gone");
    assert!(matches!(error, keychain::Error::NoSuchItem), "{error}");
}

#[test]
fn a_deleted_item_leaves_no_readable_secret_behind() {
    let dir = TempDir::new("edit-delete-bytes");
    let path = dir.join("k.keychain");
    let mut file = populated(&path, "pw");

    let number = item_number(&file, "alice");
    let ciphertext = file
        .items()
        .into_iter()
        .find(|item| item.number() == number)
        .map(|item| item.record.key_data.clone())
        .expect("item");
    file.delete_item(RecordType::GENERIC_PASSWORD, number)
        .expect("delete");
    file.save(&path).expect("save");

    // The record is not just unlinked: its bytes are not in the file.
    let bytes = std::fs::read(&path).expect("read");
    assert!(
        !bytes
            .windows(ciphertext.len())
            .any(|window| window == ciphertext.as_slice()),
        "the deleted item's encrypted payload is still in the file"
    );
    assert!(
        !bytes.windows(5).any(|window| window == b"alice"),
        "the deleted item's account name is still in the file"
    );
}

#[test]
fn changing_the_password_keeps_every_secret_readable() {
    let dir = TempDir::new("edit-passwd");
    let path = dir.join("k.keychain");
    let mut file = populated(&path, "pw");

    let blob_before = file.db_blob().expect("blob");
    let keys_before = blob_before.unlock(b"pw").expect("unlock");
    let key_records: Vec<Vec<u8>> = file
        .records_of_type(RecordType::SYMMETRIC_KEY)
        .iter()
        .map(|record| record.key_data.clone())
        .collect();

    file.change_password(b"pw", b"different").expect("change");
    file.save(&path).expect("save");

    let blob_after = file.db_blob().expect("blob");
    assert_ne!(blob_after.salt, blob_before.salt, "a fresh salt");
    assert_ne!(blob_after.iv, blob_before.iv, "a fresh IV");

    // The master keys are preserved: every item key in the file is wrapped
    // under them, so new ones would orphan every secret.
    let keys_after = blob_after.unlock(b"different").expect("unlock");
    assert_eq!(
        keys_after.encryption_key.as_slice(),
        keys_before.encryption_key.as_slice()
    );
    assert_eq!(
        keys_after.signing_key.as_slice(),
        keys_before.signing_key.as_slice()
    );
    assert!(
        blob_after.verify(keys_after.signing_key.as_slice()),
        "re-signed"
    );

    // Which means the item key blobs are untouched, byte for byte.
    let key_records_after: Vec<Vec<u8>> = file
        .records_of_type(RecordType::SYMMETRIC_KEY)
        .iter()
        .map(|record| record.key_data.clone())
        .collect();
    assert_eq!(key_records_after, key_records);

    let mut reopened = KeychainFile::open(&path).expect("reopen");
    assert!(
        reopened.unlock(b"pw").is_err(),
        "the old password no longer opens it"
    );
    let mut reopened = KeychainFile::open(&path).expect("reopen");
    reopened.unlock(b"different").expect("new password");
    assert_eq!(secret_of(&reopened, "alice"), "first");
    assert_eq!(secret_of(&reopened, "carol"), "second");
}

#[test]
fn settings_round_trip_through_the_database_blob() {
    let dir = TempDir::new("edit-settings");
    let path = dir.join("k.keychain");
    let mut file = populated(&path, "pw");

    assert_eq!(
        file.settings().expect("settings"),
        Settings {
            idle_timeout: 300,
            lock_on_sleep: true
        }
    );

    file.set_settings(&Settings {
        idle_timeout: 900,
        lock_on_sleep: false,
    })
    .expect("set");
    file.save(&path).expect("save");

    let mut reopened = KeychainFile::open(&path).expect("reopen");
    assert_eq!(
        reopened.settings().expect("settings"),
        Settings {
            idle_timeout: 900,
            lock_on_sleep: false
        }
    );
    // Still signed correctly, and still unlockable.
    reopened.unlock(b"pw").expect("unlock");
    let blob = reopened.db_blob().expect("blob");
    let keys = blob.unlock(b"pw").expect("keys");
    assert!(blob.verify(keys.signing_key.as_slice()));

    // A locked keychain cannot re-sign the blob.
    let mut locked = KeychainFile::open(&path).expect("open");
    let error = locked
        .set_settings(&Settings {
            idle_timeout: 60,
            lock_on_sleep: true,
        })
        .expect_err("needs the signing key");
    assert!(matches!(error, keychain::Error::Locked), "{error}");
}

#[test]
fn item_access_can_be_rewritten_without_touching_the_key() {
    let dir = TempDir::new("edit-trust");
    let path = dir.join("k.keychain");
    let mut file = populated(&path, "pw");
    let number = item_number(&file, "alice");

    let key_blob_before = KeyBlob::parse(
        &file.records_of_type(RecordType::SYMMETRIC_KEY)[0]
            .key_data
            .clone(),
    )
    .expect("parse");

    // A real requirement blob, the one `csreq -b` emits for an identifier.
    let requirement = hex::decode("fade0c000000003000000001000000060000000200000012").expect("hex");
    let application = TrustedApplication::new("/usr/bin/security", requirement);
    file.set_item_trust(
        RecordType::GENERIC_PASSWORD,
        number,
        std::slice::from_ref(&application),
    )
    .expect("trust");

    let record = file
        .records_of_type(RecordType::SYMMETRIC_KEY)
        .into_iter()
        .find(|record| {
            KeyBlob::parse(&record.key_data)
                .map(|blob| blob.public_acl.trusted_paths() == vec!["/usr/bin/security"])
                .unwrap_or(false)
        })
        .expect("the ACL now names the application");

    let key_blob_after = KeyBlob::parse(&record.key_data).expect("parse");
    assert_eq!(
        key_blob_after.crypto_blob, key_blob_before.crypto_blob,
        "the wrapped key itself is untouched"
    );
    assert_eq!(key_blob_after.iv, key_blob_before.iv);

    // The blob is re-signed, so securityd will still accept it, and the secret
    // is still readable here.
    let keys = file.db_blob().expect("blob").unlock(b"pw").expect("keys");
    assert!(key_blob_after.verify(keys.signing_key.as_slice()));
    assert_eq!(secret_of(&file, "alice"), "first");

    // And back to any application.
    file.set_item_trust(RecordType::GENERIC_PASSWORD, number, &[])
        .expect("trust");
    let record = &file.records_of_type(RecordType::SYMMETRIC_KEY)[0];
    let blob = KeyBlob::parse(&record.key_data).expect("parse");
    assert!(blob.public_acl.trusted_paths().is_empty());
}

#[test]
fn an_attribute_is_written_in_the_format_its_relation_declares() {
    let dir = TempDir::new("edit-formats");
    let path = dir.join("k.keychain");
    let mut file = populated(&path, "pw");
    let number = item_number(&file, "alice");

    // Text for a number attribute has to become a number. Storing the bytes
    // instead would not fail loudly: an integer is four raw bytes while a blob
    // is a length followed by data, so "7" would read back as 1 — its length.
    file.update_item(
        RecordType::GENERIC_PASSWORD,
        number,
        &ItemChanges {
            attributes: vec![("invi".to_string(), Value::Blob(b"7".to_vec()))],
            ..ItemChanges::default()
        },
        None,
        &now_timestamp(),
    )
    .expect("update");
    let item = file
        .items()
        .into_iter()
        .find(|item| item.number() == number)
        .expect("item");
    assert_eq!(item.attribute("invi"), Some(&Value::Sint32(7)));

    // An integer attribute that holds a four-character code keeps reading as
    // one.
    file.update_item(
        RecordType::GENERIC_PASSWORD,
        number,
        &ItemChanges {
            attributes: vec![("type".to_string(), Value::Blob(b"aapl".to_vec()))],
            ..ItemChanges::default()
        },
        None,
        &now_timestamp(),
    )
    .expect("update");
    let item = file
        .items()
        .into_iter()
        .find(|item| item.number() == number)
        .expect("item");
    assert_eq!(item.display_attribute("type").as_deref(), Some("aapl"));

    // A date has one stored form.
    file.update_item(
        RecordType::GENERIC_PASSWORD,
        number,
        &ItemChanges {
            attributes: vec![("cdat".to_string(), Value::Blob(b"20200101000000Z".to_vec()))],
            ..ItemChanges::default()
        },
        None,
        &now_timestamp(),
    )
    .expect("update");
    let item = file
        .items()
        .into_iter()
        .find(|item| item.number() == number)
        .expect("item");
    assert_eq!(item.text("cdat").as_deref(), Some("20200101000000Z"));

    // And what cannot be fitted is refused rather than guessed at.
    for (name, value) in [("invi", "not a number"), ("cdat", "yesterday")] {
        let error = file
            .update_item(
                RecordType::GENERIC_PASSWORD,
                number,
                &ItemChanges {
                    attributes: vec![(name.to_string(), Value::Blob(value.as_bytes().to_vec()))],
                    ..ItemChanges::default()
                },
                None,
                &now_timestamp(),
            )
            .expect_err("should be refused");
        assert!(
            error.to_string().contains(name),
            "unexpected error for {name}: {error}"
        );
    }
}
