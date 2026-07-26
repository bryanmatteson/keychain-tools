//! Item ACLs, against the ones macOS writes.
//!
//! The load-bearing test is
//! [`apple_trusted_application_acls_round_trip_byte_for_byte`]. An earlier
//! version of this code read the last word of a requirement blob as a block
//! separator and emitted an extra one; its own parser accepted that happily, and
//! only re-serializing macOS's bytes exposed it. `securityd` responded to the
//! malformed ACL by crashing rather than denying, which is worth knowing: a
//! plausible-looking ACL is not a safe ACL.

mod common;

use common::*;
use keychain::acl::{AclBlob, Authorization, Subject, TrustedApplication};
use keychain::crypto::KeyBlob;
use keychain::write::{NewItem, now_timestamp};
use keychain::{KeychainFile, RecordType};

/// Every item ACL in a keychain, in record order.
fn item_acls(path: &std::path::Path) -> Vec<Vec<u8>> {
    let file = KeychainFile::open(path).expect("open");
    file.records_of_type(RecordType::SYMMETRIC_KEY)
        .iter()
        .map(|record| {
            KeyBlob::parse(&record.key_data)
                .expect("key blob")
                .public_acl
                .to_bytes()
        })
        .collect()
}

#[test]
fn apple_trusted_application_acls_round_trip_byte_for_byte() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("acl-roundtrip");
    let path = dir.join("k.keychain");
    create_with_security(&path, "pw");

    // One, two and three trusted applications, so the per-application block and
    // the boundary between blocks are both exercised.
    add_generic_trusting_with_security(&path, "u", "one", "s", &["/usr/bin/security"]);
    add_generic_trusting_with_security(&path, "u", "two", "s", &["/usr/bin/security", "/bin/ls"]);
    add_generic_trusting_with_security(
        &path,
        "u",
        "three",
        "s",
        &["/usr/bin/security", "/bin/ls", "/bin/cat"],
    );

    let acls = item_acls(&path);
    assert_eq!(acls.len(), 3);
    for (index, bytes) in acls.iter().enumerate() {
        let parsed = AclBlob::parse(bytes)
            .unwrap_or_else(|error| panic!("ACL {index} did not parse: {error}"));
        assert_eq!(
            &parsed.to_bytes(),
            bytes,
            "ACL {index} did not re-serialize to the bytes macOS wrote"
        );
        assert_eq!(parsed.trusted_paths().len(), index + 1);
    }
}

#[test]
fn apple_prompt_every_application_acl_round_trips_byte_for_byte() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("acl-prompt");
    let path = dir.join("k.keychain");
    create_with_security(&path, "pw");
    security_ok(&[
        "add-generic-password",
        "-a",
        "u",
        "-s",
        "prompt",
        "-w",
        "secret",
        "-T",
        "",
        path.to_str().expect("utf-8 path"),
    ]);

    let bytes = &item_acls(&path)[0];
    let parsed = AclBlob::parse(bytes).unwrap_or_else(|error| {
        panic!(
            "Apple's prompt ACL did not parse: {error}; bytes={}",
            hex::encode(bytes)
        )
    });
    assert_eq!(parsed.to_bytes(), *bytes);
    assert_eq!(
        AclBlob::for_item_prompting("prompt").to_bytes(),
        *bytes,
        "kc's prompt ACL must be byte-identical to security -T \"\""
    );
}

#[test]
fn parsed_trusted_applications_carry_the_path_hash_and_requirement() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("acl-fields");
    let path = dir.join("k.keychain");
    create_with_security(&path, "pw");
    add_generic_trusting_with_security(&path, "u", "svc", "s", &["/usr/bin/security"]);

    let acl = AclBlob::parse(&item_acls(&path)[0]).expect("parse");
    // macOS restricts the item-access entry, not the single-tag one.
    let restricted = acl
        .entries
        .iter()
        .find(|entry| entry.authorization == Some(Authorization::ItemAccess))
        .expect("an item-access entry");
    let Some(Subject::TrustedApplications(applications)) = &restricted.subject else {
        panic!("the item-access entry should name trusted applications");
    };

    assert_eq!(applications.len(), 1);
    assert_eq!(applications[0].path, "/usr/bin/security");
    // macOS fills in the legacy hash; the requirement is the binary's own.
    assert_ne!(applications[0].legacy_hash, [0u8; 20]);
    assert_eq!(
        applications[0].requirement,
        designated_requirement("/usr/bin/security")
    );

    // The other entries stay open, as macOS leaves them.
    let others: Vec<_> = acl
        .entries
        .iter()
        .filter(|entry| entry.authorization != Some(Authorization::ItemAccess))
        .collect();
    assert!(
        others
            .iter()
            .all(|entry| entry.subject == Some(Subject::Any))
    );
}

#[test]
fn security_reads_an_item_whose_restricted_acl_this_code_wrote() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("acl-author");
    let path = dir.join("mine.keychain");

    let mut file = keychain::create(b"pw", &Default::default()).expect("create");
    let item = NewItem {
        account: Some("u".into()),
        service: Some("restricted".into()),
        // `security` is the tool that will read it, so trust exactly that.
        trusted_applications: vec![TrustedApplication::new(
            "/usr/bin/security",
            designated_requirement("/usr/bin/security"),
        )],
        ..NewItem::default()
    };
    file.add_password(
        RecordType::GENERIC_PASSWORD,
        &item,
        b"restricted-secret",
        &now_timestamp(),
    )
    .expect("add");
    file.save(&path).expect("save");

    let as_str = path.to_str().expect("utf-8 path");
    security_ok(&["unlock-keychain", "-p", "pw", as_str]);
    assert_eq!(
        security_ok(&[
            "find-generic-password",
            "-a",
            "u",
            "-s",
            "restricted",
            "-w",
            as_str
        ]),
        "restricted-secret",
        "securityd should honour an ACL written here"
    );
}

/// Two applications is the case that exposed the element-count word: an entry
/// stores one more than the number of subject elements, so a two-application
/// subject stores 3 where a one-application subject stores 2.
#[test]
fn security_reads_an_item_restricted_to_two_applications() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("acl-two");
    let path = dir.join("mine.keychain");

    let mut file = keychain::create(b"pw", &Default::default()).expect("create");
    let item = NewItem {
        account: Some("u".into()),
        service: Some("two".into()),
        trusted_applications: vec![
            TrustedApplication::new(
                "/usr/bin/security",
                designated_requirement("/usr/bin/security"),
            ),
            TrustedApplication::new("/bin/ls", designated_requirement("/bin/ls")),
        ],
        ..NewItem::default()
    };
    file.add_password(
        RecordType::GENERIC_PASSWORD,
        &item,
        b"two-app-secret",
        &now_timestamp(),
    )
    .expect("add");
    file.save(&path).expect("save");

    // The ACL parses back with both applications, in order.
    let acl = AclBlob::parse(&item_acls(&path)[0]).expect("parse");
    assert_eq!(acl.trusted_paths(), vec!["/usr/bin/security", "/bin/ls"]);

    let as_str = path.to_str().expect("utf-8 path");
    security_ok(&["unlock-keychain", "-p", "pw", as_str]);
    assert_eq!(
        security_ok(&[
            "find-generic-password",
            "-a",
            "u",
            "-s",
            "two",
            "-w",
            as_str
        ]),
        "two-app-secret"
    );
}

#[test]
fn an_authored_acl_matches_apples_apart_from_the_legacy_hash() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("acl-compare");
    let theirs = dir.join("theirs.keychain");
    create_with_security(&theirs, "pw");
    add_generic_trusting_with_security(&theirs, "u", "same", "x", &["/usr/bin/security"]);

    let generated = AclBlob::for_item_trusting(
        "same",
        vec![TrustedApplication::new(
            "/usr/bin/security",
            designated_requirement("/usr/bin/security"),
        )],
    );
    let apples = AclBlob::parse(&item_acls(&theirs)[0]).expect("parse");

    // Same size, so the structure agrees byte for byte in length.
    assert_eq!(generated.encoded_len(), apples.encoded_len());

    // And the same content once the legacy hash — which cannot be computed here —
    // is set aside, and the two authorization entries are ordered (macOS writes
    // them in either order).
    assert_eq!(normalize(&generated), normalize(&apples));
}

/// An ACL with legacy hashes cleared and authorization entries sorted, for
/// comparing two ACLs that describe the same policy.
fn normalize(blob: &AclBlob) -> AclBlob {
    let mut blob = blob.clone();
    for entry in std::iter::once(&mut blob.owner).chain(blob.entries.iter_mut()) {
        if let Some(Subject::TrustedApplications(applications)) = &mut entry.subject {
            for application in applications {
                application.legacy_hash = [0u8; 20];
            }
        }
    }
    blob.entries.sort_by_key(|entry| {
        entry
            .authorization
            .as_ref()
            .map(|authorization| authorization.tags().to_vec())
    });
    blob
}
