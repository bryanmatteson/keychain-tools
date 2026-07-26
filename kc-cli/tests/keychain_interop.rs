//! Interoperability with macOS, in both directions.
//!
//! These are the tests that matter most: a keychain this code writes has to be
//! usable by Apple's `security`, and a keychain `security` writes has to remain
//! usable after this code modifies it. Everything is checked through the real
//! tool, so a pass means securityd accepted the file — signatures, ACLs, key
//! headers, indexes and all.

mod common;

use common::*;
use keychain::write::{CreateOptions, NewItem, create, now_timestamp};
use keychain::{KeychainFile, RecordType};

/// Build a keychain with this code, with one item of each class.
fn build_keychain(path: &std::path::Path, password: &str) {
    let mut file = create(password.as_bytes(), &CreateOptions::default()).expect("create");
    let timestamp = now_timestamp();

    file.add_password(
        RecordType::GENERIC_PASSWORD,
        &NewItem {
            account: Some("alice".into()),
            service: Some("myservice".into()),
            description: Some("token".into()),
            comment: Some("a comment".into()),
            ..NewItem::default()
        },
        b"generic-secret",
        &timestamp,
    )
    .expect("add generic");

    file.add_password(
        RecordType::INTERNET_PASSWORD,
        &NewItem {
            account: Some("bob".into()),
            server: Some("example.com".into()),
            path: Some("/login".into()),
            port: Some(8080),
            protocol: Some(*b"http"),
            auth_type: Some(*b"dflt"),
            ..NewItem::default()
        },
        b"internet-secret",
        &timestamp,
    )
    .expect("add internet");

    file.save(path).expect("save");
}

#[test]
fn security_unlocks_and_reads_a_keychain_this_code_wrote() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("interop-write");
    let path = dir.join("mine.keychain");
    build_keychain(&path, "master-pw");
    let as_str = path.to_str().expect("utf-8 path");

    // Unlock: proves the database blob, its signature, and the schema are right.
    security_ok(&["unlock-keychain", "-p", "master-pw", as_str]);

    // Find: proves the records and the index regions are right.
    let listing = security_ok(&["dump-keychain", as_str]);
    assert!(
        listing.contains("genp"),
        "generic item is visible to security"
    );
    assert!(
        listing.contains("inet"),
        "internet item is visible to security"
    );

    // Read: proves the item keys, their ACLs, and the key wrapping are right.
    assert_eq!(
        security_ok(&[
            "find-generic-password",
            "-a",
            "alice",
            "-s",
            "myservice",
            "-w",
            as_str
        ]),
        "generic-secret"
    );
    assert_eq!(
        security_ok(&[
            "find-internet-password",
            "-a",
            "bob",
            "-s",
            "example.com",
            "-w",
            as_str
        ]),
        "internet-secret"
    );
}

#[test]
fn security_can_add_an_item_to_a_keychain_this_code_wrote() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("interop-both");
    let path = dir.join("mine.keychain");
    build_keychain(&path, "master-pw");
    let as_str = path.to_str().expect("utf-8 path");

    security_ok(&["unlock-keychain", "-p", "master-pw", as_str]);
    add_generic_with_security(&path, "fromapple", "applesvc", "written-by-security");

    // Everything is still readable here, including the items written earlier: a
    // stale free-list marker would have let securityd overwrite one of them.
    let mut file = KeychainFile::open(&path).expect("open");
    file.unlock(b"master-pw").expect("unlock");

    let mut found: Vec<(String, String)> = file
        .items()
        .iter()
        .map(|item| {
            let secret = file.secret(item).expect("decrypt");
            (
                item.account().unwrap_or_default(),
                String::from_utf8_lossy(secret.as_slice()).into_owned(),
            )
        })
        .collect();
    found.sort();

    assert_eq!(
        found,
        vec![
            ("alice".to_string(), "generic-secret".to_string()),
            ("bob".to_string(), "internet-secret".to_string()),
            ("fromapple".to_string(), "written-by-security".to_string()),
        ]
    );
}

#[test]
fn security_still_reads_a_keychain_after_this_code_adds_to_it() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("interop-modify");
    let path = populated_keychain(&dir, "theirs.keychain", "pw");
    let as_str = path.to_str().expect("utf-8 path");

    let mut file = KeychainFile::open(&path).expect("open");
    file.unlock(b"pw").expect("unlock");
    file.add_password(
        RecordType::GENERIC_PASSWORD,
        &NewItem {
            account: Some("zoe".into()),
            service: Some("addedsvc".into()),
            ..NewItem::default()
        },
        b"added-by-kc",
        &now_timestamp(),
    )
    .expect("add");
    file.save(&path).expect("save");

    // securityd re-reads the modified file: unlock still works, its own items
    // are intact, and the new one is findable.
    security_ok(&["unlock-keychain", "-p", "pw", as_str]);
    assert_eq!(
        security_ok(&[
            "find-generic-password",
            "-a",
            "alice",
            "-s",
            "myservice",
            "-w",
            as_str
        ]),
        "s3cr3t-generic"
    );
    assert_eq!(
        security_ok(&[
            "find-internet-password",
            "-a",
            "bob",
            "-s",
            "example.com",
            "-w",
            as_str
        ]),
        "s3cr3t-internet"
    );
    assert_eq!(
        security_ok(&[
            "find-generic-password",
            "-a",
            "zoe",
            "-s",
            "addedsvc",
            "-w",
            as_str
        ]),
        "added-by-kc"
    );
}

#[test]
fn many_items_survive_a_round_trip_through_both_implementations() {
    if !security_available() {
        return;
    }
    let dir = TempDir::new("interop-many");
    let path = dir.join("mine.keychain");
    let mut file = create(b"pw", &CreateOptions::default()).expect("create");
    let timestamp = now_timestamp();

    // Enough items, in a deliberately unsorted order, that the index ordering
    // matters.
    let services = ["delta", "alpha", "echo", "bravo", "charlie"];
    for service in services {
        file.add_password(
            RecordType::GENERIC_PASSWORD,
            &NewItem {
                account: Some("u".into()),
                service: Some(service.to_string()),
                ..NewItem::default()
            },
            format!("secret-{service}").as_bytes(),
            &timestamp,
        )
        .expect("add");
    }
    file.save(&path).expect("save");
    let as_str = path.to_str().expect("utf-8 path");

    security_ok(&["unlock-keychain", "-p", "pw", as_str]);
    for service in services {
        assert_eq!(
            security_ok(&[
                "find-generic-password",
                "-a",
                "u",
                "-s",
                service,
                "-w",
                as_str
            ]),
            format!("secret-{service}"),
            "security should find {service}"
        );
    }
}

#[test]
fn a_duplicate_is_refused_by_both_implementations() {
    if !security_available() {
        eprintln!("skipping: /usr/bin/security is unavailable");
        return;
    }
    let dir = TempDir::new("interop-duplicate");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");

    // A generic item's identity is its account and service. A different kind
    // does not make it a different item — checked against macOS rather than
    // assumed, because the rule lives in the relation's unique index.
    create_with_security(&path, "pw");
    security_ok(&[
        "add-generic-password",
        "-a",
        "alice",
        "-s",
        "svc",
        "-D",
        "one",
        "-w",
        "s1",
        "-A",
        as_str,
    ]);

    let output = security(&[
        "add-generic-password",
        "-a",
        "alice",
        "-s",
        "svc",
        "-D",
        "two",
        "-w",
        "s2",
        "-A",
        as_str,
    ]);
    assert!(!output.status.success(), "macOS accepted a duplicate");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("already exists"),
        "unexpected error from security"
    );

    let output = kc(
        &[
            "add", "generic", "-a", "alice", "-s", "svc", "-D", "three", "-w", "s3", as_str,
        ],
        Some("pw"),
    );
    assert!(!output.status.success(), "kc accepted a duplicate");
    assert_eq!(output.status.code(), Some(46));

    // And the other way around: what kc writes, macOS also calls a duplicate.
    let ours = dir.join("ours.keychain");
    let ours_str = ours.to_str().expect("utf-8 path");
    kc_ok(&["create", ours_str], Some("pw"));
    kc_ok(
        &[
            "add", "generic", "-a", "bob", "-s", "svc2", "-w", "s1", ours_str,
        ],
        Some("pw"),
    );
    security_ok(&["unlock-keychain", "-p", "pw", ours_str]);
    let output = security(&[
        "add-generic-password",
        "-a",
        "bob",
        "-s",
        "svc2",
        "-D",
        "other",
        "-w",
        "s2",
        "-A",
        ours_str,
    ]);
    assert!(
        !output.status.success(),
        "macOS did not recognize kc's item as an existing one"
    );
}

#[test]
fn the_generic_attribute_and_security_domain_cross_over() {
    if !security_available() {
        eprintln!("skipping: /usr/bin/security is unavailable");
        return;
    }
    let dir = TempDir::new("interop-attributes");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");
    create_with_security(&path, "pw");

    // Written by macOS, filtered on by kc.
    security_ok(&[
        "add-generic-password",
        "-a",
        "carol",
        "-s",
        "other",
        "-G",
        "sec-tag",
        "-w",
        "from-sec",
        "-A",
        as_str,
    ]);
    security_ok(&[
        "add-internet-password",
        "-a",
        "dave",
        "-s",
        "host.example",
        "-d",
        "sec-realm",
        "-w",
        "from-sec-2",
        "-A",
        as_str,
    ]);
    assert_eq!(
        kc_ok(
            &[
                "get",
                "class:generic",
                "generic:sec-tag",
                "-o",
                "secret",
                "--keychain",
                as_str,
            ],
            Some("pw")
        ),
        "from-sec"
    );
    assert_eq!(
        kc_ok(
            &[
                "get",
                "class:internet",
                "security-domain:sec-realm",
                "-o",
                "secret",
                "--keychain",
                as_str,
            ],
            Some("pw")
        ),
        "from-sec-2"
    );

    // Written by kc, read back by macOS.
    kc_ok(
        &[
            "add", "generic", "-a", "erin", "-s", "kc-svc", "-G", "kc-tag", "-w", "from-kc", as_str,
        ],
        Some("pw"),
    );
    kc_ok(
        &[
            "add",
            "internet",
            "-a",
            "frank",
            "-s",
            "kc.example",
            "-S",
            "kc-realm",
            "-w",
            "from-kc-2",
            as_str,
        ],
        Some("pw"),
    );
    security_ok(&["unlock-keychain", "-p", "pw", as_str]);

    let shown = security_ok(&["find-generic-password", "-a", "erin", as_str]);
    assert!(
        shown.contains(r#""gena"<blob>="kc-tag""#),
        "unexpected: {shown}"
    );
    let shown = security_ok(&["find-internet-password", "-a", "frank", as_str]);
    assert!(
        shown.contains(r#""sdmn"<blob>="kc-realm""#),
        "unexpected: {shown}"
    );

    // And macOS finds them *by* those attributes, which is what having them in
    // the index buys.
    assert_eq!(
        security_ok(&[
            "find-internet-password",
            "-a",
            "frank",
            "-d",
            "kc-realm",
            "-w",
            as_str
        ]),
        "from-kc-2"
    );
}

#[test]
fn an_item_with_no_optional_attributes_is_still_findable() {
    if !security_available() {
        eprintln!("skipping: /usr/bin/security is unavailable");
        return;
    }
    let dir = TempDir::new("interop-sparse");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");
    create_with_security(&path, "pw");

    // No protocol, no port, no path. macOS stores those as 0/0/"" rather than
    // leaving them out, because an attribute a record does not have is not
    // indexed — and an internet item missing from the unique index cannot be
    // found at all. Compared against a macOS-written item below.
    kc_ok(
        &[
            "add",
            "internet",
            "-a",
            "gina",
            "-s",
            "kc2.example",
            "-w",
            "plain",
            as_str,
        ],
        Some("pw"),
    );
    security_ok(&["unlock-keychain", "-p", "pw", as_str]);
    assert_eq!(
        security_ok(&["find-internet-password", "-a", "gina", "-w", as_str]),
        "plain"
    );

    security_ok(&[
        "add-internet-password",
        "-a",
        "hal",
        "-s",
        "mac.example",
        "-w",
        "theirs",
        "-A",
        as_str,
    ]);

    // The two records carry the same set of attributes.
    let file = KeychainFile::open(&path).expect("open");
    let present: Vec<Vec<&str>> = file
        .items_of_type(RecordType::INTERNET_PASSWORD)
        .iter()
        .map(|item| {
            let mut names: Vec<&str> = item
                .attributes()
                .into_iter()
                .map(|(name, _)| name)
                .collect();
            names.sort_unstable();
            names
        })
        .collect();
    assert_eq!(present.len(), 2);
    assert_eq!(present[0], present[1], "attribute sets differ");
}
