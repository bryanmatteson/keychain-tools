//! The mutating commands, checked against macOS.
//!
//! Every test here asks the same question: after `kc` changes a keychain, does
//! Apple's `security` still accept the file and see the change? The library's own
//! invariants are covered in `keychain/tests/keychain_edit.rs`.
//!
//! One trap shapes these tests: `securityd` caches a keychain it has opened, and
//! `kc` replaces the file by rename, so the daemon keeps reading the old inode.
//! Each test therefore mutates *before* letting `security` touch the file, or
//! re-unlocks afterwards — which is exactly the advice the README gives.

mod common;

use common::*;
use keychain::{ApplicationAccess, KeychainFile, Query};

/// A keychain with two generic items and one internet item, all written by kc.
fn kc_keychain(dir: &TempDir, name: &str) -> String {
    let path = dir.join(name);
    let as_str = path.to_str().expect("utf-8 path").to_string();
    kc_ok(&["create", &as_str], Some("pw"));
    kc_ok(
        &[
            "add", "generic", "-a", "alice", "-s", "svc", "-D", "token", "-w", "first", &as_str,
        ],
        Some("pw"),
    );
    kc_ok(
        &[
            "add", "generic", "-a", "carol", "-s", "other", "-w", "second", &as_str,
        ],
        Some("pw"),
    );
    kc_ok(
        &[
            "add",
            "internet",
            "-a",
            "bob",
            "-s",
            "example.com",
            "-r",
            "htps",
            "-P",
            "443",
            "--path",
            "/v1",
            "-w",
            "third",
            &as_str,
        ],
        Some("pw"),
    );
    as_str
}

#[test]
fn security_reads_an_item_kc_updated() {
    if !security_available() {
        eprintln!("skipping: /usr/bin/security is unavailable");
        return;
    }
    let dir = TempDir::new("mutate-update");
    let keychain = kc_keychain(&dir, "k.keychain");

    kc_ok(
        &[
            "set",
            "-a",
            "alice",
            "-w",
            "rotated",
            "--set-comment",
            "changed by kc",
            &keychain,
        ],
        Some("pw"),
    );

    security_ok(&["unlock-keychain", "-p", "pw", &keychain]);
    assert_eq!(
        security_ok(&["find-generic-password", "-a", "alice", "-w", &keychain]),
        "rotated"
    );
    let shown = security_ok(&["find-generic-password", "-a", "alice", &keychain]);
    assert!(
        shown.contains(r#""icmt"<blob>="changed by kc""#),
        "unexpected: {shown}"
    );
    // The item it did not touch is unchanged.
    assert_eq!(
        security_ok(&["find-generic-password", "-a", "carol", "-w", &keychain]),
        "second"
    );
    let _ = security(&["delete-keychain", &keychain]);
}

#[test]
fn security_updates_an_item_that_kc_then_reads() {
    if !security_available() {
        eprintln!("skipping: /usr/bin/security is unavailable");
        return;
    }
    let dir = TempDir::new("mutate-update-back");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");
    create_with_security(&path, "pw");
    add_generic_with_security(&path, "alice", "svc", "first");

    // macOS's own in-place update, read back by kc.
    // No `-A` on an update: that would ask macOS to reset the item's access,
    // which needs an authorization dialog and fails headlessly.
    security_ok(&[
        "add-generic-password",
        "-U",
        "-a",
        "alice",
        "-s",
        "svc",
        "-w",
        "rotated-by-macos",
        "-j",
        "changed by security",
        as_str,
    ]);
    assert_eq!(
        kc_ok(
            &["find", "generic", "-a", "alice", "-w", as_str],
            Some("pw")
        ),
        "rotated-by-macos"
    );
    assert_eq!(
        kc_ok(
            &[
                "find",
                "generic",
                "-a",
                "alice",
                "-j",
                "changed by security",
                "-w",
                as_str
            ],
            Some("pw")
        ),
        "rotated-by-macos",
        "kc finds it by the comment macOS wrote"
    );
    let _ = security(&["delete-keychain", as_str]);
}

#[test]
fn security_keeps_working_on_a_keychain_kc_deleted_from() {
    if !security_available() {
        eprintln!("skipping: /usr/bin/security is unavailable");
        return;
    }
    let dir = TempDir::new("mutate-delete");
    let keychain = kc_keychain(&dir, "k.keychain");

    kc_ok(&["rm", "item", "-a", "carol", &keychain], Some("pw"));

    security_ok(&["unlock-keychain", "-p", "pw", &keychain]);
    // The survivors are readable...
    assert_eq!(
        security_ok(&["find-generic-password", "-a", "alice", "-w", &keychain]),
        "first"
    );
    assert_eq!(
        security_ok(&["find-internet-password", "-a", "bob", "-w", &keychain]),
        "third"
    );
    // ...the deleted one is gone...
    let output = security(&["find-generic-password", "-a", "carol", &keychain]);
    assert!(!output.status.success(), "the deleted item is still there");

    // ...and macOS can still write to the file, including reusing the hole.
    security_ok(&[
        "add-generic-password",
        "-a",
        "dave",
        "-s",
        "svc3",
        "-w",
        "fourth",
        "-A",
        &keychain,
    ]);
    assert_eq!(
        security_ok(&["find-generic-password", "-a", "dave", "-w", &keychain]),
        "fourth"
    );
    // kc still reads everything afterwards, and the file still verifies.
    assert_eq!(
        kc_ok(
            &["find", "generic", "-a", "dave", "-w", &keychain],
            Some("pw")
        ),
        "fourth"
    );
    let report = kc_ok(&["verify", &keychain], Some("pw"));
    assert!(report.contains("database signature   ok"), "{report}");
    assert!(!report.contains("FAILED"), "{report}");
    let _ = security(&["delete-keychain", &keychain]);
}

#[test]
fn kc_deletes_an_item_security_wrote() {
    if !security_available() {
        eprintln!("skipping: /usr/bin/security is unavailable");
        return;
    }
    let dir = TempDir::new("mutate-delete-theirs");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");
    create_with_security(&path, "pw");
    add_generic_with_security(&path, "alice", "svc", "first");
    add_generic_with_security(&path, "carol", "other", "second");

    kc_ok(&["rm", "item", "-a", "alice", as_str], Some("pw"));

    // securityd had this keychain open, so it needs telling to re-read it.
    security_ok(&["unlock-keychain", "-p", "pw", as_str]);
    let output = security(&["find-generic-password", "-a", "alice", as_str]);
    assert!(!output.status.success(), "the deleted item is still there");
    assert_eq!(
        security_ok(&["find-generic-password", "-a", "carol", "-w", as_str]),
        "second"
    );
    let _ = security(&["delete-keychain", as_str]);
}

#[test]
fn security_unlocks_a_keychain_kc_re_keyed() {
    if !security_available() {
        eprintln!("skipping: /usr/bin/security is unavailable");
        return;
    }
    let dir = TempDir::new("mutate-passwd");
    let keychain = kc_keychain(&dir, "k.keychain");

    // Deliberately before `security` ever opens the file: a daemon that already
    // holds it keeps using the old derivation until something re-opens it.
    kc_ok(&["passwd", &keychain], Some("pw\nnewpw\nnewpw"));

    security_ok(&["unlock-keychain", "-p", "newpw", &keychain]);
    assert_eq!(
        security_ok(&["find-generic-password", "-a", "alice", "-w", &keychain]),
        "first"
    );
    assert_eq!(
        security_ok(&["find-internet-password", "-a", "bob", "-w", &keychain]),
        "third"
    );

    // The old password is refused, by both implementations. The keychain has to
    // be locked first: `SecKeychainUnlock` on an already-unlocked keychain
    // returns success without checking the password at all.
    security_ok(&["lock-keychain", &keychain]);
    let output = security(&["unlock-keychain", "-p", "pw", &keychain]);
    assert!(!output.status.success(), "the old password still works");
    let output = kc(
        &["find", "generic", "-a", "alice", "-w", &keychain],
        Some("pw"),
    );
    assert_eq!(output.status.code(), Some(45));
    let _ = security(&["delete-keychain", &keychain]);
}

#[test]
fn kc_re_keys_a_keychain_security_created() {
    if !security_available() {
        eprintln!("skipping: /usr/bin/security is unavailable");
        return;
    }
    let dir = TempDir::new("mutate-passwd-theirs");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");
    create_with_security(&path, "pw");
    add_generic_with_security(&path, "alice", "svc", "first");
    // Drop it from securityd's cache before rewriting it underneath.
    let _ = security(&["lock-keychain", as_str]);

    kc_ok(&["passwd", as_str], Some("pw\nnewpw\nnewpw"));

    security_ok(&["unlock-keychain", "-p", "newpw", as_str]);
    assert_eq!(
        security_ok(&["find-generic-password", "-a", "alice", "-w", as_str]),
        "first"
    );
    let _ = security(&["delete-keychain", as_str]);
}

#[test]
fn settings_agree_with_show_keychain_info() {
    if !security_available() {
        eprintln!("skipping: /usr/bin/security is unavailable");
        return;
    }
    let dir = TempDir::new("mutate-settings");
    let keychain = kc_keychain(&dir, "k.keychain");

    kc_ok(
        &["settings", "-t", "900", "--no-lock-on-sleep", &keychain],
        Some("pw"),
    );
    security_ok(&["unlock-keychain", "-p", "pw", &keychain]);

    // `security show-keychain-info` reports on stderr, not stdout.
    let reported = {
        let output = security(&["show-keychain-info", &keychain]);
        assert!(output.status.success(), "show-keychain-info failed");
        String::from_utf8_lossy(&output.stderr).trim().to_string()
    };
    assert!(
        reported.contains("timeout=900s"),
        "macOS reports {reported:?}"
    );
    assert!(
        !reported.contains("lock-on-sleep"),
        "macOS reports {reported:?}"
    );

    // And the other way: macOS writes the settings, kc reads them back.
    security_ok(&["set-keychain-settings", "-t", "60", "-l", &keychain]);
    let shown = kc_ok(&["settings", &keychain], None);
    let shown: String = shown.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(shown.contains("idle timeout 60s"), "kc reports {shown:?}");
    assert!(shown.contains("lock on sleep true"), "kc reports {shown:?}");
    let _ = security(&["delete-keychain", &keychain]);
}

#[test]
fn an_item_kc_restricted_is_still_readable_by_the_application_it_names() {
    if !security_available() {
        eprintln!("skipping: /usr/bin/security is unavailable");
        return;
    }
    let dir = TempDir::new("mutate-trust");
    let keychain = kc_keychain(&dir, "k.keychain");
    let requirement = dir.join("req.bin");
    std::fs::write(&requirement, designated_requirement("/usr/bin/security")).expect("write");
    let requirement = format!(
        "/usr/bin/security={}",
        requirement.to_str().expect("utf-8 path")
    );

    // Restrict an item that was stored with no restriction at all.
    kc_ok(
        &[
            "trust",
            "-a",
            "alice",
            "--trust-requirement",
            &requirement,
            &keychain,
        ],
        Some("pw"),
    );
    let listed = kc_ok(&["--json", "ls", &keychain], Some("pw"));
    assert!(
        listed.contains("/usr/bin/security"),
        "kc does not see the new ACL: {listed}"
    );

    // `security` is the application the ACL names, so it reads the secret with
    // no prompt — which is what makes this a real check.
    security_ok(&["unlock-keychain", "-p", "pw", &keychain]);
    assert_eq!(
        security_ok(&["find-generic-password", "-a", "alice", "-w", &keychain]),
        "first"
    );

    // And back to any application.
    kc_ok(&["trust", "-a", "alice", "-A", &keychain], Some("pw"));
    let listed = kc_ok(&["--json", "ls", &keychain], Some("pw"));
    assert!(
        !listed.contains("/usr/bin/security"),
        "the restriction survived: {listed}"
    );
    security_ok(&["unlock-keychain", "-p", "pw", &keychain]);
    assert_eq!(
        security_ok(&["find-generic-password", "-a", "alice", "-w", &keychain]),
        "first"
    );
    let _ = security(&["delete-keychain", &keychain]);
}

#[test]
fn trust_prompt_pre_authorizes_no_application() {
    let dir = TempDir::new("mutate-prompt");
    let keychain = kc_keychain(&dir, "k.keychain");

    kc_ok(&["trust", "-a", "alice", "--prompt", &keychain], Some("pw"));

    let file = KeychainFile::open(&keychain).expect("open keychain");
    let item = file
        .find_one(&Query {
            account: Some("alice".into()),
            ..Query::default()
        })
        .expect("find item");
    assert_eq!(
        file.item_application_access(item.record_type, item.number())
            .expect("read ACL"),
        Some(ApplicationAccess::Prompt)
    );
}

#[test]
fn an_item_can_be_copied_into_another_keychain() {
    if !security_available() {
        eprintln!("skipping: /usr/bin/security is unavailable");
        return;
    }
    let dir = TempDir::new("mutate-copy");
    let source = kc_keychain(&dir, "a.keychain");
    let destination = dir.join("b.keychain");
    let destination = destination.to_str().expect("utf-8 path");
    kc_ok(&["create", destination], Some("pw"));

    kc_ok(&["cp", "-a", "bob", &source, destination], Some("pw"));

    // Every attribute that identifies the item came across, and macOS finds it
    // by them.
    security_ok(&["unlock-keychain", "-p", "pw", destination]);
    assert_eq!(
        security_ok(&[
            "find-internet-password",
            "-a",
            "bob",
            "-s",
            "example.com",
            "-P",
            "443",
            "-p",
            "/v1",
            "-w",
            destination,
        ]),
        "third"
    );
    // The source still has it.
    assert_eq!(
        kc_ok(
            &["find", "internet", "-a", "bob", "-w", &source],
            Some("pw")
        ),
        "third"
    );
    let _ = security(&["delete-keychain", destination]);
    let _ = security(&["delete-keychain", &source]);
}

#[test]
fn an_identity_survives_a_round_trip_through_export_and_import() {
    if !security_available() {
        eprintln!("skipping: /usr/bin/security is unavailable");
        return;
    }
    let dir = TempDir::new("mutate-export");
    let (certificate, key) = generate_identity(&dir, "id", "kc export test");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");
    kc_ok(&["create", as_str], Some("pw"));
    kc_ok(
        &[
            "add",
            "identity",
            "--cert",
            certificate.to_str().expect("utf-8 path"),
            "--key",
            key.to_str().expect("utf-8 path"),
            as_str,
        ],
        Some("pw"),
    );

    // What comes out is what went in.
    let exported_cert = kc_ok(&["export", "cert", as_str], Some("pw"));
    let original_cert = std::fs::read(&certificate).expect("read");
    let original_cert = keychain::der::pem_or_der(&original_cert).expect("decode");
    assert_eq!(
        keychain::der::pem_or_der(exported_cert.as_bytes()).expect("decode"),
        original_cert
    );

    let exported_key = kc_ok(&["export", "key", as_str], Some("pw"));
    let original_key = std::fs::read(&key).expect("read");
    let original_key = keychain::der::pem_or_der(&original_key).expect("decode");
    assert_eq!(
        keychain::der::pem_or_der(exported_key.as_bytes()).expect("decode"),
        original_key
    );

    // The exported pair goes back into a second keychain and still works.
    let exported = dir.join("exported.pem");
    kc_ok(
        &[
            "export",
            "identity",
            "-o",
            exported.to_str().expect("utf-8 path"),
            as_str,
        ],
        Some("pw"),
    );
    let second = dir.join("second.keychain");
    let second = second.to_str().expect("utf-8 path");
    kc_ok(&["create", second], Some("pw"));
    kc_ok(
        &[
            "add",
            "identity",
            "--cert",
            exported.to_str().expect("utf-8 path"),
            "--key",
            exported.to_str().expect("utf-8 path"),
            second,
        ],
        Some("pw"),
    );
    security_ok(&["unlock-keychain", "-p", "pw", second]);
    let found = security_ok(&["find-identity", second]);
    assert!(found.contains("1 identities found"), "unexpected: {found}");
    assert!(found.contains("kc export test"), "unexpected: {found}");

    let _ = security(&["delete-keychain", second]);
    let _ = security(&["delete-keychain", as_str]);
}

#[test]
fn deleting_an_identity_removes_both_of_its_records() {
    if !security_available() {
        eprintln!("skipping: /usr/bin/security is unavailable");
        return;
    }
    let dir = TempDir::new("mutate-rm-identity");
    let (certificate, key) = generate_identity(&dir, "id", "kc delete test");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");
    kc_ok(&["create", as_str], Some("pw"));
    kc_ok(
        &[
            "add",
            "identity",
            "--cert",
            certificate.to_str().expect("utf-8 path"),
            "--key",
            key.to_str().expect("utf-8 path"),
            as_str,
        ],
        Some("pw"),
    );
    // A password item as well, to prove the delete is surgical.
    kc_ok(
        &[
            "add", "generic", "-a", "alice", "-s", "svc", "-w", "kept", as_str,
        ],
        Some("pw"),
    );

    let output = kc_ok(
        &["rm", "identity", "-l", "kc delete test", as_str],
        Some("pw"),
    );
    assert!(output.contains("2 record(s)"), "unexpected: {output}");

    let output = kc(&["find", "identity", as_str], None);
    assert_eq!(
        output.status.code(),
        Some(44),
        "the identity is still there"
    );

    security_ok(&["unlock-keychain", "-p", "pw", as_str]);
    let found = security_ok(&["find-identity", as_str]);
    assert!(
        found.contains("0 identities found"),
        "macOS still sees it: {found}"
    );
    let output = security(&["find-certificate", "-c", "kc delete test", as_str]);
    assert!(!output.status.success(), "the certificate is still there");

    // The password item is untouched and the file still verifies.
    assert_eq!(
        security_ok(&["find-generic-password", "-a", "alice", "-w", as_str]),
        "kept"
    );
    let report = kc_ok(&["verify", as_str], Some("pw"));
    assert!(!report.contains("FAILED"), "{report}");
    let _ = security(&["delete-keychain", as_str]);
}

#[test]
fn kc_deletes_exactly_the_bytes_macos_deletes() {
    if !security_available() {
        eprintln!("skipping: /usr/bin/security is unavailable");
        return;
    }
    let dir = TempDir::new("mutate-delete-bytes");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");
    create_with_security(&path, "pw");
    for index in 1..=5 {
        add_generic_with_security(&path, &format!("a{index}"), &format!("s{index}"), "secret");
    }

    // The same starting file, deleted from by each implementation. The result
    // must be byte-identical: the freed slot, the free-list chain threaded
    // through the slot array, the slot-array length, the compacted records, the
    // rebuilt indexes, and the commit version.
    for target in ["a1", "a3", "a5"] {
        let theirs = dir.join(&format!("theirs-{target}.keychain"));
        let ours = dir.join(&format!("ours-{target}.keychain"));
        std::fs::copy(&path, &theirs).expect("copy");
        std::fs::copy(&path, &ours).expect("copy");

        let deleted = security(&[
            "delete-generic-password",
            "-a",
            target,
            theirs.to_str().expect("utf-8 path"),
        ]);
        assert!(deleted.status.success(), "macOS could not delete {target}");
        kc_ok(
            &[
                "rm",
                "item",
                "-a",
                target,
                ours.to_str().expect("utf-8 path"),
            ],
            Some("pw"),
        );

        let theirs = std::fs::read(&theirs).expect("read");
        let ours = std::fs::read(&ours).expect("read");
        assert_eq!(
            ours.len(),
            theirs.len(),
            "deleting {target} produced a different size"
        );
        assert!(
            ours == theirs,
            "deleting {target} differs from macOS at byte {:?}",
            ours.iter().zip(&theirs).position(|(a, b)| a != b)
        );
    }
    let _ = security(&["delete-keychain", as_str]);
}

#[test]
fn a_keychain_macos_deleted_from_still_round_trips_byte_for_byte() {
    if !security_available() {
        eprintln!("skipping: /usr/bin/security is unavailable");
        return;
    }
    let dir = TempDir::new("mutate-holes");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");
    create_with_security(&path, "pw");
    for index in 1..=5 {
        add_generic_with_security(&path, &format!("a{index}"), &format!("s{index}"), "secret");
    }
    // Holes, a shortened slot array, and a reused slot whose record is last in
    // the file — the three ways slot order and file order come apart.
    for target in ["a2", "a4", "a5"] {
        assert!(
            security(&["delete-generic-password", "-a", target, as_str])
                .status
                .success()
        );
    }
    add_generic_with_security(&path, "a6", "s6", "secret");

    let bytes = std::fs::read(&path).expect("read");
    let keychain = keychain::Keychain::parse(&bytes).expect("parse");
    assert_eq!(
        keychain.to_bytes().expect("serialize"),
        bytes,
        "re-serializing a keychain with holes changed it"
    );
    let _ = security(&["delete-keychain", as_str]);
}

#[test]
fn deleting_a_certificate_leaves_the_private_key_the_way_macos_does() {
    if !security_available() {
        eprintln!("skipping: /usr/bin/security is unavailable");
        return;
    }
    let dir = TempDir::new("mutate-rm-cert");
    let (certificate, key) = generate_identity(&dir, "id", "kc cert only");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");
    kc_ok(&["create", as_str], Some("pw"));
    kc_ok(
        &[
            "add",
            "identity",
            "--cert",
            certificate.to_str().expect("utf-8 path"),
            "--key",
            key.to_str().expect("utf-8 path"),
            as_str,
        ],
        Some("pw"),
    );

    let output = kc_ok(&["rm", "cert", "-l", "kc cert only", as_str], Some("pw"));
    assert!(output.contains("1 record(s)"), "unexpected: {output}");

    // The key is still there, orphaned — which is exactly what
    // `security delete-certificate` leaves behind.
    let mut file = keychain::KeychainFile::open(&path).expect("open");
    file.unlock(b"pw").expect("unlock");
    assert_eq!(
        file.records_of_type(keychain::RecordType::PRIVATE_KEY)
            .len(),
        1,
        "the private key should survive"
    );
    assert!(
        file.records_of_type(keychain::RecordType::X509_CERTIFICATE)
            .is_empty(),
        "the certificate should be gone"
    );

    security_ok(&["unlock-keychain", "-p", "pw", as_str]);
    let found = security_ok(&["find-identity", as_str]);
    assert!(
        found.contains("0 identities found"),
        "macOS still pairs them: {found}"
    );
    let _ = security(&["delete-keychain", as_str]);
}

#[test]
fn the_no_timeout_setting_is_the_one_macos_writes() {
    if !security_available() {
        eprintln!("skipping: /usr/bin/security is unavailable");
        return;
    }
    let dir = TempDir::new("mutate-no-timeout");
    let keychain = kc_keychain(&dir, "k.keychain");

    kc_ok(&["settings", "--no-timeout", "-l", &keychain], Some("pw"));
    security_ok(&["unlock-keychain", "-p", "pw", &keychain]);
    let reported = {
        let output = security(&["show-keychain-info", &keychain]);
        String::from_utf8_lossy(&output.stderr).trim().to_string()
    };
    assert!(
        reported.contains("lock-on-sleep no-timeout"),
        "macOS reports {reported:?}"
    );

    // macOS's own "never" is the same value, and kc reads it back as never.
    security_ok(&["set-keychain-settings", &keychain]);
    let shown = kc_ok(&["--json", "settings", &keychain], None);
    let parsed: serde_json::Value = serde_json::from_str(&shown).expect("json");
    assert_eq!(parsed["never_times_out"], true);
    assert_eq!(parsed["idle_timeout"], 2147483647u32);

    // And a timeout macOS refuses is refused here too, without writing.
    let before = std::fs::read(&keychain).expect("read");
    let output = kc(&["settings", "-t", "0", &keychain], Some("pw"));
    assert!(!output.status.success());
    assert_eq!(std::fs::read(&keychain).expect("read"), before);
    let _ = security(&["delete-keychain", &keychain]);
}

#[test]
fn a_number_attribute_set_from_the_command_line_is_a_number_to_macos() {
    if !security_available() {
        eprintln!("skipping: /usr/bin/security is unavailable");
        return;
    }
    let dir = TempDir::new("mutate-formats");
    let keychain = kc_keychain(&dir, "k.keychain");

    kc_ok(
        &["set", "-a", "alice", "--set", "invi=7", &keychain],
        Some("pw"),
    );
    kc_ok(
        &["set", "-a", "alice", "--set", "type=aapl", &keychain],
        Some("pw"),
    );

    security_ok(&["unlock-keychain", "-p", "pw", &keychain]);
    let shown = security_ok(&["find-generic-password", "-a", "alice", &keychain]);
    assert!(
        shown.contains(r#""invi"<sint32>=0x00000007"#),
        "macOS reads: {shown}"
    );
    assert!(
        shown.contains(r#""type"<uint32>="aapl""#),
        "macOS reads: {shown}"
    );

    // A value that does not fit is refused, and nothing is written.
    let before = std::fs::read(&keychain).expect("read");
    let output = kc(
        &[
            "set",
            "-a",
            "alice",
            "--set",
            "invi=not-a-number",
            &keychain,
        ],
        Some("pw"),
    );
    assert!(!output.status.success());
    assert_eq!(std::fs::read(&keychain).expect("read"), before);
    let _ = security(&["delete-keychain", &keychain]);
}
