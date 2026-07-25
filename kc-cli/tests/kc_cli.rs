//! End-to-end tests for the `kc` command line.

mod common;

use common::*;

#[test]
fn create_add_and_find_through_the_cli() {
    let dir = TempDir::new("cli-basic");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");

    kc_ok(&["create", as_str], Some("cli-pw"));
    assert!(path.exists());

    kc_ok(
        &[
            "add",
            "generic",
            "-a",
            "alice",
            "-s",
            "github.com",
            "-w",
            "gh-token",
            "-D",
            "token",
            "-j",
            "work",
            as_str,
        ],
        Some("cli-pw"),
    );
    kc_ok(
        &[
            "add",
            "internet",
            "-a",
            "bob",
            "-s",
            "api.example.com",
            "--path",
            "/v1",
            "-P",
            "443",
            "-r",
            "htps",
            "-w",
            "api-secret",
            as_str,
        ],
        Some("cli-pw"),
    );
    kc_ok(
        &[
            "add",
            "appleshare",
            "-a",
            "carol",
            "-v",
            "Shared",
            "--address",
            "afp.example.com",
            "-w",
            "afp-secret",
            as_str,
        ],
        Some("cli-pw"),
    );

    // `-w` prints just the secret, so it pipes.
    let generic = kc_ok(
        &[
            "find",
            "generic",
            "-a",
            "alice",
            "-s",
            "github.com",
            "-w",
            as_str,
        ],
        Some("cli-pw"),
    );
    assert_eq!(generic, "gh-token");
    let internet = kc_ok(
        &[
            "find",
            "internet",
            "-a",
            "bob",
            "-s",
            "api.example.com",
            "-w",
            as_str,
        ],
        Some("cli-pw"),
    );
    assert_eq!(internet, "api-secret");
    let appleshare = kc_ok(
        &[
            "find",
            "appleshare",
            "-a",
            "carol",
            "-v",
            "Shared",
            "-w",
            as_str,
        ],
        Some("cli-pw"),
    );
    assert_eq!(appleshare, "afp-secret");

    // Attributes are listed without the password.
    let listing = kc_ok(&["show", as_str], None);
    assert!(listing.contains("class: generic"));
    assert!(listing.contains("class: internet"));
    assert!(listing.contains("class: appleshare"));
    assert!(listing.contains("github.com"));
    assert!(
        !listing.contains("gh-token"),
        "a show without -d must not print secrets"
    );

    let listing = kc_ok(&["show", "-d", as_str], Some("cli-pw"));
    assert!(listing.contains("gh-token"));
}

#[test]
fn json_output_is_machine_readable() {
    let dir = TempDir::new("cli-json");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");

    kc_ok(&["--json", "create", as_str], Some("pw"));
    kc_ok(
        &[
            "add", "generic", "-a", "u", "-s", "svc", "-w", "s3cr3t", as_str,
        ],
        Some("pw"),
    );

    let info: serde_json::Value =
        serde_json::from_str(&kc_ok(&["--json", "info", as_str], None)).expect("info json");
    assert_eq!(info["ok"], true);
    assert_eq!(info["format_version"], "0x00010000");
    assert_eq!(info["pbkdf2_iterations"], 1000);
    assert!(info["tables"].as_array().expect("tables").len() >= 11);

    let show: serde_json::Value =
        serde_json::from_str(&kc_ok(&["--json", "show", "-d", as_str], Some("pw")))
            .expect("show json");
    assert_eq!(show["items"][0]["account"], "u");
    assert_eq!(show["items"][0]["secret"], "s3cr3t");

    let verify: serde_json::Value =
        serde_json::from_str(&kc_ok(&["--json", "verify", as_str], Some("pw")))
            .expect("verify json");
    assert_eq!(verify["ok"], true);
    assert_eq!(verify["items_readable"], 1);
}

#[test]
fn verify_reports_a_consistent_keychain() {
    let dir = TempDir::new("cli-verify");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");

    kc_ok(&["create", as_str], Some("pw"));
    for account in ["a", "b", "c"] {
        kc_ok(
            &[
                "add", "generic", "-a", account, "-s", "svc", "-w", "x", as_str,
            ],
            Some("pw"),
        );
    }

    let report = kc_ok(&["verify", as_str], Some("pw"));
    assert!(report.contains("database signature   ok"), "{report}");
    assert!(report.contains("3/3 verified"), "{report}");
    assert!(report.contains("items readable       3/3"), "{report}");
    assert!(report.contains("understood"), "{report}");

    let keys = kc_ok(&["ls", as_str], Some("pw"));
    assert_eq!(keys.lines().count(), 4, "a header and one line per key");
    assert!(keys.contains("192 bits"));
}

#[test]
fn the_wrong_password_fails_with_a_distinct_exit_code() {
    let dir = TempDir::new("cli-wrongpw");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");

    kc_ok(&["create", as_str], Some("right"));
    let output = kc(&["show", "-d", as_str], Some("wrong"));
    assert_eq!(output.status.code(), Some(45));
    assert!(String::from_utf8_lossy(&output.stderr).contains("incorrect password"));
}

#[test]
fn a_missing_item_fails_with_a_distinct_exit_code() {
    let dir = TempDir::new("cli-missing");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");

    kc_ok(&["create", as_str], Some("pw"));
    let output = kc(
        &["find", "generic", "-a", "nobody", "-w", as_str],
        Some("pw"),
    );
    assert_eq!(output.status.code(), Some(44));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no item matched"));
}

#[test]
fn an_ambiguous_query_names_the_candidates() {
    let dir = TempDir::new("cli-ambiguous");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");

    kc_ok(&["create", as_str], Some("pw"));
    for account in ["alice", "carol"] {
        kc_ok(
            &[
                "add", "generic", "-a", account, "-s", "shared", "-w", "x", as_str,
            ],
            Some("pw"),
        );
    }

    let output = kc(
        &["find", "generic", "-s", "shared", "-w", as_str],
        Some("pw"),
    );
    assert!(!output.status.success());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("2 items match"), "{message}");
    assert!(
        message.contains("alice") && message.contains("carol"),
        "{message}"
    );
}

#[test]
fn refuses_to_overwrite_an_existing_keychain() {
    let dir = TempDir::new("cli-exists");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");

    kc_ok(&["create", as_str], Some("pw"));
    let output = kc(&["create", as_str], Some("pw"));
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already exists"));
}

#[test]
fn a_secret_can_be_piped_in_rather_than_passed_on_the_command_line() {
    // The password comes from stdin's first line and the secret from the rest,
    // so neither ends up in `argv` where `ps` would show it.
    let dir = TempDir::new("cli-stdin");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");

    kc_ok(&["create", as_str], Some("pw"));
    let output = kc(
        &["add", "generic", "-a", "u", "-s", "svc", as_str],
        Some("pw\npiped"),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let secret = kc_ok(&["find", "generic", "-a", "u", "-w", as_str], Some("pw"));
    assert_eq!(secret, "piped");
}

#[test]
fn a_file_that_is_not_a_keychain_is_rejected() {
    let dir = TempDir::new("cli-notkc");
    let path = dir.join("random.bin");
    std::fs::write(&path, b"this is not a keychain database").expect("write");

    let output = kc(&["info", path.to_str().expect("utf-8 path")], None);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("kych"));
}

#[test]
fn add_identity_needs_a_certificate_and_a_key() {
    let dir = TempDir::new("cli-identity");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");

    kc_ok(&["create", as_str], Some("pw"));
    let output = kc(&["add", "identity", as_str], None);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--cert"), "unexpected error: {stderr}");
}
