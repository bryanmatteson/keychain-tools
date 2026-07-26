//! End-to-end tests for the `kc` command line.

mod common;

use common::*;

#[test]
fn create_add_and_get_through_the_cli() {
    let dir = TempDir::new("cli-basic");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");

    kc_ok(&["create", as_str], Some("cli-pw"));
    assert!(path.exists());

    kc_ok(
        &[
            "add",
            "class=generic",
            "account=alice",
            "service=github.com",
            "kind=token",
            "comment=work",
            "-w",
            "gh-token",
            "--keychain",
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
            "--port",
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

    // A secret projection prints just the selected secret.
    let generic = kc_ok(
        &[
            "get",
            "class:generic",
            "account:alice",
            "service:github.com",
            "-o",
            "secret",
            "--keychain",
            as_str,
        ],
        Some("cli-pw"),
    );
    assert_eq!(generic, "gh-token");
    let internet = kc_ok(
        &[
            "get",
            "class:internet",
            "account:bob",
            "server:api.example.com",
            "-o",
            "secret",
            "--keychain",
            as_str,
        ],
        Some("cli-pw"),
    );
    assert_eq!(internet, "api-secret");
    let appleshare = kc_ok(
        &[
            "get",
            "class:appleshare",
            "account:carol",
            "volume:Shared",
            "-o",
            "secret",
            "--keychain",
            as_str,
        ],
        Some("cli-pw"),
    );
    assert_eq!(appleshare, "afp-secret");

    // Attributes are listed without the password.
    let listing = kc_ok(
        &[
            "get",
            "-o",
            "class,account,service,server",
            "--keychain",
            as_str,
        ],
        None,
    );
    assert!(listing.contains("generic"));
    assert!(listing.contains("internet"));
    assert!(listing.contains("appleshare"));
    assert!(listing.contains("github.com"));
    assert!(
        !listing.contains("gh-token"),
        "a get without a secret projection must not print secrets"
    );

    let listing = kc_ok(
        &["get", "class:generic", "-o", "secret", "--keychain", as_str],
        Some("cli-pw"),
    );
    assert!(listing.contains("gh-token"));
}

#[test]
fn get_filters_items_and_projects_ordered_properties() {
    let dir = TempDir::new("cli-show-properties");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");

    kc_ok(&["create", as_str], Some("pw"));
    kc_ok(
        &[
            "add",
            "generic",
            "-a",
            "machina",
            "-s",
            "vpn",
            "-l",
            "machina-operator-vpn-key",
            "-D",
            "api key",
            "-w",
            "secret",
            as_str,
        ],
        Some("pw"),
    );

    let shown = kc_ok(
        &[
            "get",
            "account:machina",
            "service:vpn",
            "-o",
            "label,kind,account,service",
            "--keychain",
            as_str,
        ],
        None,
    );
    assert_eq!(shown, "machina-operator-vpn-key  api key  machina  vpn");

    let shown: serde_json::Value = serde_json::from_str(&kc_ok(
        &[
            "--json",
            "get",
            "label:machina-operator-vpn-key",
            "--output",
            "kind,service",
            "--keychain",
            as_str,
        ],
        None,
    ))
    .expect("projected show json");
    assert_eq!(shown["items"][0]["kind"], "api key");
    assert_eq!(shown["items"][0]["service"], "vpn");
    assert!(shown["items"][0].get("account").is_none());
}

#[test]
fn filtered_get_reports_when_no_item_matches() {
    let dir = TempDir::new("cli-show-missing");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");

    kc_ok(&["create", as_str], Some("pw"));
    let output = kc(
        &["get", "account:nobody", "-o", "label", "--keychain", as_str],
        None,
    );
    assert_eq!(output.status.code(), Some(44));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no item matched"));
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

    let get: serde_json::Value = serde_json::from_str(&kc_ok(
        &[
            "--json",
            "get",
            "account:u",
            "-o",
            "account,secret",
            "--keychain",
            as_str,
        ],
        Some("pw"),
    ))
    .expect("get json");
    assert_eq!(get["items"][0]["account"], "u");
    assert_eq!(get["items"][0]["secret"], "s3cr3t");

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

    let keys = kc_ok(
        &[
            "get",
            "class:item-key",
            "-o",
            "record,key-bits,item",
            "--keychain",
            as_str,
        ],
        None,
    );
    assert_eq!(keys.lines().count(), 3, "one line per item key");
    assert!(keys.contains("192"));
}

#[test]
fn the_wrong_password_fails_with_a_distinct_exit_code() {
    let dir = TempDir::new("cli-wrongpw");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");

    kc_ok(&["create", as_str], Some("right"));
    kc_ok(
        &[
            "add", "generic", "-a", "alice", "-s", "svc", "-w", "secret", as_str,
        ],
        Some("right"),
    );
    let output = kc(
        &["get", "class:generic", "-o", "secret", "--keychain", as_str],
        Some("wrong"),
    );
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
        &[
            "get",
            "class:generic",
            "account:nobody",
            "-o",
            "secret",
            "--keychain",
            as_str,
        ],
        Some("pw"),
    );
    assert_eq!(output.status.code(), Some(44));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no item matched"));
}

#[test]
fn a_secret_projection_requires_an_unambiguous_query() {
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
        &[
            "get",
            "class:generic",
            "service:shared",
            "-o",
            "secret",
            "--keychain",
            as_str,
        ],
        Some("pw"),
    );
    assert!(!output.status.success());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("2 items match"), "{message}");
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

    let secret = kc_ok(
        &[
            "get",
            "class:generic",
            "account:u",
            "-o",
            "secret",
            "--keychain",
            as_str,
        ],
        Some("pw"),
    );
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

#[test]
fn references_drive_atomic_multi_item_updates_and_detect_staleness() {
    let dir = TempDir::new("cli-refs");
    let path = dir.join("k.keychain");
    let keychain = path.to_str().unwrap();
    kc_ok(&["create", keychain], Some("pw"));
    for account in ["alice", "carol"] {
        kc_ok(
            &[
                "add",
                "class=generic",
                &format!("account={account}"),
                "service=shared",
                "kind=token",
                "-w",
                "secret",
                "--keychain",
                keychain,
            ],
            Some("pw"),
        );
    }

    let references = kc_ok(
        &[
            "get",
            "class:generic",
            "service:shared",
            "-o",
            "@ref",
            "--keychain",
            keychain,
        ],
        None,
    );
    let updated = kc(&["set", "kind=credential", "--for", "-"], Some(&references));
    assert!(
        updated.status.success(),
        "{}",
        String::from_utf8_lossy(&updated.stderr)
    );
    let items = kc_ok(
        &[
            "get",
            "class:generic",
            "kind:credential",
            "-o",
            "account",
            "--keychain",
            keychain,
        ],
        None,
    );
    assert_eq!(items.lines().count(), 2);

    let stale = kc(&["set", "comment=stale", "--for", "-"], Some(&references));
    assert!(!stale.status.success());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("stale item reference"));
    let unchanged = kc_ok(
        &[
            "get",
            "class:generic",
            "-o",
            "comment",
            "--keychain",
            keychain,
        ],
        None,
    );
    assert!(!unchanged.contains("stale"));
}

#[test]
fn superseded_read_commands_are_not_part_of_the_cli() {
    for command in ["show", "find", "ls"] {
        let output = kc(&[command], None);
        assert!(!output.status.success(), "{command} unexpectedly succeeded");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("unrecognized subcommand"),
            "{command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
