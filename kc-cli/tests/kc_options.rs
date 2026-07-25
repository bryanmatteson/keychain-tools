//! Command-line surface: where the password comes from, how output is
//! formatted, and which attributes `find` can filter on.

mod common;

use common::*;

/// A keychain with one generic and one internet item, both carrying every
/// attribute the CLI can set.
fn populated(dir: &TempDir, password: &str) -> String {
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path").to_string();

    kc_ok(&["create", &as_str], Some(password));
    kc_ok(
        &[
            "add",
            "generic",
            "-a",
            "alice",
            "-s",
            "svc",
            "-G",
            "tag-bytes",
            "-D",
            "app password",
            "-j",
            "made by kc",
            "-l",
            "the label",
            "-w",
            "generic-secret",
            &as_str,
        ],
        Some(password),
    );
    kc_ok(
        &[
            "add",
            "internet",
            "-a",
            "bob",
            "-s",
            "example.com",
            "-S",
            "realm.example",
            "-r",
            "htps",
            "--path",
            "/login",
            "-P",
            "8443",
            "-j",
            "web login",
            "-w",
            "internet-secret",
            &as_str,
        ],
        Some(password),
    );
    as_str
}

#[test]
fn the_password_can_come_from_an_environment_variable() {
    let dir = TempDir::new("options-env");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");

    // Including for `create`, which is where the password is chosen.
    let output = kc_with_env(&["create", "-e", "KC_TEST_PW"], &[("KC_TEST_PW", "envpw")]);
    assert!(
        !output.status.success(),
        "the keychain argument is required"
    );

    let output = kc_with_env(
        &["create", "-e", "KC_TEST_PW", as_str],
        &[("KC_TEST_PW", "envpw")],
    );
    assert!(
        output.status.success(),
        "create failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = kc_with_env(
        &[
            "add",
            "generic",
            "-e",
            "KC_TEST_PW",
            "-a",
            "alice",
            "-s",
            "svc",
            "-w",
            "s3cret",
            as_str,
        ],
        &[("KC_TEST_PW", "envpw")],
    );
    assert!(
        output.status.success(),
        "add failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = kc_with_env(
        &[
            "find",
            "generic",
            "-a",
            "alice",
            "-w",
            "-e",
            "KC_TEST_PW",
            as_str,
        ],
        &[("KC_TEST_PW", "envpw")],
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "s3cret");

    // A trailing newline in the variable is not part of the password.
    let output = kc_with_env(
        &[
            "find",
            "generic",
            "-a",
            "alice",
            "-w",
            "-e",
            "KC_TEST_PW",
            as_str,
        ],
        &[("KC_TEST_PW", "envpw\n")],
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "s3cret");

    // And the wrong password is reported as such, not as a missing item.
    let output = kc_with_env(
        &[
            "find",
            "generic",
            "-a",
            "alice",
            "-w",
            "-e",
            "KC_TEST_PW",
            as_str,
        ],
        &[("KC_TEST_PW", "wrong")],
    );
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(45), "wrong-password exit code");
}

#[test]
fn an_unset_environment_variable_says_so() {
    let dir = TempDir::new("options-env-missing");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");
    kc_ok(&["create", as_str], Some("pw"));

    let output = kc_with_env(&["ls", "-e", "KC_TEST_UNSET_PW", as_str], &[]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("KC_TEST_UNSET_PW is not set"),
        "unexpected error: {stderr}"
    );
}

#[test]
fn the_password_can_come_from_a_file_or_from_stdin() {
    let dir = TempDir::new("options-file");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");
    let password_file = dir.join("pw.txt");
    // Written the way a shell would write it: with a trailing newline.
    std::fs::write(&password_file, "filepw\n").expect("write the password file");
    let password_file = password_file.to_str().expect("utf-8 path");

    kc_ok(&["create", "-f", password_file, as_str], None);
    kc_ok(
        &[
            "add",
            "generic",
            "-f",
            password_file,
            "-a",
            "alice",
            "-s",
            "svc",
            "-w",
            "s3cret",
            as_str,
        ],
        None,
    );
    assert_eq!(
        kc_ok(
            &[
                "find",
                "generic",
                "-a",
                "alice",
                "-w",
                "-f",
                password_file,
                as_str
            ],
            None
        ),
        "s3cret"
    );

    // `-f -` is stdin, which is also what a bare pipe means.
    assert_eq!(
        kc_ok(
            &["find", "generic", "-a", "alice", "-w", "-f", "-", as_str],
            Some("filepw")
        ),
        "s3cret"
    );
    assert_eq!(
        kc_ok(
            &["find", "generic", "-a", "alice", "-w", as_str],
            Some("filepw")
        ),
        "s3cret"
    );

    let output = kc(
        &[
            "find",
            "generic",
            "-a",
            "alice",
            "-w",
            "-f",
            dir.join("absent.txt").to_str().expect("utf-8 path"),
            as_str,
        ],
        None,
    );
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("could not read"),
        "unexpected error"
    );
}

#[test]
fn the_password_sources_are_mutually_exclusive() {
    let dir = TempDir::new("options-exclusive");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");
    kc_ok(&["create", as_str], Some("pw"));

    let output = kc(&["ls", "-e", "KC_TEST_PW", "-f", "/dev/null", as_str], None);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be used with"),
        "unexpected: {stderr}"
    );
}

#[test]
fn there_is_no_way_to_pass_the_password_as_an_argument() {
    let dir = TempDir::new("options-no-argv");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");
    kc_ok(&["create", as_str], Some("pw"));

    // `ps` shows argv to every user on the machine, so the password has no flag
    // of its own — not even one that warns.
    for args in [
        vec!["ls", "-p", "pw", as_str],
        vec!["ls", "--password", "pw", as_str],
        vec!["find", "generic", "-a", "alice", "-p", "pw", as_str],
    ] {
        let output = kc(&args, None);
        assert!(!output.status.success(), "{args:?} was accepted");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("unexpected argument"),
            "unexpected error for {args:?}: {stderr}"
        );
    }
}

#[test]
fn format_secret_prints_the_secret_and_nothing_else() {
    let dir = TempDir::new("options-format");
    let keychain = populated(&dir, "pw");

    // On `find`, the same thing `-w` does.
    let secret = kc_ok(
        &[
            "--format", "secret", "find", "generic", "-a", "alice", &keychain,
        ],
        Some("pw"),
    );
    assert_eq!(secret, "generic-secret");

    // On `show`, one secret per item, which needs no `-d`.
    let secrets = kc_ok(&["--format", "secret", "show", &keychain], Some("pw"));
    let mut lines: Vec<&str> = secrets.lines().collect();
    lines.sort_unstable();
    assert_eq!(lines, ["generic-secret", "internet-secret"]);

    // Commands that read no secrets say so rather than ignoring the flag.
    let output = kc(&["--format", "secret", "info", &keychain], None);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--format secret applies to"),
        "unexpected error"
    );
}

#[test]
fn format_json_is_the_json_flag() {
    let dir = TempDir::new("options-json");
    let keychain = populated(&dir, "pw");

    let with_flag = kc_ok(
        &["--json", "find", "generic", "-a", "alice", &keychain],
        None,
    );
    let with_format = kc_ok(
        &[
            "--format", "json", "find", "generic", "-a", "alice", &keychain,
        ],
        None,
    );
    assert_eq!(with_flag, with_format);

    let parsed: serde_json::Value = serde_json::from_str(&with_format).expect("valid JSON");
    assert_eq!(parsed["item"]["account"], "alice");

    // Asking for both is a mistake worth reporting.
    let output = kc(
        &[
            "--json", "--format", "text", "find", "generic", "-a", "alice", &keychain,
        ],
        None,
    );
    assert!(!output.status.success());
}

#[test]
fn find_filters_on_every_attribute_it_offers() {
    let dir = TempDir::new("options-filters");
    let keychain = populated(&dir, "pw");

    let cases: Vec<Vec<&str>> = vec![
        vec!["find", "generic", "-a", "alice"],
        vec!["find", "generic", "-s", "svc"],
        vec!["find", "generic", "-l", "the label"],
        vec!["find", "generic", "-D", "app password"],
        vec!["find", "generic", "-j", "made by kc"],
        vec!["find", "generic", "-G", "tag-bytes"],
        vec!["find", "generic", "--attr", "acct=alice"],
        vec!["find", "generic", "--attr", "gena=tag-bytes", "-a", "alice"],
    ];
    for case in cases {
        let mut args = case.clone();
        args.extend_from_slice(&["-w", &keychain]);
        assert_eq!(
            kc_ok(&args, Some("pw")),
            "generic-secret",
            "filter {case:?} did not match"
        );
    }

    let internet: Vec<Vec<&str>> = vec![
        vec!["find", "internet", "-S", "realm.example"],
        vec!["find", "internet", "-d", "realm.example"],
        vec!["find", "internet", "-j", "web login"],
        vec!["find", "internet", "--path", "/login"],
        vec!["find", "internet", "-P", "8443"],
        // A four-char code reads as text, so it is matched as text.
        vec!["find", "internet", "--attr", "ptcl=htps"],
        vec!["find", "internet", "--attr", "port=8443"],
    ];
    for case in internet {
        let mut args = case.clone();
        args.extend_from_slice(&["-w", &keychain]);
        assert_eq!(
            kc_ok(&args, Some("pw")),
            "internet-secret",
            "filter {case:?} did not match"
        );
    }

    // A filter that matches nothing is "no item matched", not a false hit.
    let output = kc(
        &["find", "generic", "-j", "not this comment", &keychain],
        Some("pw"),
    );
    assert_eq!(output.status.code(), Some(44));

    let output = kc(&["find", "generic", "--attr", "nonsense", &keychain], None);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("expected NAME=VALUE"),
        "unexpected error"
    );

    // An attribute the relation does not have matches nothing rather than
    // being ignored.
    let output = kc(&["find", "generic", "--attr", "srvr=x", &keychain], None);
    assert_eq!(output.status.code(), Some(44));
}

#[test]
fn the_generic_attribute_and_security_domain_survive_a_round_trip() {
    let dir = TempDir::new("options-attributes");
    let keychain = populated(&dir, "pw");

    let shown = kc_ok(&["show", &keychain], None);
    assert!(
        shown.contains("gena         tag-bytes"),
        "unexpected: {shown}"
    );
    assert!(
        shown.contains("sdmn         realm.example"),
        "unexpected: {shown}"
    );

    // The two are part of the internet relation's unique index, so storing the
    // same item again is a duplicate rather than a second record.
    let output = kc(
        &[
            "add",
            "internet",
            "-a",
            "bob",
            "-s",
            "example.com",
            "-S",
            "realm.example",
            "-r",
            "htps",
            "--path",
            "/login",
            "-P",
            "8443",
            "-w",
            "again",
            &keychain,
        ],
        Some("pw"),
    );
    assert_eq!(output.status.code(), Some(46), "duplicate exit code");
}
