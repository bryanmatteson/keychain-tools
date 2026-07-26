//! Canonical command surface: password sources, projections, assignments, and
//! the typed `get` query language.

mod common;

use common::*;

fn populated(dir: &TempDir, password: &str) -> String {
    let path = dir.join("k.keychain");
    let keychain = path.to_str().expect("utf-8 path").to_string();

    kc_ok(&["create", "--no-access-policy", &keychain], Some(password));
    kc_ok(
        &[
            "add",
            "class=generic",
            "account=alice",
            "service=svc",
            "generic=tag-bytes",
            "kind=app password",
            "comment=made by kc",
            "label=the label",
            "-w",
            "generic-secret",
            "--keychain",
            &keychain,
        ],
        Some(password),
    );
    kc_ok(
        &[
            "add",
            "class=internet",
            "account=bob",
            "server=example.com",
            "security-domain=realm.example",
            "protocol=htps",
            "path=/login",
            "port=8443",
            "comment=web login",
            "-w",
            "internet-secret",
            "--keychain",
            &keychain,
        ],
        Some(password),
    );
    keychain
}

#[test]
fn password_sources_work_for_secret_projections() {
    let dir = TempDir::new("options-sources");
    let keychain = populated(&dir, "source-pw");
    let password_file = dir.join("pw.txt");
    std::fs::write(&password_file, "source-pw\n").expect("write password file");
    let password_file = password_file.to_str().unwrap();

    let base = [
        "get",
        "class:generic",
        "account:alice",
        "-o",
        "secret",
        "--keychain",
        &keychain,
    ];
    let with_env = kc_with_env(
        &[
            "get",
            "class:generic",
            "account:alice",
            "-o",
            "secret",
            "-E",
            "KC_TEST_PW",
            "--keychain",
            &keychain,
        ],
        &[("KC_TEST_PW", "source-pw\n")],
    );
    assert!(with_env.status.success());
    assert_eq!(
        String::from_utf8_lossy(&with_env.stdout).trim(),
        "generic-secret"
    );

    assert_eq!(
        kc_ok(
            &[
                "get",
                "class:generic",
                "account:alice",
                "-o",
                "secret",
                "-F",
                password_file,
                "--keychain",
                &keychain,
            ],
            None,
        ),
        "generic-secret"
    );
    assert_eq!(kc_ok(&base, Some("source-pw")), "generic-secret");
    assert_eq!(
        kc_ok(
            &[
                "get",
                "class:generic",
                "account:alice",
                "-o",
                "secret",
                "-P",
                "source-pw",
                "--keychain",
                &keychain,
            ],
            None,
        ),
        "generic-secret"
    );

    let missing = kc_with_env(
        &[
            "get",
            "class:generic",
            "-o",
            "secret",
            "-E",
            "KC_TEST_UNSET_PW",
            "--keychain",
            &keychain,
        ],
        &[],
    );
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("KC_TEST_UNSET_PW is not set"));

    let exclusive = kc(
        &[
            "get",
            "class:generic",
            "-o",
            "secret",
            "-E",
            "KC_TEST_PW",
            "-F",
            password_file,
            "--keychain",
            &keychain,
        ],
        None,
    );
    assert!(!exclusive.status.success());
    assert!(String::from_utf8_lossy(&exclusive.stderr).contains("cannot be used with"));
}

#[test]
fn password_flags_and_generation_follow_the_contract() {
    let dir = TempDir::new("options-passwords");
    let path = dir.join("generated.keychain");
    let path = path.to_str().unwrap();
    let output = kc(&["create", "--password-gen", path], None);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let password = stdout
        .lines()
        .find_map(|line| line.strip_prefix("password: "))
        .expect("generated password");
    assert_eq!(password.len(), 40);
    assert!(password.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(kc(&["verify", "-P", password, path], None).status.success());
    assert!(
        kc_with_env(&["verify", path, "-E"], &[("KC_PASSWORD", password)])
            .status
            .success()
    );

    for policy in ["alphanumeric", "mixed-case", "symbol", "secure"] {
        let name = format!("{policy}.keychain");
        let path = dir.join(&name);
        let output = kc(
            &[
                "create",
                "--password-gen",
                "--password-policy",
                policy,
                path.to_str().unwrap(),
            ],
            None,
        );
        assert!(output.status.success(), "{policy}");
        let password = String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| line.strip_prefix("password: "))
            .unwrap()
            .to_string();
        assert_eq!(password.len(), 40);
        match policy {
            "alphanumeric" => assert!(password.bytes().all(|b| b.is_ascii_alphanumeric())),
            "mixed-case" => {
                assert!(password.bytes().any(|b| b.is_ascii_lowercase()));
                assert!(password.bytes().any(|b| b.is_ascii_uppercase()));
                assert!(password.bytes().any(|b| b.is_ascii_digit()));
            }
            "symbol" => assert!(password.bytes().any(|b| !b.is_ascii_alphanumeric())),
            "secure" => {
                assert!(password.bytes().any(|b| b.is_ascii_lowercase()));
                assert!(password.bytes().any(|b| b.is_ascii_uppercase()));
                assert!(password.bytes().any(|b| b.is_ascii_digit()));
                assert!(password.bytes().any(|b| !b.is_ascii_alphanumeric()));
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn get_supports_aliases_typed_comparisons_and_unicode_like_matching() {
    let dir = TempDir::new("options-query");
    let keychain = populated(&dir, "pw");

    let cases = [
        "class:generic",
        "acct:alice",
        "svce:svc",
        "label:the label",
        "kind:app password",
        "icmt:%by kc",
        "gena:tag-bytes",
    ];
    for predicate in cases {
        let output = kc_ok(
            &[
                "get",
                predicate,
                "-o",
                "class,account",
                "--keychain",
                &keychain,
            ],
            None,
        );
        assert!(output.contains("generic"), "{predicate}: {output}");
    }
    let internet = kc_ok(
        &[
            "get",
            "class:internet",
            "port:>=8443",
            "ptcl:htps",
            "icmt:%login",
            "-o",
            "account,server,port",
            "--keychain",
            &keychain,
        ],
        None,
    );
    assert_eq!(internet, "bob  example.com  8443");

    kc_ok(
        &[
            "set",
            "label=Café.com",
            "--for",
            "class:generic account:alice",
            "--keychain",
            &keychain,
        ],
        None,
    );
    let folded = kc_ok(
        &[
            "get",
            "class:generic",
            "label[cd]:cafe.%",
            "-o",
            "label",
            "--keychain",
            &keychain,
        ],
        None,
    );
    assert_eq!(folded, "Café.com");

    let created = kc_ok(
        &[
            "get",
            "class:generic",
            "cdat:<99991231235959Z",
            "mdat:>=20000101000000Z",
            "-o",
            "account",
            "--keychain",
            &keychain,
        ],
        None,
    );
    assert_eq!(created, "alice");
}

#[test]
fn projections_and_formats_have_one_shape() {
    let dir = TempDir::new("options-formats");
    let keychain = populated(&dir, "pw");

    let text = kc_ok(
        &[
            "get",
            "class:generic",
            "-o",
            "label,kind,account,service",
            "--keychain",
            &keychain,
        ],
        None,
    );
    assert_eq!(text, "the label  app password  alice  svc");

    let json = kc_ok(
        &[
            "--json",
            "get",
            "class:generic",
            "-o",
            "account,service",
            "--keychain",
            &keychain,
        ],
        None,
    );
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["items"][0]["account"], "alice");
    assert_eq!(parsed["items"][0]["service"], "svc");

    let secret = kc_ok(
        &[
            "--format",
            "secret",
            "get",
            "class:generic",
            "--keychain",
            &keychain,
        ],
        Some("pw"),
    );
    assert_eq!(secret, "generic-secret");

    let many = kc(
        &["get", "-o", "secret", "--keychain", &keychain],
        Some("pw"),
    );
    assert!(!many.status.success());
    assert!(String::from_utf8_lossy(&many.stderr).contains("pass --all"));

    let aliases = kc_ok(
        &[
            "get",
            "class:generic",
            "-o",
            "label,kind,acct,svce,icmt,gena",
            "--keychain",
            &keychain,
        ],
        None,
    );
    assert!(aliases.contains("made by kc"));
    assert!(aliases.contains("tag-bytes"));
}

#[test]
fn distinct_deduplicates_typed_projection_tuples_in_first_seen_order() {
    let dir = TempDir::new("options-distinct");
    let path = dir.join("k.keychain");
    let keychain = path.to_str().unwrap();
    kc_ok(&["create", "--no-access-policy", keychain], Some("pw"));
    for (account, service) in [("alice", "machina"), ("bob", "machina"), ("carol", "other")] {
        kc_ok(
            &[
                "add",
                "class=generic",
                &format!("account={account}"),
                &format!("service={service}"),
                "-w",
                "secret",
                "--keychain",
                keychain,
            ],
            Some("pw"),
        );
    }

    let all = kc_ok(
        &["get", "service:_%", "-o", "service", "--keychain", keychain],
        None,
    );
    assert_eq!(
        all.lines().collect::<Vec<_>>(),
        ["machina", "machina", "other"]
    );

    let distinct = kc_ok(
        &[
            "get",
            "service:_%",
            "-o",
            "service",
            "--distinct",
            "--keychain",
            keychain,
        ],
        None,
    );
    assert_eq!(distinct.lines().collect::<Vec<_>>(), ["machina", "other"]);

    let json = kc_ok(
        &[
            "--json",
            "get",
            "service:_%",
            "-o",
            "service",
            "-u",
            "--keychain",
            keychain,
        ],
        None,
    );
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(json["items"].as_array().unwrap().len(), 2);
    assert_eq!(json["items"][0]["service"], "machina");
    assert_eq!(json["items"][1]["service"], "other");

    let pairs = kc_ok(
        &[
            "get",
            "service:_%",
            "-o",
            "account,service",
            "-u",
            "--keychain",
            keychain,
        ],
        None,
    );
    assert_eq!(
        pairs.lines().count(),
        3,
        "distinct applies to the whole tuple"
    );
}

#[test]
fn assignment_add_validates_class_specific_fields() {
    let dir = TempDir::new("options-assignment-add");
    let path = dir.join("k.keychain");
    let keychain = path.to_str().unwrap();
    kc_ok(&["create", "--no-access-policy", keychain], Some("pw"));

    let invalid = kc(
        &[
            "add",
            "class=generic",
            "account=alice",
            "server=example.com",
            "-w",
            "secret",
            "--keychain",
            keychain,
        ],
        Some("pw"),
    );
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("no assignable attribute"));

    // The requested uppercase metadata shorts remain available on the typed
    // identity/password writer surface.
    kc_ok(
        &[
            "add", "generic", "-P", "pw", "-A", "alice", "-S", "svc", "-L", "label", "-C",
            "comment", "-w", "secret", keychain,
        ],
        None,
    );
    let output = kc_ok(
        &[
            "get",
            "class:generic",
            "account:alice",
            "service:svc",
            "label:label",
            "comment:comment",
            "-o",
            "account",
            "--keychain",
            keychain,
        ],
        None,
    );
    assert_eq!(output, "alice");
}
