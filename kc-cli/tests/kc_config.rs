//! Keychain name resolution and persistent defaults.

mod common;

use common::*;
use keychain::{ApplicationAccess, KeychainFile};

#[test]
fn create_requires_an_output_even_when_a_default_is_configured() {
    let home = TempDir::new("create-output-home");
    let output = kc_with_env(
        &["create", "-p", "test-password"],
        &[("HOME", home.path().to_str().unwrap())],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("<KEYCHAIN>"));
}

#[test]
fn created_keychains_default_to_prompt_for_direct_and_native_access() {
    let home = TempDir::new("create-access-home");
    let home_text = home.path().to_str().unwrap();
    let keychain = home.join("prompt.keychain-db");
    let keychain_text = keychain.to_str().unwrap();

    for args in [
        vec!["create", "-p", "pw", keychain_text],
        vec![
            "add",
            "generic",
            "-p",
            "pw",
            "-A",
            "alice",
            "-S",
            "service",
            "-w",
            "secret",
            keychain_text,
        ],
    ] {
        let output = kc_with_env(&args, &[("HOME", home_text)]);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let shown = kc_with_env(&["access", "show", keychain_text], &[("HOME", home_text)]);
    let shown = String::from_utf8_lossy(&shown.stdout);
    assert!(shown.contains("hybrid"), "{shown}");
    assert!(shown.contains("prompt"), "{shown}");

    let audited = kc_with_env(&["access", "audit", keychain_text], &[("HOME", home_text)]);
    assert!(
        audited.status.success(),
        "{}",
        String::from_utf8_lossy(&audited.stderr)
    );

    let file = KeychainFile::open(&keychain).expect("open created keychain");
    let item = file.items().into_iter().next().expect("one item");
    assert_eq!(
        file.item_application_access(item.record_type, item.number())
            .expect("read ACL"),
        Some(ApplicationAccess::Prompt)
    );

    let denied = kc_with_env(
        &[
            "find",
            "generic",
            "-p",
            "pw",
            "-A",
            "alice",
            "-w",
            keychain_text,
        ],
        &[("HOME", home_text)],
    );
    assert!(!denied.status.success());
    assert!(
        String::from_utf8_lossy(&denied.stderr).contains("rerun with --interactive"),
        "{}",
        String::from_utf8_lossy(&denied.stderr)
    );
}

#[test]
fn an_existing_keychain_can_project_prompt_without_trusted_apps() {
    let home = TempDir::new("access-prompt-projection-home");
    let home_text = home.path().to_str().unwrap();
    let keychain = home.join("existing.keychain-db");
    let keychain_text = keychain.to_str().unwrap();

    for args in [
        vec!["create", "--no-access-policy", "-p", "pw", keychain_text],
        vec![
            "add",
            "generic",
            "-p",
            "pw",
            "-A",
            "alice",
            "-S",
            "service",
            "-w",
            "secret",
            keychain_text,
        ],
        vec![
            "access",
            "set",
            "--mode",
            "hybrid",
            "--default",
            "prompt",
            keychain_text,
        ],
        vec!["access", "apply", "-p", "pw", keychain_text],
    ] {
        let output = kc_with_env(&args, &[("HOME", home_text)]);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let file = KeychainFile::open(&keychain).expect("open keychain");
    let item = file.items().into_iter().next().expect("one item");
    assert_eq!(
        file.item_application_access(item.record_type, item.number())
            .expect("read ACL"),
        Some(ApplicationAccess::Prompt)
    );
}

#[test]
fn bare_names_and_the_saved_default_resolve_under_home() {
    let home = TempDir::new("config-home");
    std::fs::create_dir_all(home.join("Library/Keychains")).unwrap();
    let home_text = home.path().to_str().unwrap();

    let output = kc_with_env(
        &["config", "set", "keychains.default", "machina"],
        &[("HOME", home_text)],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = kc_with_env(
        &["create", "-p", "test-password", "machina"],
        &[("HOME", home_text)],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(home.join("Library/Keychains/machina.keychain-db").exists());

    let output = kc_with_env(&["info"], &[("HOME", home_text)]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let text = std::fs::read_to_string(home.join(".config/keychain.kdl")).unwrap();
    assert!(text.contains("default \"machina\""));
}

#[test]
fn additional_search_paths_are_used_for_existing_names() {
    let home = TempDir::new("search-home");
    let extra = home.join("extra");
    std::fs::create_dir_all(home.join("Library/Keychains")).unwrap();
    std::fs::create_dir_all(&extra).unwrap();
    let home_text = home.path().to_str().unwrap();
    let extra_text = extra.to_str().unwrap();
    let keychain = extra.join("archive.keychain-db");
    let keychain_text = keychain.to_str().unwrap();

    let output = kc_with_env(
        &["create", "-p", "test-password", keychain_text],
        &[("HOME", home_text)],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = kc_with_env(
        &["config", "set", "search.paths", extra_text],
        &[("HOME", home_text)],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = kc_with_env(&["info", "archive"], &[("HOME", home_text)]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn setting_search_paths_replaces_the_complete_list() {
    let home = TempDir::new("search-list-home");
    let home_text = home.path().to_str().unwrap();

    let output = kc_with_env(
        &["config", "set", "search.paths", "path1", "path2"],
        &[("HOME", home_text)],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = std::fs::read_to_string(home.join(".config/keychain.kdl")).unwrap();
    assert!(text.contains("search-path \"path1\""));
    assert!(text.contains("search-path \"path2\""));
}

#[test]
fn search_paths_can_be_appended_and_prepended() {
    let home = TempDir::new("search-order-home");
    let home_text = home.path().to_str().unwrap();
    for args in [
        &["config", "set", "search.paths", "middle"][..],
        &["config", "append", "search.paths", "last"][..],
        &["config", "prepend", "search.paths", "first"][..],
    ] {
        let output = kc_with_env(args, &[("HOME", home_text)]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let text = std::fs::read_to_string(home.join(".config/keychain.kdl")).unwrap();
    let first = text.find("search-path \"first\"").unwrap();
    let middle = text.find("search-path \"middle\"").unwrap();
    let last = text.find("search-path \"last\"").unwrap();
    assert!(first < middle && middle < last);
}

#[test]
fn keychain_access_policy_can_be_saved_projected_and_audited() {
    let home = TempDir::new("access-policy-home");
    let home_text = home.path().to_str().unwrap();
    let keychain = home.join("policy.keychain");
    let keychain_text = keychain.to_str().unwrap();
    let requirement_file = home.join("security.req");
    std::fs::write(
        &requirement_file,
        designated_requirement("/usr/bin/security"),
    )
    .unwrap();
    let requirement = format!("/usr/bin/security={}", requirement_file.to_str().unwrap());

    for args in [
        vec!["create", "-p", "pw", keychain_text],
        vec![
            "add",
            "generic",
            "-p",
            "pw",
            "-A",
            "alice",
            "-S",
            "svc",
            "-w",
            "secret",
            keychain_text,
        ],
        vec![
            "access",
            "set",
            "--mode",
            "hybrid",
            "--default",
            "prompt",
            "--trust-requirement",
            &requirement,
            keychain_text,
        ],
    ] {
        let output = kc_with_env(&args, &[("HOME", home_text)]);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let before = kc_with_env(&["access", "audit", keychain_text], &[("HOME", home_text)]);
    assert!(!before.status.success(), "an unprojected ACL matched");

    let applied = kc_with_env(
        &["access", "apply", "-p", "pw", keychain_text],
        &[("HOME", home_text)],
    );
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let audited = kc_with_env(&["access", "audit", keychain_text], &[("HOME", home_text)]);
    assert!(
        audited.status.success(),
        "{}",
        String::from_utf8_lossy(&audited.stderr)
    );

    let inherited = kc_with_env(
        &[
            "add",
            "generic",
            "-p",
            "pw",
            "-A",
            "bob",
            "-S",
            "other",
            "-w",
            "second",
            keychain_text,
        ],
        &[("HOME", home_text)],
    );
    assert!(
        inherited.status.success(),
        "{}",
        String::from_utf8_lossy(&inherited.stderr)
    );
    let audited = kc_with_env(&["access", "audit", keychain_text], &[("HOME", home_text)]);
    assert!(
        audited.status.success(),
        "a new item did not inherit policy: {}",
        String::from_utf8_lossy(&audited.stderr)
    );

    let denied = kc_with_env(
        &[
            "find",
            "generic",
            "-p",
            "pw",
            "-A",
            "alice",
            "-w",
            keychain_text,
        ],
        &[("HOME", home_text)],
    );
    assert!(!denied.status.success());
    assert!(
        String::from_utf8_lossy(&denied.stderr).contains("rerun with --interactive"),
        "{}",
        String::from_utf8_lossy(&denied.stderr)
    );
}
