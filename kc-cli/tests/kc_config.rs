//! Keychain name resolution and persistent defaults.

mod common;

use common::*;

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

    let output = kc_with_env(&["create", "-p", "test-password"], &[("HOME", home_text)]);
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
