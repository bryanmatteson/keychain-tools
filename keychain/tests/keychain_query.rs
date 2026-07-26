use keychain::edit::ItemChanges;
use keychain::write::{CreateOptions, NewItem, create};
use keychain::{Expression, ItemRef, KeychainFile, RecordType};

#[test]
fn typed_queries_and_revision_bound_references_are_public_library_contracts() {
    let path = std::env::temp_dir().join(format!(
        "keychain-query-{}-{:?}.keychain-db",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&path);

    let mut file = create(b"pw", &CreateOptions::default()).expect("create");
    file.add_password(
        RecordType::GENERIC_PASSWORD,
        &NewItem {
            label: Some("Café.com".into()),
            account: Some("machina".into()),
            service: Some("vpn".into()),
            comment: Some("created in 2026".into()),
            ..NewItem::default()
        },
        b"secret",
        "20260515074219Z",
    )
    .expect("add");
    file.save(&path).expect("save");

    let file = KeychainFile::open(&path).expect("open");
    let expression =
        Expression::parse(r#"class:generic label[cd]:cafe.% icmt:%2026% cdat:<=20260515074219Z"#)
            .expect("parse expression");
    let items = file.select(&expression).expect("select");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].account().as_deref(), Some("machina"));

    let encoded = file.item_ref(&items[0]).expect("reference").encode();
    let reference = ItemRef::decode(&encoded).expect("decode reference");
    assert_eq!(reference.keychain(), path);
    assert_eq!(reference.class(), Some("generic"));
    assert_eq!(reference.record_type(), RecordType::GENERIC_PASSWORD);
    assert_eq!(reference.record_number(), items[0].number());
    assert_eq!(
        file.resolve_ref(&reference).expect("resolve").number(),
        items[0].number()
    );

    let mut file = file;
    file.update_item(
        RecordType::GENERIC_PASSWORD,
        reference.record_number(),
        &ItemChanges {
            comment: Some("updated".into()),
            ..ItemChanges::default()
        },
        None,
        "20260516074219Z",
    )
    .expect("update");
    let stale = match file.resolve_ref(&reference) {
        Ok(_) => panic!("old revision unexpectedly resolved"),
        Err(error) => error,
    };
    assert!(stale.to_string().contains("stale item reference"));

    let _ = std::fs::remove_file(path);
}
