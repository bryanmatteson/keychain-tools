//! Identities: a certificate plus the private key that matches it.
//!
//! Everything here is checked against the system, in both directions: what
//! `security import` writes is parsed and compared field by field with what
//! `kc add identity` writes, and `security find-certificate` /
//! `security find-identity` are asked to read a keychain `kc` wrote.

mod common;

use common::{
    TempDir, create_with_security, generate_identity, import_identity_with_security, kc, kc_ok,
    security, security_available, security_ok,
};

use keychain::crypto::KeyBlob;
use keychain::der;
use keychain::{KeychainFile, RecordType, Value};

/// The attributes of a record, by attribute name.
fn attributes(file: &KeychainFile, record_type: RecordType, number: u32) -> Vec<(String, Value)> {
    let relation = file
        .schema()
        .relation(record_type)
        .expect("relation is in the schema");
    let record = file
        .records_of_type(record_type)
        .into_iter()
        .find(|record| record.number == number)
        .expect("record exists");
    relation
        .attributes
        .iter()
        .enumerate()
        .filter_map(|(position, attribute)| {
            record
                .attribute(position)
                .map(|value| (attribute.name.clone(), value.clone()))
        })
        .collect()
}

fn only_record(file: &KeychainFile, record_type: RecordType) -> u32 {
    let records = file.records_of_type(record_type);
    assert_eq!(
        records.len(),
        1,
        "expected one {} record",
        record_type.name()
    );
    records[0].number
}

#[test]
fn kc_writes_the_records_security_import_writes() {
    if !security_available() {
        eprintln!("skipping: /usr/bin/security is unavailable");
        return;
    }
    let dir = TempDir::new("identity-compare");
    let (certificate, key) = generate_identity(&dir, "id", "kc identity compare");

    // The same certificate and key, stored twice: once by macOS, once by us.
    let theirs = dir.join("theirs.keychain");
    create_with_security(&theirs, "pw");
    import_identity_with_security(
        &dir,
        &theirs,
        "id",
        &certificate,
        &key,
        "kc identity compare",
    );

    let ours = dir.join("ours.keychain");
    kc_ok(&["create", ours.to_str().expect("utf-8 path")], Some("pw"));
    kc_ok(
        &[
            "add",
            "identity",
            "--cert",
            certificate.to_str().expect("utf-8 path"),
            "--key",
            key.to_str().expect("utf-8 path"),
            ours.to_str().expect("utf-8 path"),
        ],
        Some("pw"),
    );

    let theirs = KeychainFile::open(&theirs).expect("open the keychain macOS wrote");
    let ours = KeychainFile::open(&ours).expect("open the keychain kc wrote");

    // The certificate record: every attribute, and the stored certificate.
    let their_cert = only_record(&theirs, RecordType::X509_CERTIFICATE);
    let our_cert = only_record(&ours, RecordType::X509_CERTIFICATE);
    assert_eq!(
        attributes(&theirs, RecordType::X509_CERTIFICATE, their_cert),
        attributes(&ours, RecordType::X509_CERTIFICATE, our_cert),
    );

    let certificate_der = std::fs::read(&certificate).expect("read the certificate");
    let certificate_der = der::pem_or_der(&certificate_der).expect("decode the certificate");
    for file in [&theirs, &ours] {
        let record = file.records_of_type(RecordType::X509_CERTIFICATE)[0];
        assert_eq!(
            record.key_data, certificate_der,
            "certificate is stored as-is"
        );
        assert_eq!(record.unknown3, 0);
    }

    // The private-key record: attributes, header word, and the wrapped key.
    let their_key = only_record(&theirs, RecordType::PRIVATE_KEY);
    let our_key = only_record(&ours, RecordType::PRIVATE_KEY);
    assert_eq!(
        attributes(&theirs, RecordType::PRIVATE_KEY, their_key),
        attributes(&ours, RecordType::PRIVATE_KEY, our_key),
    );

    let their_record = theirs.records_of_type(RecordType::PRIVATE_KEY)[0];
    let our_record = ours.records_of_type(RecordType::PRIVATE_KEY)[0];
    assert_eq!(our_record.unknown3, their_record.unknown3);
    assert_eq!(our_record.version, their_record.version);

    let their_blob = KeyBlob::parse(&their_record.key_data).expect("parse their key blob");
    let our_blob = KeyBlob::parse(&our_record.key_data).expect("parse our key blob");
    assert_eq!(our_blob.version, their_blob.version);
    assert_eq!(our_blob.header, their_blob.header);
    assert_eq!(our_blob.wrapped, their_blob.wrapped);
    assert_eq!(
        our_blob.crypto_blob.len(),
        their_blob.crypto_blob.len(),
        "the wrapped key is the same size"
    );

    // And the schema learned the same relation, with the same table layout.
    assert_eq!(
        theirs
            .keychain()
            .tables
            .iter()
            .map(|table| table.record_type.0)
            .collect::<Vec<_>>(),
        ours.keychain()
            .tables
            .iter()
            .map(|table| table.record_type.0)
            .collect::<Vec<_>>(),
    );
    let their_table = theirs
        .keychain()
        .table(RecordType::X509_CERTIFICATE)
        .expect("their certificate table");
    let our_table = ours
        .keychain()
        .table(RecordType::X509_CERTIFICATE)
        .expect("our certificate table");
    assert_eq!(
        our_table.indexes, their_table.indexes,
        "index regions match"
    );
    assert_eq!(our_table.free_list_head, their_table.free_list_head);
}

#[test]
fn security_finds_an_identity_kc_wrote() {
    if !security_available() {
        eprintln!("skipping: /usr/bin/security is unavailable");
        return;
    }
    let dir = TempDir::new("identity-read");
    let (certificate, key) = generate_identity(&dir, "id", "kc identity read");
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
    security_ok(&["unlock-keychain", "-p", "pw", as_str]);

    let found = security_ok(&["find-certificate", "-a", "-c", "kc identity read", as_str]);
    assert!(found.contains("kc identity read"), "unexpected: {found}");
    assert!(found.contains("0x80001000"), "unexpected: {found}");

    // A self-signed certificate is untrusted, so `find-identity` reports the
    // identity but not as valid: what matters is that it pairs the two records.
    let identities = security_ok(&["find-identity", as_str]);
    assert!(
        identities.contains("1 identities found"),
        "unexpected: {identities}"
    );
    assert!(
        identities.contains("kc identity read"),
        "unexpected: {identities}"
    );

    // And `kc` correlates them the same way.
    let listed = kc_ok(&["find", "identity", as_str], None);
    assert!(listed.contains("kc identity read"), "unexpected: {listed}");
}

#[test]
fn the_stored_private_key_is_the_key_that_went_in() {
    let dir = TempDir::new("identity-unwrap");
    let (certificate, key) = generate_identity(&dir, "id", "kc identity unwrap");
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

    let mut file = KeychainFile::open(&path).expect("open");
    file.unlock(b"pw").expect("unlock");
    let record = file.records_of_type(RecordType::PRIVATE_KEY)[0];
    let blob = KeyBlob::parse(&record.key_data).expect("parse the key blob");
    let keys = file
        .db_blob()
        .expect("the metadata record")
        .unlock(b"pw")
        .expect("derive the database keys");
    let unwrapped =
        keychain::crypto::unwrap_blob(keys.encryption_key.as_slice(), &blob.iv, &blob.crypto_blob)
            .expect("unwrap the private key");

    let expected = std::fs::read(&key).expect("read the key");
    let expected = der::pem_or_der(&expected).expect("decode the key");
    assert_eq!(unwrapped.as_slice(), expected.as_slice());

    // The link between the two records: the key's Label is the hash of the
    // certificate's public key.
    let certificate_der = std::fs::read(&certificate).expect("read the certificate");
    let certificate_der = der::pem_or_der(&certificate_der).expect("decode the certificate");
    let parsed = der::Certificate::parse(&certificate_der).expect("parse the certificate");
    let label = file
        .schema()
        .attribute(RecordType::PRIVATE_KEY, record, "Label")
        .and_then(Value::as_bytes)
        .expect("the key record has a Label");
    assert_eq!(label, parsed.public_key_hash());
}

#[test]
fn an_ec_key_is_refused_rather_than_stored_wrongly() {
    let dir = TempDir::new("identity-ec");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");
    kc_ok(&["create", as_str], Some("pw"));

    // Generate an EC identity: the record attributes for one differ from RSA,
    // so storing it as RSA would be worse than refusing.
    let certificate = dir.join("ec-cert.pem");
    let key = dir.join("ec-key.pem");
    let generated = std::process::Command::new("/usr/bin/openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-days",
            "30",
            "-subj",
            "/CN=kc identity ec",
        ])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&certificate)
        .output()
        .expect("run openssl");
    if !generated.status.success() {
        eprintln!("skipping: openssl could not generate an EC key");
        return;
    }

    let output = kc(
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
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("only RSA"), "unexpected error: {stderr}");
}

#[test]
fn a_certificate_that_is_not_a_certificate_is_refused() {
    let dir = TempDir::new("identity-junk");
    let path = dir.join("k.keychain");
    let as_str = path.to_str().expect("utf-8 path");
    kc_ok(&["create", as_str], Some("pw"));

    let junk = dir.join("junk.der");
    std::fs::write(&junk, b"not DER at all").expect("write");
    let (_, key) = generate_identity(&dir, "id", "kc identity junk");

    let output = kc(
        &[
            "add",
            "identity",
            "--cert",
            junk.to_str().expect("utf-8 path"),
            "--key",
            key.to_str().expect("utf-8 path"),
            as_str,
        ],
        Some("pw"),
    );
    assert!(!output.status.success());
    // Nothing was written: the keychain still has no certificate table.
    let file = KeychainFile::open(&path).expect("open");
    assert!(
        file.keychain()
            .table(RecordType::X509_CERTIFICATE)
            .is_none()
    );
    let _ = security(&["delete-keychain", as_str]);
}
