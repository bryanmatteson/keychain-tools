//! Identities: a certificate plus the private key that matches it.
//!
//! Everything here is checked against the system, in both directions: what
//! `security import` writes is parsed and compared field by field with what
//! `kc add identity` writes, and `security find-certificate` /
//! `security find-identity` are asked to read a keychain `kc` wrote.

mod common;

use common::{
    TempDir, create_with_security, generate_identity, generate_pkcs12,
    import_identity_with_security, kc, kc_ok, kc_with_env, security, security_available,
    security_ok,
};

use keychain::crypto::KeyBlob;
use keychain::der;
use keychain::{KeychainFile, RecordType, Value};
use std::process::Command;

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
fn traditional_pkcs1_rsa_keys_work_with_pem_and_der_certificates() {
    let dir = TempDir::new("identity-pkcs1");
    let (certificate_pem, key_pkcs8) = generate_identity(&dir, "id", "kc identity traditional RSA");
    let certificate_der = dir.join("id-cert.der");
    let key_pem = dir.join("id-key-rsa.pem");
    let key_der = dir.join("id-key-rsa.der");

    for output in [
        Command::new("/usr/bin/openssl")
            .args(["x509", "-in"])
            .arg(&certificate_pem)
            .args(["-outform", "DER", "-out"])
            .arg(&certificate_der)
            .output()
            .expect("convert certificate to DER"),
        Command::new("/usr/bin/openssl")
            .args(["rsa", "-in"])
            .arg(&key_pkcs8)
            .arg("-out")
            .arg(&key_pem)
            .output()
            .expect("convert key to PKCS#1 PEM"),
        Command::new("/usr/bin/openssl")
            .args(["rsa", "-in"])
            .arg(&key_pkcs8)
            .args(["-outform", "DER", "-out"])
            .arg(&key_der)
            .output()
            .expect("convert key to PKCS#1 DER"),
    ] {
        assert!(
            output.status.success(),
            "openssl conversion failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    for (name, certificate, key) in [
        ("pem.keychain", &certificate_pem, &key_pem),
        ("der.keychain", &certificate_der, &key_der),
    ] {
        let keychain = dir.join(name);
        kc_ok(
            &["create", keychain.to_str().expect("utf-8 path")],
            Some("pw"),
        );
        kc_ok(
            &[
                "add",
                "identity",
                "--cert",
                certificate.to_str().expect("utf-8 path"),
                "--key",
                key.to_str().expect("utf-8 path"),
                keychain.to_str().expect("utf-8 path"),
            ],
            Some("pw"),
        );

        let file = KeychainFile::open(&keychain).expect("open keychain");
        assert_eq!(file.identities().len(), 1);
    }
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

#[test]
fn pkcs12_import_and_export_round_trip_through_openssl() {
    let dir = TempDir::new("identity-pkcs12");
    let (certificate, key) = generate_identity(&dir, "id", "kc pkcs12 round trip");
    let source = generate_pkcs12(
        &dir,
        "source",
        &certificate,
        &key,
        "friendly identity",
        "bundle-in",
    );
    let first = dir.join("first.keychain");
    let second = dir.join("second.keychain");
    let exported = dir.join("exported.p12");

    let created = kc_with_env(
        &[
            "create",
            "--no-access-policy",
            "--password-env",
            "KC_PASSWORD",
            first.to_str().unwrap(),
        ],
        &[("KC_PASSWORD", "keychain")],
    );
    assert!(created.status.success());
    let imported = kc_with_env(
        &[
            "import",
            "identity",
            "--password-env",
            "KC_PASSWORD",
            "--pkcs12-password-env",
            "P12_PASSWORD",
            source.to_str().unwrap(),
            first.to_str().unwrap(),
        ],
        &[("KC_PASSWORD", "keychain"), ("P12_PASSWORD", "bundle-in")],
    );
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );

    let exported_result = kc_with_env(
        &[
            "export",
            "identity",
            "--password-env",
            "KC_PASSWORD",
            "--pkcs12",
            "--pkcs12-password-env",
            "P12_PASSWORD",
            "--out",
            exported.to_str().unwrap(),
            first.to_str().unwrap(),
        ],
        &[("KC_PASSWORD", "keychain"), ("P12_PASSWORD", "bundle-out")],
    );
    assert!(
        exported_result.status.success(),
        "{}",
        String::from_utf8_lossy(&exported_result.stderr)
    );

    let openssl = std::process::Command::new("/usr/bin/openssl")
        .args([
            "pkcs12",
            "-in",
            exported.to_str().unwrap(),
            "-passin",
            "pass:bundle-out",
            "-info",
            "-noout",
        ])
        .output()
        .expect("run openssl");
    assert!(
        openssl.status.success(),
        "openssl rejected the export: {}",
        String::from_utf8_lossy(&openssl.stderr)
    );

    let created = kc_with_env(
        &[
            "create",
            "--no-access-policy",
            "--password-env",
            "KC_PASSWORD",
            second.to_str().unwrap(),
        ],
        &[("KC_PASSWORD", "keychain")],
    );
    assert!(created.status.success());
    let reimported = kc_with_env(
        &[
            "add",
            "identity",
            "--password-env",
            "KC_PASSWORD",
            "--pkcs12",
            exported.to_str().unwrap(),
            "--pkcs12-password-env",
            "P12_PASSWORD",
            second.to_str().unwrap(),
        ],
        &[("KC_PASSWORD", "keychain"), ("P12_PASSWORD", "bundle-out")],
    );
    assert!(
        reimported.status.success(),
        "{}",
        String::from_utf8_lossy(&reimported.stderr)
    );

    let mut first_file = KeychainFile::open(&first).unwrap();
    let mut second_file = KeychainFile::open(&second).unwrap();
    first_file.unlock(b"keychain").unwrap();
    second_file.unlock(b"keychain").unwrap();
    let first_identity = first_file.identities().remove(0);
    let second_identity = second_file.identities().remove(0);
    assert_eq!(first_identity.label, Some("friendly identity".to_string()));
    assert_eq!(second_identity.label, first_identity.label);
    assert_eq!(second_identity.certificate, first_identity.certificate);
    let first_key = first_file
        .private_key_pkcs8(first_identity.private_key_record.unwrap())
        .unwrap();
    let second_key = second_file
        .private_key_pkcs8(second_identity.private_key_record.unwrap())
        .unwrap();
    assert_eq!(second_key.as_slice(), first_key.as_slice());
}

#[test]
fn pkcs12_pem_is_accepted_and_can_be_exported() {
    let dir = TempDir::new("identity-pkcs12-pem");
    let (certificate, key) = generate_identity(&dir, "id", "kc pkcs12 pem");
    let der = generate_pkcs12(&dir, "source", &certificate, &key, "pem identity", "p12");
    let pem = dir.join("source.pem");
    std::fs::write(
        &pem,
        keychain::der::to_pem(
            keychain::der::PEM_PKCS12,
            &std::fs::read(&der).expect("read p12"),
        ),
    )
    .expect("write PEM");
    let keychain_path = dir.join("pem.keychain");
    let exported = dir.join("exported.pem");

    let created = kc_with_env(
        &[
            "create",
            "--no-access-policy",
            "--password-env",
            "KC_PASSWORD",
            keychain_path.to_str().unwrap(),
        ],
        &[("KC_PASSWORD", "kc")],
    );
    assert!(created.status.success());
    let imported = kc_with_env(
        &[
            "import",
            "identity",
            "--password-env",
            "KC_PASSWORD",
            "--pkcs12-password-env",
            "P12_PASSWORD",
            pem.to_str().unwrap(),
            keychain_path.to_str().unwrap(),
        ],
        &[("KC_PASSWORD", "kc"), ("P12_PASSWORD", "p12")],
    );
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );

    let result = kc_with_env(
        &[
            "export",
            "identity",
            "--password-env",
            "KC_PASSWORD",
            "--pkcs12",
            "--pem",
            "--pkcs12-password-env",
            "P12_PASSWORD",
            "-o",
            exported.to_str().unwrap(),
            keychain_path.to_str().unwrap(),
        ],
        &[("KC_PASSWORD", "kc"), ("P12_PASSWORD", "new")],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output = std::fs::read_to_string(exported).expect("read PEM export");
    assert!(output.starts_with("-----BEGIN PKCS12-----"));
    let decoded = keychain::der::pem_or_der(output.as_bytes()).expect("decode PEM");
    let identity = keychain::pkcs12::decode(&decoded, "new").expect("decode exported PKCS#12");
    assert_eq!(identity.friendly_name.as_deref(), Some("pem identity"));
}

#[test]
fn combined_pem_identity_imports_without_a_bundle_password() {
    let dir = TempDir::new("identity-combined-pem");
    let (certificate, key) = generate_identity(&dir, "id", "kc combined pem");
    let combined = dir.join("identity.pem");
    let mut bytes = std::fs::read(certificate).expect("read certificate");
    bytes.extend_from_slice(&std::fs::read(key).expect("read key"));
    std::fs::write(&combined, bytes).expect("write combined PEM");
    let path = dir.join("combined.keychain");

    kc_ok(&["create", path.to_str().unwrap()], Some("pw"));
    let output = kc(
        &[
            "import",
            "identity",
            combined.to_str().unwrap(),
            path.to_str().unwrap(),
        ],
        Some("pw"),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let file = KeychainFile::open(path).expect("open imported keychain");
    assert_eq!(
        file.identities()[0].label.as_deref(),
        Some("kc combined pem")
    );
}
