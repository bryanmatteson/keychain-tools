//! Just enough DER to fill in a certificate record's attributes.
//!
//! A keychain stores several fields of an X.509 certificate alongside the
//! certificate itself: the subject and issuer names, the serial number, the
//! subject key identifier, and a hash of the public key. Every one of them is a
//! *copy of bytes already in the certificate*, so this module locates fields and
//! hands back slices. It does not decode, validate, or re-encode anything, and it
//! is not a general ASN.1 library — that boundary is what keeps it small enough
//! to be obviously right.
//!
//! Field positions come from RFC 5280:
//!
//! ```text
//! Certificate      ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
//! TBSCertificate   ::= SEQUENCE { [0] version OPTIONAL, serialNumber, signature,
//!                                 issuer, validity, subject,
//!                                 subjectPublicKeyInfo, ... [3] extensions }
//! ```

use crate::error::{Error, Result};

/// A tag-length-value element, with its contents located inside the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv {
    pub tag: u8,
    /// Offset of the first content byte.
    pub start: usize,
    /// Offset one past the last content byte.
    pub end: usize,
    /// Offset one past the whole element, header included.
    pub next: usize,
}

impl Tlv {
    pub fn contents<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.start..self.end]
    }

    /// The element including its tag and length, which is what the keychain
    /// stores for a name.
    pub fn element<'a>(&self, data: &'a [u8], header_start: usize) -> &'a [u8] {
        &data[header_start..self.end]
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Universal and context tags this module names.
pub mod tag {
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const OID: u8 = 0x06;
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;
    /// `[0]` constructed: the optional version in a `TBSCertificate`.
    pub const CONTEXT_0: u8 = 0xa0;
    /// `[3]` constructed: the extensions.
    pub const CONTEXT_3: u8 = 0xa3;
}

/// Read one element at `at`.
pub fn read(data: &[u8], at: usize) -> Result<Tlv> {
    let tag = *data
        .get(at)
        .ok_or_else(|| malformed("element runs past the end"))?;
    let first = *data
        .get(at + 1)
        .ok_or_else(|| malformed("element has no length"))?;

    let (length, header) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return Err(malformed("unsupported DER length encoding"));
        }
        let bytes = data
            .get(at + 2..at + 2 + count)
            .ok_or_else(|| malformed("truncated DER length"))?;
        (
            bytes
                .iter()
                .fold(0usize, |value, byte| (value << 8) | *byte as usize),
            2 + count,
        )
    };

    let start = at + header;
    let end = start
        .checked_add(length)
        .ok_or_else(|| malformed("DER length overflows"))?;
    if end > data.len() {
        return Err(malformed("DER element extends past the input"));
    }
    Ok(Tlv {
        tag,
        start,
        end,
        next: end,
    })
}

/// Read an element and require its tag.
fn read_tagged(data: &[u8], at: usize, expected: u8) -> Result<Tlv> {
    let tlv = read(data, at)?;
    if tlv.tag != expected {
        return Err(malformed(format!(
            "expected tag 0x{expected:02x} at offset {at}, found 0x{:02x}",
            tlv.tag
        )));
    }
    Ok(tlv)
}

fn malformed(detail: impl Into<String>) -> Error {
    Error::format(format!("malformed certificate: {}", detail.into()))
}

/// The parts of a certificate a keychain record stores.
///
/// Every field borrows the certificate's own bytes; nothing is re-encoded.
#[derive(Debug, Clone)]
pub struct Certificate<'a> {
    /// `serialNumber`, the INTEGER's content bytes — leading zero included, the
    /// way the keychain stores it.
    pub serial_number: &'a [u8],
    /// `issuer`, the whole `Name` element including its SEQUENCE header.
    pub issuer: &'a [u8],
    /// `subject`, likewise.
    pub subject: &'a [u8],
    /// The `subjectPublicKey` BIT STRING contents: what `PublicKeyHash` hashes.
    pub subject_public_key: &'a [u8],
    /// The `subjectKeyIdentifier` extension's OCTET STRING contents, when present.
    pub subject_key_identifier: Option<&'a [u8]>,
    /// The first `commonName` in the subject, for a default label.
    pub common_name: Option<String>,
}

/// `id-ce-subjectKeyIdentifier` (2.5.29.14).
const OID_SUBJECT_KEY_IDENTIFIER: [u8; 3] = [0x55, 0x1d, 0x0e];

/// `id-at-commonName` (2.5.4.3).
const OID_COMMON_NAME: [u8; 3] = [0x55, 0x04, 0x03];

impl<'a> Certificate<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let certificate = read_tagged(data, 0, tag::SEQUENCE)?;
        let tbs = read_tagged(data, certificate.start, tag::SEQUENCE)?;

        // An explicit version is optional; skip it when present.
        let mut at = tbs.start;
        let first = read(data, at)?;
        if first.tag == tag::CONTEXT_0 {
            at = first.next;
        }

        let serial = read_tagged(data, at, tag::INTEGER)?;
        let signature = read_tagged(data, serial.next, tag::SEQUENCE)?;
        let issuer_at = signature.next;
        let issuer = read_tagged(data, issuer_at, tag::SEQUENCE)?;
        let validity = read_tagged(data, issuer.next, tag::SEQUENCE)?;
        let subject_at = validity.next;
        let subject = read_tagged(data, subject_at, tag::SEQUENCE)?;
        let spki = read_tagged(data, subject.next, tag::SEQUENCE)?;

        // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }
        let algorithm = read_tagged(data, spki.start, tag::SEQUENCE)?;
        let public_key = read_tagged(data, algorithm.next, tag::BIT_STRING)?;
        // The first content byte counts unused bits and is not part of the key.
        let subject_public_key = data
            .get(public_key.start + 1..public_key.end)
            .ok_or_else(|| malformed("empty subject public key"))?;

        Ok(Self {
            serial_number: serial.contents(data),
            issuer: issuer.element(data, issuer_at),
            subject: subject.element(data, subject_at),
            subject_public_key,
            subject_key_identifier: subject_key_identifier(data, &tbs, public_key.next)?,
            common_name: common_name(data, subject.contents(data)),
        })
    }

    /// `PublicKeyHash`: SHA-1 of the public key bits.
    ///
    /// Of the SubjectPublicKey BIT STRING contents, *not* of the whole
    /// SubjectPublicKeyInfo — checked against a certificate macOS imported.
    pub fn public_key_hash(&self) -> [u8; 20] {
        use sha1::Digest as _;
        sha1::Sha1::digest(self.subject_public_key).into()
    }
}

/// Walk the extensions for a subject key identifier.
fn subject_key_identifier<'a>(
    data: &'a [u8],
    tbs: &Tlv,
    mut at: usize,
) -> Result<Option<&'a [u8]>> {
    // The optional [1], [2] and [3] fields follow the public key.
    while at < tbs.end {
        let field = read(data, at)?;
        if field.tag != tag::CONTEXT_3 {
            at = field.next;
            continue;
        }

        let extensions = read_tagged(data, field.start, tag::SEQUENCE)?;
        let mut extension_at = extensions.start;
        while extension_at < extensions.end {
            let extension = read_tagged(data, extension_at, tag::SEQUENCE)?;
            let oid = read_tagged(data, extension.start, tag::OID)?;
            let mut value_at = oid.next;
            // An optional critical BOOLEAN may sit between the OID and the value.
            let value = loop {
                let next = read(data, value_at)?;
                if next.tag == tag::OCTET_STRING {
                    break next;
                }
                value_at = next.next;
                if value_at >= extension.end {
                    return Err(malformed("extension has no value"));
                }
            };

            if oid.contents(data) == OID_SUBJECT_KEY_IDENTIFIER {
                // The value is a DER OCTET STRING wrapping another one.
                let inner = read_tagged(data, value.start, tag::OCTET_STRING)?;
                return Ok(Some(inner.contents(data)));
            }
            extension_at = extension.next;
        }
        return Ok(None);
    }
    Ok(None)
}

/// The first `commonName` attribute value in a `Name`.
fn common_name(data: &[u8], name_contents: &[u8]) -> Option<String> {
    // Name ::= SEQUENCE OF RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
    let base = name_contents.as_ptr() as usize - data.as_ptr() as usize;
    let mut at = base;
    let end = base + name_contents.len();
    while at < end {
        let rdn = read(data, at).ok()?;
        if rdn.tag == tag::SET {
            let mut pair_at = rdn.start;
            while pair_at < rdn.end {
                let pair = read(data, pair_at).ok()?;
                let oid = read(data, pair.start).ok()?;
                if oid.tag == tag::OID && oid.contents(data) == OID_COMMON_NAME {
                    let value = read(data, oid.next).ok()?;
                    return Some(String::from_utf8_lossy(value.contents(data)).into_owned());
                }
                pair_at = pair.next;
            }
        }
        at = rdn.next;
    }
    None
}

/// A PKCS#8 `PrivateKeyInfo`, enough of it to describe the key.
#[derive(Debug, Clone)]
pub struct PrivateKeyInfo<'a> {
    /// The algorithm OID's content bytes.
    pub algorithm_oid: &'a [u8],
    /// The `privateKey` OCTET STRING contents: an `RSAPrivateKey` for RSA.
    pub private_key: &'a [u8],
}

/// `rsaEncryption` (1.2.840.113549.1.1.1).
pub const OID_RSA_ENCRYPTION: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// `id-ecPublicKey` (1.2.840.10045.2.1).
pub const OID_EC_PUBLIC_KEY: [u8; 7] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

impl<'a> PrivateKeyInfo<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let info = read_tagged(data, 0, tag::SEQUENCE)?;
        let version = read_tagged(data, info.start, tag::INTEGER)?;
        let algorithm = read_tagged(data, version.next, tag::SEQUENCE)?;
        let oid = read_tagged(data, algorithm.start, tag::OID)?;
        let key = read_tagged(data, algorithm.next, tag::OCTET_STRING)?;
        Ok(Self {
            algorithm_oid: oid.contents(data),
            private_key: key.contents(data),
        })
    }

    pub fn is_rsa(&self) -> bool {
        self.algorithm_oid == OID_RSA_ENCRYPTION
    }

    pub fn is_ec(&self) -> bool {
        self.algorithm_oid == OID_EC_PUBLIC_KEY
    }

    /// Key size in bits: the RSA modulus length, for an RSA key.
    ///
    /// `RSAPrivateKey ::= SEQUENCE { version, modulus, ... }`
    pub fn rsa_key_size_in_bits(&self) -> Result<u32> {
        if !self.is_rsa() {
            return Err(malformed("key size is only computed for RSA keys"));
        }
        let sequence = read_tagged(self.private_key, 0, tag::SEQUENCE)?;
        let version = read_tagged(self.private_key, sequence.start, tag::INTEGER)?;
        let modulus = read_tagged(self.private_key, version.next, tag::INTEGER)?;
        let bytes = modulus.contents(self.private_key);
        // DER integers are signed, so a leading zero pads a high bit.
        let significant = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len());
        Ok(((bytes.len() - significant) * 8) as u32)
    }
}

/// The DER inside the PEM block with the given label, when the input is PEM.
///
/// A file may hold a certificate and a key together — `kc export identity`
/// writes exactly that — so a caller that knows which half it wants says so.
/// Input that is not PEM is passed through as DER, and PEM without a matching
/// label falls back to the first block.
pub fn pem_block(data: &[u8], label: &str) -> Result<Vec<u8>> {
    let Ok(text) = std::str::from_utf8(data) else {
        return Ok(data.to_vec());
    };
    let begin = format!("-----BEGIN {label}-----");
    let Some(start) = text.find(&begin) else {
        return pem_or_der(data);
    };
    let body: String = text[start..]
        .lines()
        .skip(1)
        .take_while(|line| !line.starts_with("-----END"))
        .collect();
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|error| malformed(format!("invalid base64 in PEM: {error}")))
}

/// Decode PEM if the input looks like it, otherwise pass DER through.
///
/// Accepts any label, so a certificate, a `PRIVATE KEY` and an `RSA PRIVATE KEY`
/// all work; the caller checks what it actually got.
pub fn pem_or_der(data: &[u8]) -> Result<Vec<u8>> {
    let text = match std::str::from_utf8(data) {
        Ok(text) if text.contains("-----BEGIN") => text,
        // Not text, or no PEM header: treat it as DER.
        _ => return Ok(data.to_vec()),
    };

    let body: String = text
        .lines()
        .skip_while(|line| !line.starts_with("-----BEGIN"))
        .skip(1)
        .take_while(|line| !line.starts_with("-----END"))
        .collect();
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|error| malformed(format!("invalid base64 in PEM: {error}")))
}

/// Wrap DER in PEM, with the 64-column line wrapping every tool expects.
///
/// `label` is the part after `BEGIN`, such as `CERTIFICATE` or `PRIVATE KEY`.
pub fn to_pem(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// The PEM label for a certificate.
pub const PEM_CERTIFICATE: &str = "CERTIFICATE";

/// The PEM label for an unencrypted PKCS#8 private key.
pub const PEM_PRIVATE_KEY: &str = "PRIVATE KEY";

/// The PEM label for a PKCS#12/PFX container.
pub const PEM_PKCS12: &str = "PKCS12";

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed RSA certificate, the one used to check these fields against
    /// the record macOS wrote when it imported the matching identity.
    const CERTIFICATE: &str = concat!(
        "MIICzDCCAbQCCQDjBOPvAqI4rTANBgkqhkiG9w0BAQsFADAoMRkwFwYDVQQDDBBrYyBpZGVudGl0",
        "eSB0ZXN0MQswCQYDVQQKDAJrYzAeFw0yNjA3MjUxMjAzMTJaFw0zNjA3MjIxMjAzMTJaMCgxGTAX",
        "BgNVBAMMEGtjIGlkZW50aXR5IHRlc3QxCzAJBgNVBAoMAmtjMIIBIjANBgkqhkiG9w0BAQEFAAOC",
        "AQ8AMIIBCgKCAQEAovSsY3lsY/7mA8gwXu4KAiEgI2Gv4+nEifdtGQFOMOMPl7EG9mqZo3A7SD6B",
        "HyZFwGdfkZvP4uUXCM2z54EbV64FdpyFGll96yIgW6nTy7WOHHL3s8myi1uWVWd0hfxYnJ9FRimV",
        "o4Y6mQK6anZs/WeiUKR+nQYSydYiCYJEzRY7xZVrSDrd2gcxzQ14okhx7VoWKN3pJhpT5Ot6HnvZ",
        "PUTPpacEEXDNnHSVlOF5wK1rAejp8X7FOgqBfbNKY8WJgPbtOqY5luv72PbBWJ4ueFLc3LlbQOVe",
        "GFqyIV4JqlADewaHNV4E1ZRHG369fZuHC/3/mWmHbphRBwz4ZyNZ1QIDAQABMA0GCSqGSIb3DQEB",
        "CwUAA4IBAQBXNRJTBjM45WJb/8yJyBF7VplpoV0UAUdLoEGV4u7yOZ0E4CVixq7WIy0Z443EtFjc",
        "0j5reSenUntTkDL82YlhRJQW0swfDuapNquBz/HD3GZviPzVboI7hgpimZdKV085iS3OmYP++HM4",
        "iZWFXA4FqQmZMa8BqArugAroPM2HH3/1ZmskhibcAaXx5zBK2kHAAMo9eFHujEaGyQaHMQKeyUNo",
        "aQmcoSi099cPIyLD1DJ2G2ue1WSZVqKNEvZ6ueXKLOT9pO8rKlKD3QRCdaV2hpxn4o+6h8c7/o86",
        "JkwsmuiKjVzhZLc3d0/r9OsTObFwOhBDzb0dyX581TQEOd0l",
    );

    fn certificate() -> Vec<u8> {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(CERTIFICATE)
            .unwrap()
    }

    #[test]
    fn a_labelled_block_is_picked_out_of_a_bundle() {
        let certificate: Vec<u8> = (0..40u32).map(|byte| byte as u8).collect();
        let key: Vec<u8> = (100..160u32).map(|byte| byte as u8).collect();
        let mut bundle = to_pem(PEM_CERTIFICATE, &certificate);
        bundle.push_str(&to_pem(PEM_PRIVATE_KEY, &key));

        assert_eq!(
            pem_block(bundle.as_bytes(), PEM_CERTIFICATE).expect("cert"),
            certificate
        );
        assert_eq!(
            pem_block(bundle.as_bytes(), PEM_PRIVATE_KEY).expect("key"),
            key
        );
        // A label that is not there falls back to the first block, and raw DER
        // passes through untouched.
        assert_eq!(
            pem_block(bundle.as_bytes(), "SOMETHING ELSE").expect("fallback"),
            certificate
        );
        assert_eq!(pem_block(&key, PEM_PRIVATE_KEY).expect("der"), key);
    }

    #[test]
    fn pem_round_trips_through_the_decoder() {
        // Long enough to need wrapping, so the line breaks are exercised.
        let der: Vec<u8> = (0..200u32).map(|byte| byte as u8).collect();
        let pem = to_pem(PEM_CERTIFICATE, &der);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        assert!(
            pem.lines()
                .skip(1)
                .take_while(|l| !l.starts_with("-----"))
                .all(|l| l.len() <= 64),
            "lines are wrapped"
        );
        assert_eq!(pem_or_der(pem.as_bytes()).expect("decode"), der);
    }

    #[test]
    fn certificate_fields_match_the_record_macos_wrote() {
        let der = certificate();
        let parsed = Certificate::parse(&der).unwrap();

        // Every expected value here is what macOS stored in the certificate
        // record when it imported this identity.
        assert_eq!(hex::encode(parsed.serial_number), "00e304e3ef02a238ad");
        assert_eq!(parsed.subject.len(), 42);
        assert_eq!(parsed.issuer, parsed.subject, "self-signed");
        assert_eq!(
            hex::encode(&parsed.subject[..24]),
            "30283119301706035504030c106b63206964656e74697479"
        );
        assert_eq!(
            hex::encode(parsed.public_key_hash()),
            "665e69a00dd3a6d68498c89ef3263702a475066d"
        );
        assert_eq!(
            parsed.subject_key_identifier, None,
            "this certificate has no SKI"
        );
        assert_eq!(parsed.common_name.as_deref(), Some("kc identity test"));
    }

    #[test]
    fn the_public_key_hash_covers_the_bit_string_not_the_whole_spki() {
        use sha1::Digest as _;
        let der = certificate();
        let parsed = Certificate::parse(&der).unwrap();

        // A 2048-bit RSA key: the BIT STRING holds a 270-byte RSAPublicKey.
        assert_eq!(parsed.subject_public_key.len(), 270);
        assert_eq!(
            parsed.subject_public_key[0], 0x30,
            "an RSAPublicKey SEQUENCE"
        );
        // Hashing the enclosing SubjectPublicKeyInfo gives a different answer,
        // which is the mistake this pins down.
        let spki_hash: [u8; 20] = sha1::Sha1::digest(&der[..]).into();
        assert_ne!(parsed.public_key_hash(), spki_hash);
    }

    #[test]
    fn lengths_are_read_in_both_short_and_long_form() {
        // Short form: one length byte.
        let short = [0x02u8, 0x01, 0x07];
        let tlv = read(&short, 0).unwrap();
        assert_eq!(tlv.tag, tag::INTEGER);
        assert_eq!(tlv.contents(&short), &[0x07]);

        // Long form: 0x82 means two length bytes follow.
        let mut long = vec![0x04u8, 0x82, 0x01, 0x00];
        long.extend(std::iter::repeat_n(0xabu8, 256));
        let tlv = read(&long, 0).unwrap();
        assert_eq!(tlv.len(), 256);
        assert_eq!(tlv.next, 260);
    }

    #[test]
    fn malformed_input_is_an_error_not_a_panic() {
        assert!(read(&[], 0).is_err());
        assert!(read(&[0x30], 0).is_err());
        assert!(read(&[0x30, 0x05, 0x00], 0).is_err(), "length past the end");
        assert!(
            read(&[0x30, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0).is_err(),
            "9-byte length"
        );
        assert!(Certificate::parse(b"not a certificate").is_err());
        assert!(PrivateKeyInfo::parse(&[0x30, 0x00]).is_err());
    }

    #[test]
    fn a_pkcs8_key_that_is_not_a_key_is_rejected() {
        // Real keys are exercised in `tests/keychain_identity.rs`, against ones
        // openssl generates; here only the failure paths.
        assert!(PrivateKeyInfo::parse(&[]).is_err());
        assert!(PrivateKeyInfo::parse(&[0x30, 0x03, 0x02, 0x01, 0x00]).is_err());

        let certificate = certificate();
        // A certificate is a SEQUENCE too, but not a PrivateKeyInfo.
        assert!(PrivateKeyInfo::parse(&certificate).is_err());
    }

    #[test]
    fn pem_and_der_are_both_accepted() {
        let der = certificate();
        assert_eq!(pem_or_der(&der).unwrap(), der, "DER passes through");

        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&der);
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            encoded
                .as_bytes()
                .chunks(64)
                .map(|line| String::from_utf8_lossy(line).into_owned())
                .collect::<Vec<_>>()
                .join("\n")
        );
        assert_eq!(pem_or_der(pem.as_bytes()).unwrap(), der);

        // Junk that claims to be PEM is an error rather than silent garbage.
        assert!(
            pem_or_der(b"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----").is_err()
        );
    }
}
