//! Decode an identity from a PKCS#12/PFX container.
//!
//! The decoder is pure Rust and returns the same DER certificate and PKCS#8
//! private-key representation that [`crate::write::NewIdentity`] accepts.

use p12_keystore::{
    Certificate as Pkcs12Certificate, KeyStore, KeyStoreEntry, Pkcs12ImportPolicy, PrivateKey,
    PrivateKeyChain,
};

use crate::{Error, Result};

/// One certificate/private-key pair decoded from a PKCS#12 container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The leaf X.509 certificate, DER-encoded.
    pub certificate: Vec<u8>,
    /// The matching private key as a PKCS#8 `PrivateKeyInfo`, DER-encoded.
    pub private_key: Vec<u8>,
    /// The PKCS#12 friendly name, when one was present.
    pub friendly_name: Option<String>,
}

/// Decode the single identity in a PKCS#12/PFX container.
///
/// Certificate-only entries and certificates forming the selected identity's
/// chain are ignored. Containers with no identity or more than one identity
/// are refused rather than selecting one implicitly.
pub fn decode(data: &[u8], password: &str) -> Result<Identity> {
    let store = KeyStore::from_pkcs12(data, password, Pkcs12ImportPolicy::Strict).map_err(
        |error| {
            Error::other(format!(
                "could not decode PKCS#12 (the password may be wrong, or the container uses an unsupported algorithm): {error}"
            ))
        },
    )?;

    let mut identities = store.entries().filter_map(|(alias, entry)| match entry {
        KeyStoreEntry::PrivateKeyChain(chain) => Some((alias, chain)),
        _ => None,
    });
    let Some((alias, chain)) = identities.next() else {
        return Err(Error::other(
            "the PKCS#12 container has no private key with a matching certificate",
        ));
    };
    if identities.next().is_some() {
        return Err(Error::other(
            "the PKCS#12 container contains more than one identity",
        ));
    }
    let certificate = chain
        .certs()
        .first()
        .ok_or_else(|| Error::other("the PKCS#12 private key has no matching leaf certificate"))?;

    Ok(Identity {
        certificate: certificate.as_der().to_vec(),
        private_key: chain.key().as_der().to_vec(),
        friendly_name: (!alias.is_empty()).then(|| alias.to_string()),
    })
}

/// Encode one identity as a DER PKCS#12/PFX container.
pub fn encode(identity: &Identity, password: &str) -> Result<Vec<u8>> {
    let certificate = Pkcs12Certificate::from_der(&identity.certificate)
        .map_err(|error| Error::other(format!("could not encode PKCS#12 certificate: {error}")))?;
    let private_key = PrivateKey::from_der(&identity.private_key)
        .map_err(|error| Error::other(format!("could not encode PKCS#12 private key: {error}")))?;
    let public_key_hash = crate::der::Certificate::parse(&identity.certificate)?.public_key_hash();
    let alias = identity.friendly_name.as_deref().unwrap_or("identity");
    let chain = PrivateKeyChain::new(public_key_hash.as_slice(), private_key, [certificate]);
    let mut store = KeyStore::new();
    store.add_entry(alias, KeyStoreEntry::PrivateKeyChain(chain));
    store
        .writer(password)
        .write()
        .map_err(|error| Error::other(format!("could not encode PKCS#12: {error}")))
}
