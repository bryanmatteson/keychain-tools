//! SRP-6a session against the Passwords helper.
//!
//! RFC 5054 group `G_3072` (`g = 5`) with SHA-256, per RFC 2945:
//!
//! ```text
//! x    = H(s | H(I | ":" | PIN))
//! u    = H(PAD(A) | PAD(B))
//! k    = H(N | PAD(g))
//! S    = (B - k * g^x) ^ (a + u * x) mod N
//! K    = H(S)
//! M    = H(H(N) XOR H(PAD(g)) | H(I) | s | A | B | K)
//! HAMK = H(A | M | K)
//! ```
//!
//! `I` is not a user name in any meaningful sense: it is 16 random bytes,
//! serialized, generated per session. The PIN is the six digits macOS displays
//! when the handshake starts.
//!
//! Every value fed to a hash uses minimal-length big-endian bytes except inside
//! `u` and `k`, where `PAD()` widens to the 384-byte group size.

use num_bigint::BigUint;
use std::sync::LazyLock;

use crate::crypto::{self, SecretBytes};
use crate::error::{Error, Result};

/// RFC 5054 appendix A, 3072-bit group.
const GROUP_PRIME_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08",
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B",
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9",
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6",
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8",
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D",
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C",
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D",
    "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D",
    "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226",
    "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C",
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC",
    "E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
);

/// Group size in bytes: the width `PAD()` targets.
pub const GROUP_PRIME_LEN: usize = 3072 / 8;

static GROUP_PRIME: LazyLock<BigUint> = LazyLock::new(|| {
    BigUint::parse_bytes(GROUP_PRIME_HEX.as_bytes(), 16).expect("group prime is valid hex")
});

static GROUP_GENERATOR: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(5u32));

/// How the helper wants binary values represented in JSON.
///
/// macOS 14+ negotiates base64 (`shouldUseBase64` in the capabilities reply);
/// the hex form with an `0x` prefix is what older iCloud for Windows builds use.
/// Only base64 is exercised against a live helper here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Encoding {
    #[default]
    Base64,
    Hex,
}

impl Encoding {
    /// `prefix` adds the `0x` marker in hex mode; base64 ignores it.
    pub fn encode(self, bytes: &[u8], prefix: bool) -> String {
        match self {
            Self::Base64 => {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode(bytes)
            }
            Self::Hex if prefix => format!("0x{}", hex::encode(bytes)),
            Self::Hex => hex::encode(bytes),
        }
    }

    pub fn decode(self, text: &str) -> Result<Vec<u8>> {
        match self {
            Self::Base64 => {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD
                    .decode(text)
                    .map_err(|_| Error::protocol("value is not valid base64"))
            }
            Self::Hex => hex::decode(text.strip_prefix("0x").unwrap_or(text))
                .map_err(|_| Error::protocol("value is not valid hex")),
        }
    }
}

/// One SRP-6a session: either mid-handshake, or holding a key that can encrypt.
#[derive(Debug)]
pub struct SrpSession {
    encoding: Encoding,
    /// `I`, already in wire form.
    username: String,
    /// `a`, the client ephemeral private key.
    client_private: BigUint,
    /// `B`, learned from the server hello.
    server_public: Option<BigUint>,
    /// `s`, learned from the server hello.
    salt: Option<BigUint>,
    /// `K`, the shared key; present once the PIN has been verified.
    shared_key: Option<BigUint>,
}

impl SrpSession {
    /// Start a fresh handshake with a random identity and ephemeral key.
    pub fn new(encoding: Encoding) -> Self {
        let username = encoding.encode(&crypto::random_bytes(16), true);
        let client_private = crypto::from_bytes_be(&crypto::random_bytes(32));
        Self {
            encoding,
            username,
            client_private,
            server_public: None,
            salt: None,
            shared_key: None,
        }
    }

    /// Reload an authenticated session from stored credentials.
    pub fn restore(encoding: Encoding, username: String, shared_key: BigUint) -> Self {
        Self {
            encoding,
            username,
            client_private: BigUint::ZERO,
            server_public: None,
            salt: None,
            shared_key: Some(shared_key),
        }
    }

    /// Reload a handshake that was started by an earlier process.
    pub fn resume_handshake(
        encoding: Encoding,
        username: String,
        client_private: BigUint,
        server_public: BigUint,
        salt: BigUint,
    ) -> Self {
        Self {
            encoding,
            username,
            client_private,
            server_public: Some(server_public),
            salt: Some(salt),
            shared_key: None,
        }
    }

    pub fn encoding(&self) -> Encoding {
        self.encoding
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn has_shared_key(&self) -> bool {
        self.shared_key.is_some()
    }

    pub fn shared_key(&self) -> Option<&BigUint> {
        self.shared_key.as_ref()
    }

    /// The ephemeral private key `a`. Only for handing a half-finished handshake
    /// to the process that will complete it; never persist this alongside `K`.
    pub fn client_private(&self) -> &BigUint {
        &self.client_private
    }

    pub fn server_public(&self) -> Option<&BigUint> {
        self.server_public.as_ref()
    }

    pub fn salt(&self) -> Option<&BigUint> {
        self.salt.as_ref()
    }

    /// `A = g^a mod N`
    pub fn client_public(&self) -> BigUint {
        GROUP_GENERATOR.modpow(&self.client_private, &GROUP_PRIME)
    }

    /// Serialize using this session's encoding.
    pub fn encode(&self, bytes: &[u8], prefix: bool) -> String {
        self.encoding.encode(bytes, prefix)
    }

    pub fn decode(&self, text: &str) -> Result<Vec<u8>> {
        self.encoding.decode(text)
    }

    /// Record `B` and `s` from the server hello.
    pub fn set_server_hello(&mut self, server_public: BigUint, salt: BigUint) -> Result<()> {
        if &server_public % &*GROUP_PRIME == BigUint::ZERO {
            return Err(Error::protocol(
                "server public key is a multiple of the group prime",
            ));
        }
        self.server_public = Some(server_public);
        self.salt = Some(salt);
        Ok(())
    }

    /// Derive `K` from the PIN. Returns a reference-free copy for persistence.
    pub fn derive_shared_key(&mut self, pin: &str) -> Result<BigUint> {
        let server_public = self.server_public.as_ref().ok_or(Error::Crypto(
            "handshake state is missing the server public key",
        ))?;
        let salt = self
            .salt
            .as_ref()
            .ok_or(Error::Crypto("handshake state is missing the salt"))?;

        let n = &*GROUP_PRIME;
        let client_public = self.client_public();

        let u = compute_u(&client_public, server_public);
        let k = compute_k();
        let x = compute_x(&self.username, pin, salt);

        // S = (B - k * g^x) ^ (a + u * x) mod N, with the subtraction taken in
        // the group so the base stays non-negative.
        let base = (k * GROUP_GENERATOR.modpow(&x, n)) % n;
        let base = ((n + server_public) - base) % n;
        let exponent = &self.client_private + &u * &x;
        let premaster = base.modpow(&exponent, n);

        let shared_key = compute_shared_key(&premaster);
        self.shared_key = Some(shared_key.clone());
        Ok(shared_key)
    }

    /// `M = H(H(N) XOR H(PAD(g)) | H(I) | s | A | B | K)`
    pub fn compute_m(&self) -> Result<[u8; 32]> {
        let server_public = self.server_public.as_ref().ok_or(Error::Crypto(
            "handshake state is missing the server public key",
        ))?;
        let salt = self
            .salt
            .as_ref()
            .ok_or(Error::Crypto("handshake state is missing the salt"))?;
        let shared_key = self
            .shared_key
            .as_ref()
            .ok_or(Error::Crypto("handshake state is missing the shared key"))?;

        Ok(compute_m(
            &self.username,
            salt,
            &self.client_public(),
            server_public,
            shared_key,
        ))
    }

    /// `HAMK = H(A | M | K)`, the server's proof back to us.
    pub fn compute_hamk(&self, m: &[u8]) -> Result<[u8; 32]> {
        let shared_key = self
            .shared_key
            .as_ref()
            .ok_or(Error::Crypto("handshake state is missing the shared key"))?;

        Ok(compute_hamk(&self.client_public(), m, shared_key))
    }

    fn aes_key(&self) -> Result<SecretBytes> {
        let shared_key = self.shared_key.as_ref().ok_or(Error::NoSession)?;
        crypto::aes_key(shared_key)
    }

    /// Encrypt a JSON-serializable request body.
    pub fn seal(&self, value: &impl serde::Serialize) -> Result<Vec<u8>> {
        let plaintext = serde_json::to_vec(value)?;
        crypto::seal(&self.aes_key()?, &plaintext)
    }

    /// Decrypt a response body.
    pub fn open(&self, data: &[u8]) -> Result<Vec<u8>> {
        crypto::open(&self.aes_key()?, data)
    }
}

// ---------------------------------------------------------------------------
// Shared steps
// ---------------------------------------------------------------------------

/// `u = H(PAD(A) | PAD(B))`
fn compute_u(client_public: &BigUint, server_public: &BigUint) -> BigUint {
    crypto::from_bytes_be(&crypto::sha256(&[
        &crypto::pad_left(&crypto::to_bytes_be(client_public), GROUP_PRIME_LEN),
        &crypto::pad_left(&crypto::to_bytes_be(server_public), GROUP_PRIME_LEN),
    ]))
}

/// `k = H(N | PAD(g))`. Note `N` is not padded: it is already the group width.
fn compute_k() -> BigUint {
    crypto::from_bytes_be(&crypto::sha256(&[
        &crypto::to_bytes_be(&GROUP_PRIME),
        &crypto::pad_left(&crypto::to_bytes_be(&GROUP_GENERATOR), GROUP_PRIME_LEN),
    ]))
}

/// `x = H(s | H(I | ":" | PIN))`
fn compute_x(username: &str, pin: &str, salt: &BigUint) -> BigUint {
    let identity_hash = crypto::sha256(&[username.as_bytes(), b":", pin.as_bytes()]);
    crypto::from_bytes_be(&crypto::sha256(&[
        &crypto::to_bytes_be(salt),
        &identity_hash,
    ]))
}

/// `K = H(S)`
fn compute_shared_key(premaster: &BigUint) -> BigUint {
    crypto::from_bytes_be(&crypto::sha256(&[&crypto::to_bytes_be(premaster)]))
}

/// `M = H(H(N) XOR H(PAD(g)) | H(I) | s | A | B | K)`
fn compute_m(
    username: &str,
    salt: &BigUint,
    client_public: &BigUint,
    server_public: &BigUint,
    shared_key: &BigUint,
) -> [u8; 32] {
    let n_hash = crypto::sha256(&[&crypto::to_bytes_be(&GROUP_PRIME)]);
    let g_hash = crypto::sha256(&[&crypto::pad_left(
        &crypto::to_bytes_be(&GROUP_GENERATOR),
        GROUP_PRIME_LEN,
    )]);
    let mut group_hash = [0u8; 32];
    for (index, slot) in group_hash.iter_mut().enumerate() {
        *slot = n_hash[index] ^ g_hash[index];
    }

    crypto::sha256(&[
        &group_hash,
        &crypto::sha256(&[username.as_bytes()]),
        &crypto::to_bytes_be(salt),
        &crypto::to_bytes_be(client_public),
        &crypto::to_bytes_be(server_public),
        &crypto::to_bytes_be(shared_key),
    ])
}

/// `HAMK = H(A | M | K)`
fn compute_hamk(client_public: &BigUint, m: &[u8], shared_key: &BigUint) -> [u8; 32] {
    crypto::sha256(&[
        &crypto::to_bytes_be(client_public),
        m,
        &crypto::to_bytes_be(shared_key),
    ])
}

/// Constant-time byte comparison for proof values.
fn proofs_match(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

/// The verifier's side of the handshake — what the Passwords helper computes.
///
/// Present so the client can be exercised end-to-end without Apple's binary
/// (which requires a human to read a PIN off the screen), and because it states
/// the protocol precisely enough to check the client against.
#[derive(Debug)]
pub struct SrpServer {
    encoding: Encoding,
    username: String,
    salt: BigUint,
    /// `v = g^x mod N`
    verifier: BigUint,
    /// `b`, the server ephemeral private key.
    server_private: BigUint,
    /// `A`, remembered from the key exchange: the verification message that
    /// follows does not repeat it.
    client_public: Option<BigUint>,
    shared_key: Option<BigUint>,
}

impl SrpServer {
    /// Set up a challenge for `username` protected by `pin`, with a random salt.
    pub fn new(encoding: Encoding, username: &str, pin: &str) -> Self {
        let salt = crypto::from_bytes_be(&crypto::random_bytes(16));
        Self::with_salt(encoding, username, pin, salt)
    }

    pub fn with_salt(encoding: Encoding, username: &str, pin: &str, salt: BigUint) -> Self {
        let x = compute_x(username, pin, &salt);
        Self {
            encoding,
            username: username.to_string(),
            verifier: GROUP_GENERATOR.modpow(&x, &GROUP_PRIME),
            salt,
            server_private: crypto::from_bytes_be(&crypto::random_bytes(32)),
            client_public: None,
            shared_key: None,
        }
    }

    pub fn encoding(&self) -> Encoding {
        self.encoding
    }

    pub fn salt(&self) -> &BigUint {
        &self.salt
    }

    /// `B = k * v + g^b mod N`
    pub fn server_public(&self) -> BigUint {
        let n = &*GROUP_PRIME;
        ((compute_k() * &self.verifier) % n + GROUP_GENERATOR.modpow(&self.server_private, n)) % n
    }

    /// Derive `K` from the client's `A`: `S = (A * v^u) ^ b mod N`.
    pub fn derive_shared_key(&mut self, client_public: &BigUint) -> Result<BigUint> {
        let n = &*GROUP_PRIME;
        if client_public % n == BigUint::ZERO {
            return Err(Error::protocol(
                "client public key is a multiple of the group prime",
            ));
        }
        let u = compute_u(client_public, &self.server_public());
        let base = (client_public * self.verifier.modpow(&u, n)) % n;
        let premaster = base.modpow(&self.server_private, n);

        let shared_key = compute_shared_key(&premaster);
        self.client_public = Some(client_public.clone());
        self.shared_key = Some(shared_key.clone());
        Ok(shared_key)
    }

    /// Check the client's proof `M` and return the `HAMK` to send back.
    pub fn verify_client(&self, m: &[u8]) -> Result<[u8; 32]> {
        let (Some(client_public), Some(shared_key)) = (&self.client_public, &self.shared_key)
        else {
            return Err(Error::Crypto("server has not derived the shared key yet"));
        };
        let expected = compute_m(
            &self.username,
            &self.salt,
            client_public,
            &self.server_public(),
            shared_key,
        );
        if !proofs_match(m, &expected) {
            return Err(Error::IncorrectPin);
        }
        Ok(compute_hamk(client_public, m, shared_key))
    }

    fn aes_key(&self) -> Result<SecretBytes> {
        crypto::aes_key(self.shared_key.as_ref().ok_or(Error::NoSession)?)
    }

    /// Encrypt a reply body, in the shape the client expects
    /// (`iv || ciphertext || tag`).
    pub fn seal_reply(&self, value: &impl serde::Serialize) -> Result<Vec<u8>> {
        let plaintext = serde_json::to_vec(value)?;
        let sealed = crypto::seal(&self.aes_key()?, &plaintext)?;
        let (body, iv) = sealed.split_at(sealed.len() - crypto::IV_LEN);
        let mut reply = iv.to_vec();
        reply.extend_from_slice(body);
        Ok(reply)
    }

    /// Decrypt a request body (`ciphertext || tag || iv`).
    pub fn open_request(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() <= crypto::IV_LEN {
            return Err(Error::Crypto("encrypted payload is too short"));
        }
        let (body, iv) = data.split_at(data.len() - crypto::IV_LEN);
        let mut reordered = iv.to_vec();
        reordered.extend_from_slice(body);
        crypto::open(&self.aes_key()?, &reordered)
    }

    pub fn encode(&self, bytes: &[u8], prefix: bool) -> String {
        self.encoding.encode(bytes, prefix)
    }

    pub fn decode(&self, text: &str) -> Result<Vec<u8>> {
        self.encoding.decode(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_prime_is_384_bytes_and_odd() {
        let bytes = crypto::to_bytes_be(&GROUP_PRIME);
        assert_eq!(bytes.len(), GROUP_PRIME_LEN);
        assert_eq!(bytes[0], 0xff);
        assert_eq!(bytes[bytes.len() - 1], 0xff);
    }

    #[test]
    fn encoding_round_trips() {
        let bytes = vec![0x00, 0x01, 0xfe, 0xff];
        for encoding in [Encoding::Base64, Encoding::Hex] {
            let text = encoding.encode(&bytes, true);
            assert_eq!(encoding.decode(&text).unwrap(), bytes);
        }
        assert_eq!(Encoding::Hex.encode(&bytes, true), "0x0001feff");
        assert_eq!(Encoding::Hex.encode(&bytes, false), "0001feff");
        assert_eq!(Encoding::Base64.encode(&[0xff, 0xff], true), "//8=");
    }

    #[test]
    fn new_session_identity_is_sixteen_random_bytes() {
        let session = SrpSession::new(Encoding::Base64);
        assert_eq!(
            Encoding::Base64.decode(session.username()).unwrap().len(),
            16
        );
        assert!(!session.has_shared_key());

        let other = SrpSession::new(Encoding::Base64);
        assert_ne!(session.username(), other.username());
        assert_ne!(session.client_public(), other.client_public());
    }

    #[test]
    fn server_hello_rejects_degenerate_public_key() {
        let mut session = SrpSession::new(Encoding::Base64);
        assert!(
            session
                .set_server_hello(GROUP_PRIME.clone(), BigUint::from(1u8))
                .is_err()
        );
        assert!(
            session
                .set_server_hello(BigUint::ZERO, BigUint::from(1u8))
                .is_err()
        );
        assert!(
            session
                .set_server_hello(BigUint::from(2u8), BigUint::from(1u8))
                .is_ok()
        );
    }

    #[test]
    fn sealing_without_a_key_reports_no_session() {
        let session = SrpSession::new(Encoding::Base64);
        assert!(matches!(
            session.seal(&serde_json::json!({})),
            Err(Error::NoSession)
        ));
    }

    /// Full handshake against the server side, both proofs checked.
    #[test]
    fn handshake_agrees_with_a_server_that_knows_the_pin() {
        let pin = "482915";
        let mut session = SrpSession::new(Encoding::Base64);
        let mut server = SrpServer::new(Encoding::Base64, session.username(), pin);

        session
            .set_server_hello(server.server_public(), server.salt().clone())
            .unwrap();
        let client_key = session.derive_shared_key(pin).unwrap();
        let server_key = server.derive_shared_key(&session.client_public()).unwrap();
        assert_eq!(
            client_key, server_key,
            "client and server derived different keys"
        );

        // The server accepts the client's proof, and the client accepts the
        // server's proof back.
        let m = session.compute_m().unwrap();
        let hamk = server.verify_client(&m).unwrap();
        assert_eq!(session.compute_hamk(&m).unwrap(), hamk);
    }

    #[test]
    fn a_wrong_pin_fails_verification() {
        let mut session = SrpSession::new(Encoding::Base64);
        let mut server = SrpServer::new(Encoding::Base64, session.username(), "482915");

        session
            .set_server_hello(server.server_public(), server.salt().clone())
            .unwrap();
        let wrong_key = session.derive_shared_key("000000").unwrap();
        let server_key = server.derive_shared_key(&session.client_public()).unwrap();

        assert_ne!(wrong_key, server_key);
        let m = session.compute_m().unwrap();
        assert!(matches!(server.verify_client(&m), Err(Error::IncorrectPin)));
    }

    #[test]
    fn each_side_reads_what_the_other_sealed() {
        let pin = "135790";
        let mut session = SrpSession::new(Encoding::Base64);
        let mut server = SrpServer::new(Encoding::Base64, session.username(), pin);
        session
            .set_server_hello(server.server_public(), server.salt().clone())
            .unwrap();
        session.derive_shared_key(pin).unwrap();
        server.derive_shared_key(&session.client_public()).unwrap();

        let request = session
            .seal(&serde_json::json!({ "ACT": 5, "URL": "example.com" }))
            .unwrap();
        let opened: serde_json::Value =
            serde_json::from_slice(&server.open_request(&request).unwrap()).unwrap();
        assert_eq!(opened["URL"], "example.com");

        let reply = server
            .seal_reply(&serde_json::json!({ "STATUS": 0 }))
            .unwrap();
        let opened: serde_json::Value =
            serde_json::from_slice(&session.open(&reply).unwrap()).unwrap();
        assert_eq!(opened["STATUS"], 0);
    }

    #[test]
    fn server_rejects_a_degenerate_client_public_key() {
        let mut server = SrpServer::new(Encoding::Base64, "user", "482915");
        assert!(server.derive_shared_key(&GROUP_PRIME.clone()).is_err());
        assert!(server.derive_shared_key(&BigUint::ZERO).is_err());
    }

    #[test]
    fn server_refuses_to_verify_before_deriving_a_key() {
        let server = SrpServer::new(Encoding::Base64, "user", "482915");
        assert!(server.verify_client(&[0u8; 32]).is_err());
        assert!(matches!(
            server.seal_reply(&serde_json::json!({})),
            Err(Error::NoSession)
        ));
    }

    #[test]
    fn a_fixed_salt_makes_the_server_reproducible() {
        let salt = crypto::from_bytes_be(&[0x5c; 16]);
        let first = SrpServer::with_salt(Encoding::Base64, "user", "482915", salt.clone());
        let second = SrpServer::with_salt(Encoding::Base64, "user", "482915", salt);
        // Same verifier, but independent ephemeral keys.
        assert_eq!(first.verifier, second.verifier);
        assert_ne!(first.server_public(), second.server_public());
    }

    #[test]
    fn resumed_handshake_reproduces_the_original_public_key() {
        let session = SrpSession::new(Encoding::Base64);
        let resumed = SrpSession::resume_handshake(
            Encoding::Base64,
            session.username().to_string(),
            session.client_private().clone(),
            BigUint::from(7u8),
            BigUint::from(9u8),
        );
        assert_eq!(session.client_public(), resumed.client_public());
    }
}
