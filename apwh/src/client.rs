//! The client half: SRP handshake, then encrypted requests through the service.
//!
//! Every request is sealed with the session key before it leaves this process
//! and every reply is opened here, so the service (and anything else on the
//! socket) only ever handles ciphertext.

use serde_json::Value;
use std::io::ErrorKind;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use crate::config::{Config, Paths, PendingAuth};
use crate::crypto;
use crate::entries::Payload;
use crate::error::{Error, Result};
use crate::frame::{read_frame, write_frame};
use crate::protocol::{Capabilities, Messages, MsgType, Request, Response, ServerPake};
use crate::srp::{Encoding, SrpSession};

/// How long to wait for the service to answer. The service gives the helper 30
/// seconds, so this has to be longer or a slow helper looks like a dead socket.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(40);

/// Request/response transport over the service's Unix socket.
#[derive(Debug, Clone)]
pub struct Transport {
    socket: PathBuf,
    timeout: Duration,
}

impl Transport {
    pub fn new(socket: PathBuf, timeout: Duration) -> Self {
        Self { socket, timeout }
    }

    pub fn socket(&self) -> &PathBuf {
        &self.socket
    }

    /// True if something is listening. Used by `apwh status`.
    pub fn is_listening(&self) -> bool {
        UnixStream::connect(&self.socket).is_ok()
    }

    pub fn send(&self, request: &Request) -> Result<Response> {
        crate::config::validate_socket_path(&self.socket)?;
        let mut stream =
            UnixStream::connect(&self.socket).map_err(|source| Error::ServiceUnavailable {
                path: self.socket.clone(),
                source,
            })?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;

        let body = serde_json::to_vec(request)?;
        self.map_timeout(write_frame(&mut stream, &body))?;

        let reply = self
            .map_timeout(read_frame(&mut stream))?
            .ok_or_else(|| Error::protocol("the service closed the connection without replying"))?;
        let response: Response = serde_json::from_slice(&reply)?;

        if let Some(error) = &response.error {
            return Err(match error.as_str() {
                "timeout" => Error::Timeout(self.timeout),
                "helper-exited" => Error::HelperExited,
                other => Error::protocol(other.to_string()),
            });
        }
        Ok(response)
    }

    fn map_timeout<T>(&self, result: std::io::Result<T>) -> Result<T> {
        result.map_err(|source| match source.kind() {
            ErrorKind::WouldBlock | ErrorKind::TimedOut => Error::Timeout(self.timeout),
            _ => Error::io("service connection failed", source),
        })
    }
}

/// High-level access to Apple Passwords.
pub struct PasswordsClient {
    transport: Transport,
    paths: Paths,
    config: Config,
    session: Option<SrpSession>,
}

impl PasswordsClient {
    /// Load stored state and prepare to talk to the service.
    pub fn open(paths: Paths, timeout: Duration) -> Result<Self> {
        let config = Config::load(&paths.config())?;
        let session = config.session()?;
        let transport = Transport::new(paths.socket.clone(), timeout);
        Ok(Self {
            transport,
            paths,
            config,
            session,
        })
    }

    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// True once a PIN has been verified and a key is stored.
    pub fn is_authenticated(&self) -> bool {
        self.session
            .as_ref()
            .is_some_and(SrpSession::has_shared_key)
    }

    /// Ask the helper what it supports. Works without a session.
    pub fn capabilities(&self) -> Result<CapabilitiesReply> {
        let response = self.transport.send(&Messages::get_capabilities())?;

        // The field has been seen at the top level and nested under `payload`;
        // accept either, and keep the raw document for `--raw`.
        let raw = response
            .payload
            .clone()
            .unwrap_or_else(|| serde_json::to_value(&response.capabilities).unwrap_or(Value::Null));
        let capabilities = match response.capabilities {
            Some(capabilities) => capabilities,
            None => match &response.payload {
                Some(payload) => payload
                    .get("capabilities")
                    .cloned()
                    .map(serde_json::from_value)
                    .unwrap_or_else(|| serde_json::from_value(payload.clone()))
                    .unwrap_or_default(),
                None => Capabilities::default(),
            },
        };
        Ok(CapabilitiesReply { capabilities, raw })
    }

    /// Start a handshake: send `A`, receive `B` and `s`. macOS shows the PIN.
    ///
    /// Discards any existing session, since a handshake replaces it.
    pub fn begin_auth(&mut self) -> Result<()> {
        let encoding = self.negotiated_encoding();
        let mut session = SrpSession::new(encoding);
        let request = Messages::request_challenge(&session, self.config.browser())?;
        let response = self.transport.send(&request)?;
        let hello = response.handshake()?;

        self.check_identity(&hello, &session, "hello")?;
        if let Some(code) = hello.err_code.filter(|code| *code != 0) {
            return Err(Error::protocol(format!(
                "server hello reported error code {code}"
            )));
        }
        if !hello.is_stage(MsgType::ServerKeyExchange) {
            return Err(Error::protocol(
                "server hello is not a key exchange message",
            ));
        }
        if hello.proto != Some(1) {
            return Err(Error::protocol(format!(
                "server hello requested unsupported secret-session protocol {:?}",
                hello.proto
            )));
        }
        if let Some(version) = &hello.version
            && version != crate::protocol::PROTOCOL_VERSION
        {
            return Err(Error::protocol(format!(
                "server hello requested unsupported protocol version {version}"
            )));
        }

        let server_public = crypto::from_bytes_be(
            &session.decode(
                hello
                    .server_public
                    .as_deref()
                    .ok_or_else(|| Error::protocol("server hello has no public key"))?,
            )?,
        );
        let salt = crypto::from_bytes_be(
            &session.decode(
                hello
                    .salt
                    .as_deref()
                    .ok_or_else(|| Error::protocol("server hello has no salt"))?,
            )?,
        );
        session.set_server_hello(server_public, salt)?;

        self.session = Some(session);
        Ok(())
    }

    /// Snapshot the in-progress handshake so another process can finish it.
    pub fn pending_auth(&self) -> Result<PendingAuth> {
        PendingAuth::capture(self.session.as_ref().ok_or(Error::NoSession)?)
    }

    /// Adopt a handshake captured by [`Self::pending_auth`].
    pub fn adopt_session(&mut self, session: SrpSession) {
        self.session = Some(session);
    }

    /// Finish the handshake with the PIN macOS displayed, and store the key.
    pub fn complete_auth(&mut self, pin: &str) -> Result<()> {
        let session = self.session.as_mut().ok_or_else(|| {
            Error::other("no handshake in progress; run `apwh auth` or `apwh auth begin` first")
        })?;

        session.derive_shared_key(pin)?;
        let m = session.compute_m()?;
        let request = Messages::verify_challenge(session, &m, self.config.browser())?;
        let response = self.transport.send(&request)?;
        let verification = response.handshake()?;

        // Check the identity first, then the error code: a wrong PIN is by far
        // the most likely failure and deserves the clearest message.
        let session = self.session.as_ref().expect("session was just borrowed");
        self.check_identity(&verification, session, "verification")?;
        match verification.err_code {
            None | Some(0) => {}
            Some(1) => return Err(Error::IncorrectPin),
            Some(code) => {
                return Err(Error::protocol(format!(
                    "server verification reported error code {code}"
                )));
            }
        }
        if !verification.is_stage(MsgType::ServerVerification) {
            return Err(Error::protocol(
                "server reply is not a verification message",
            ));
        }

        let hamk = session.decode(
            verification
                .hamk
                .as_deref()
                .ok_or_else(|| Error::protocol("server verification has no HAMK"))?,
        )?;
        let expected = session.compute_hamk(&m)?;
        if !constant_time_eq(trim_leading_zeros(&hamk), trim_leading_zeros(&expected)) {
            return Err(Error::protocol(
                "server proof (HAMK) did not match; the session may be under attack",
            ));
        }

        self.config.set_session(session)?;
        self.config.save(&self.paths.config())?;
        Ok(())
    }

    /// Forget the stored session. The helper keeps its own until it restarts.
    pub fn logout(&mut self) -> Result<()> {
        self.session = None;
        self.config.clear_session();
        self.config.save(&self.paths.config())?;
        crate::config::remove_if_present(&self.paths.pending_auth())
    }

    /// User names and sites known for a URL. Never returns secrets.
    pub fn login_names(&self, url: &str) -> Result<Payload> {
        let session = self.authenticated_session()?;
        self.secure_request(Messages::login_names_for_url(session, url)?)
    }

    /// The password for one login. Pass `None` to let the helper choose when a
    /// site has exactly one item.
    pub fn password(&self, url: &str, login_name: Option<&str>) -> Result<Payload> {
        let session = self.authenticated_session()?;
        self.secure_request(Messages::password_for_url(
            session,
            url,
            login_name.unwrap_or(""),
        )?)
    }

    /// One-time-code items for a URL, without the codes.
    pub fn list_one_time_codes(&self, url: &str) -> Result<Payload> {
        let session = self.authenticated_session()?;
        self.secure_request(Messages::list_one_time_codes(session, &otp_url(url))?)
    }

    /// The current one-time code for a URL.
    pub fn one_time_code(&self, url: &str) -> Result<Payload> {
        let session = self.authenticated_session()?;
        self.secure_request(Messages::get_one_time_code(session, &otp_url(url))?)
    }

    /// Save a new login. The helper decides whether to prompt the user.
    pub fn save_account(&self, url: &str, login_name: &str, password: &str) -> Result<Payload> {
        let session = self.authenticated_session()?;
        let payload = self.secure_request(Messages::new_account_for_url(
            session, url, login_name, password,
        )?)?;
        payload.ensure_success()?;
        Ok(payload)
    }

    fn negotiated_encoding(&self) -> Encoding {
        self.session
            .as_ref()
            .map(SrpSession::encoding)
            .unwrap_or_default()
    }

    fn authenticated_session(&self) -> Result<&SrpSession> {
        match &self.session {
            Some(session) if session.has_shared_key() => Ok(session),
            _ => Err(Error::NoSession),
        }
    }

    /// Send an encrypted request and decrypt the reply.
    fn secure_request(&self, request: Request) -> Result<Payload> {
        let session = self.authenticated_session()?;
        let response = self.transport.send(&request)?;
        let smsg = response.secure_message()?;

        if smsg.tid != session.username() {
            return Err(Error::protocol(
                "reply was addressed to a different session",
            ));
        }
        let sealed = session.decode(&smsg.sdata)?;
        let plaintext = session.open(&sealed)?;
        Payload::parse(&plaintext)
    }

    fn check_identity(&self, pake: &ServerPake, session: &SrpSession, stage: &str) -> Result<()> {
        if pake.tid == session.username() {
            Ok(())
        } else {
            Err(Error::protocol(format!(
                "server {stage} was addressed to a different session"
            )))
        }
    }
}

/// Result of [`PasswordsClient::capabilities`].
#[derive(Debug, Clone)]
pub struct CapabilitiesReply {
    pub capabilities: Capabilities,
    pub raw: Value,
}

/// One-time-code lookups match on frame URLs, which the helper expects to be
/// absolute. Bare hosts get a scheme; anything already absolute passes through.
fn otp_url(url: &str) -> String {
    if url.contains("://") {
        url.to_string()
    } else {
        format!("http://{url}")
    }
}

fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    &bytes[start..]
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn otp_urls_gain_a_scheme_only_when_missing() {
        assert_eq!(otp_url("example.com"), "http://example.com");
        assert_eq!(otp_url("http://example.com"), "http://example.com");
        assert_eq!(
            otp_url("https://example.com/login"),
            "https://example.com/login"
        );
    }

    #[test]
    fn zero_trimming_makes_bignum_comparisons_agree() {
        assert!(constant_time_eq(
            trim_leading_zeros(&[0, 0, 5]),
            trim_leading_zeros(&[5])
        ));
        assert!(!constant_time_eq(
            trim_leading_zeros(&[0, 5]),
            trim_leading_zeros(&[6])
        ));
        assert!(!constant_time_eq(&[1, 2], &[1, 2, 3]));
        assert!(constant_time_eq(&[], &[]));
        assert_eq!(trim_leading_zeros(&[0, 0]), &[] as &[u8]);
    }

    #[test]
    fn unauthenticated_client_refuses_data_requests_without_touching_the_socket() {
        let paths = Paths {
            home: std::env::temp_dir().join("apwh-no-such-home"),
            socket: std::env::temp_dir().join("apwh-no-such-socket.sock"),
        };
        let client = PasswordsClient::open(paths, Duration::from_millis(100)).unwrap();

        assert!(!client.is_authenticated());
        // NoSession, not ServiceUnavailable: the check happens before connecting.
        assert!(matches!(
            client.login_names("example.com"),
            Err(Error::NoSession)
        ));
        assert!(matches!(
            client.password("example.com", None),
            Err(Error::NoSession)
        ));
        assert!(matches!(
            client.one_time_code("example.com"),
            Err(Error::NoSession)
        ));
        assert!(matches!(
            client.save_account("a", "b", "c"),
            Err(Error::NoSession)
        ));
    }

    #[test]
    fn missing_socket_reports_the_service_as_unavailable() {
        let socket = std::env::temp_dir().join("apwh-definitely-absent.sock");
        let transport = Transport::new(socket.clone(), Duration::from_millis(100));

        assert!(!transport.is_listening());
        let error = transport.send(&Messages::get_capabilities()).unwrap_err();
        assert!(matches!(error, Error::ServiceUnavailable { .. }));
        assert!(error.to_string().contains("apwh serve"));
    }
}
