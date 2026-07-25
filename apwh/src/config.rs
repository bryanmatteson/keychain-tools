//! On-disk state: the derived session key, the browser name, and the paths
//! everything lives at.
//!
//! The session key is the whole ballgame — with it, any process can read every
//! password the helper will hand out — so the state directory is `0700`, files
//! are written `0600` through a temp-file-and-rename so a reader never sees a
//! partial file, and nothing secret is ever passed on a command line where `ps`
//! would show it.
//!
//! Storing the key in a file rather than the login keychain is a deliberate
//! trade-off, kept because the service must run unattended after login; see
//! `README.md`.

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::crypto;
use crate::error::{Error, IoContext, Result};
use crate::protocol::DEFAULT_BROWSER_NAME;
use crate::srp::{Encoding, SrpSession};

/// Environment variable that relocates the whole state directory.
pub const HOME_ENV: &str = "APWH_HOME";

/// Environment variable that relocates just the service socket.
pub const SOCKET_ENV: &str = "APWH_SOCKET";

const DIR_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

/// Longest usable Unix socket path. `sockaddr_un.sun_path` is 104 bytes on
/// macOS, one of which is the terminator. Worth checking explicitly: the kernel
/// error for exceeding it ("path must be shorter than SUN_LEN") says nothing
/// about which path or how long it may be.
pub const MAX_SOCKET_PATH: usize = 103;

/// Reject a socket path the kernel cannot represent.
pub fn validate_socket_path(path: &Path) -> Result<()> {
    let length = path.as_os_str().as_encoded_bytes().len();
    if length > MAX_SOCKET_PATH {
        return Err(Error::SocketPathTooLong {
            path: path.to_path_buf(),
            length,
            limit: MAX_SOCKET_PATH,
        });
    }
    Ok(())
}

/// Where state lives.
#[derive(Debug, Clone)]
pub struct Paths {
    pub home: PathBuf,
    pub socket: PathBuf,
}

impl Paths {
    /// Resolve from the environment: `$APWH_HOME` or `~/.apwh`, and `$APWH_SOCKET`
    /// or `<home>/service.sock`.
    pub fn from_env() -> Result<Self> {
        let home = match std::env::var_os(HOME_ENV) {
            Some(value) if !value.is_empty() => PathBuf::from(value),
            _ => {
                let user_home = std::env::var_os("HOME")
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| Error::other("neither $APWH_HOME nor $HOME is set"))?;
                PathBuf::from(user_home).join(".apwh")
            }
        };
        let socket = match std::env::var_os(SOCKET_ENV) {
            Some(value) if !value.is_empty() => PathBuf::from(value),
            _ => home.join("service.sock"),
        };
        Ok(Self { home, socket })
    }

    pub fn with_socket(mut self, socket: PathBuf) -> Self {
        self.socket = socket;
        self
    }

    pub fn config(&self) -> PathBuf {
        self.home.join("config.json")
    }

    /// Half-finished handshake, between `auth begin` and `auth complete`.
    pub fn pending_auth(&self) -> PathBuf {
        self.home.join("pending-auth.json")
    }

    pub fn log_dir(&self) -> PathBuf {
        self.home.join("logs")
    }

    pub fn service_log(&self) -> PathBuf {
        self.log_dir().join("service.log")
    }

    /// Create the state directory with restrictive permissions.
    pub fn ensure_home(&self) -> Result<()> {
        ensure_private_dir(&self.home)
    }
}

/// Persisted configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Config {
    /// `HSTBRSR` value sent during the handshake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<String>,
    /// Present once `apwh auth` has succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<StoredSession>,
}

/// An authenticated SRP session, as stored.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StoredSession {
    /// SRP identity `I`, already in wire form.
    pub username: String,
    /// SRP shared key `K`, base64 of its minimal big-endian bytes.
    pub shared_key: String,
    #[serde(default)]
    pub encoding: StoredEncoding,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StoredEncoding {
    #[default]
    Base64,
    Hex,
}

impl From<StoredEncoding> for Encoding {
    fn from(value: StoredEncoding) -> Self {
        match value {
            StoredEncoding::Base64 => Self::Base64,
            StoredEncoding::Hex => Self::Hex,
        }
    }
}

impl From<Encoding> for StoredEncoding {
    fn from(value: Encoding) -> Self {
        match value {
            Encoding::Base64 => Self::Base64,
            Encoding::Hex => Self::Hex,
        }
    }
}

impl Config {
    /// Load configuration, treating a missing file as defaults.
    pub fn load(path: &Path) -> Result<Self> {
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
                Error::other(format!(
                    "{} is not valid apwh config: {error}",
                    path.display()
                ))
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(Error::io(
                format!("could not read {}", path.display()),
                error,
            )),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let mut json = serde_json::to_vec_pretty(self)?;
        json.push(b'\n');
        write_private(path, &json)
    }

    pub fn browser(&self) -> &str {
        self.browser.as_deref().unwrap_or(DEFAULT_BROWSER_NAME)
    }

    /// Rebuild an authenticated [`SrpSession`] from stored credentials.
    pub fn session(&self) -> Result<Option<SrpSession>> {
        let Some(stored) = &self.session else {
            return Ok(None);
        };
        let encoding = Encoding::from(stored.encoding);
        let key = decode_base64(&stored.shared_key, "session shared key")?;
        Ok(Some(SrpSession::restore(
            encoding,
            stored.username.clone(),
            crypto::from_bytes_be(&key),
        )))
    }

    pub fn set_session(&mut self, session: &SrpSession) -> Result<()> {
        let key = session.shared_key().ok_or(Error::NoSession)?;
        self.session = Some(StoredSession {
            username: session.username().to_string(),
            shared_key: encode_base64(&crypto::to_bytes_be(key)),
            encoding: session.encoding().into(),
        });
        Ok(())
    }

    pub fn clear_session(&mut self) {
        self.session = None;
    }
}

/// A handshake that has been started but not yet confirmed with a PIN.
///
/// This holds the ephemeral private key `a`, which is why it is written `0600`
/// and deleted as soon as the PIN is verified.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PendingAuth {
    pub username: String,
    /// `a`, base64 of its minimal big-endian bytes.
    pub client_private: String,
    /// `B` from the server hello.
    pub server_public: String,
    /// `s` from the server hello.
    pub salt: String,
    #[serde(default)]
    pub encoding: StoredEncoding,
}

impl PendingAuth {
    pub fn capture(session: &SrpSession) -> Result<Self> {
        let server_public = session.server_public().ok_or(Error::Crypto(
            "handshake state is missing the server public key",
        ))?;
        let salt = session
            .salt()
            .ok_or(Error::Crypto("handshake state is missing the salt"))?;
        Ok(Self {
            username: session.username().to_string(),
            client_private: encode_base64(&crypto::to_bytes_be(session.client_private())),
            server_public: encode_base64(&crypto::to_bytes_be(server_public)),
            salt: encode_base64(&crypto::to_bytes_be(salt)),
            encoding: session.encoding().into(),
        })
    }

    pub fn restore(&self) -> Result<SrpSession> {
        let decode = |text: &str, field| -> Result<BigUint> {
            Ok(crypto::from_bytes_be(&decode_base64(text, field)?))
        };
        Ok(SrpSession::resume_handshake(
            self.encoding.into(),
            self.username.clone(),
            decode(&self.client_private, "client private key")?,
            decode(&self.server_public, "server public key")?,
            decode(&self.salt, "salt")?,
        ))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Error::other(format!(
                    "no pending handshake at {}; run `apwh auth begin` first",
                    path.display()
                ))
            } else {
                Error::io(format!("could not read {}", path.display()), error)
            }
        })?;
        serde_json::from_slice(&bytes).map_err(|error| {
            Error::other(format!(
                "{} is not a valid pending handshake: {error}",
                path.display()
            ))
        })
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let mut json = serde_json::to_vec_pretty(self)?;
        json.push(b'\n');
        write_private(path, &json)
    }
}

/// Remove a file, ignoring the case where it never existed.
pub fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::io(
            format!("could not remove {}", path.display()),
            error,
        )),
    }
}

/// Create a directory (and parents) that only the owner can enter.
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).context(format!("could not create {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(DIR_MODE)).context(format!(
        "could not restrict permissions on {}",
        path.display()
    ))
}

/// Write `contents` to `path` as an owner-only file, atomically.
pub fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }

    let temp = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(FILE_MODE)
        .open(&temp)
        .context(format!("could not create {}", temp.display()))?;
    let write_result = file
        .write_all(contents)
        .and_then(|()| file.sync_all())
        .context(format!("could not write {}", temp.display()));
    drop(file);

    if let Err(error) = write_result {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }

    // Pre-existing files may predate the 0600 rule; the rename below replaces
    // them wholesale, so the new mode wins.
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(Error::io(
            format!("could not update {}", path.display()),
            error,
        ));
    }
    Ok(())
}

fn encode_base64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode_base64(text: &str, field: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|_| Error::other(format!("stored {field} is not valid base64")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scratch directory that cleans itself up.
    struct TempHome(PathBuf);

    impl TempHome {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "apwh-test-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn missing_config_loads_as_defaults() {
        let home = TempHome::new("missing");
        let config = Config::load(&home.path().join("config.json")).unwrap();
        assert!(config.session.is_none());
        assert_eq!(config.browser(), DEFAULT_BROWSER_NAME);
    }

    #[test]
    fn malformed_config_is_reported_not_ignored() {
        let home = TempHome::new("malformed");
        let path = home.path().join("config.json");
        fs::write(&path, b"{not json").unwrap();
        assert!(Config::load(&path).is_err());
    }

    #[test]
    fn session_round_trips_through_disk_with_owner_only_permissions() {
        let home = TempHome::new("session");
        let path = home.path().join("nested").join("config.json");

        let session = SrpSession::restore(
            Encoding::Base64,
            "aWRlbnRpdHktMTZieXRlcw==".to_string(),
            crypto::from_bytes_be(&[0x7c; 32]),
        );
        let mut config = Config::default();
        config.set_session(&session).unwrap();
        config.save(&path).unwrap();

        assert_eq!(mode_of(&path), FILE_MODE);
        assert_eq!(mode_of(path.parent().unwrap()), DIR_MODE);

        let loaded = Config::load(&path).unwrap();
        let restored = loaded.session().unwrap().unwrap();
        assert_eq!(restored.username(), session.username());
        assert_eq!(restored.shared_key(), session.shared_key());
    }

    #[test]
    fn clearing_the_session_keeps_other_settings() {
        let home = TempHome::new("clear");
        let path = home.path().join("config.json");

        let mut config = Config {
            browser: Some("Firefox".to_string()),
            session: None,
        };
        config
            .set_session(&SrpSession::restore(
                Encoding::Base64,
                "u".to_string(),
                crypto::from_bytes_be(&[9u8; 32]),
            ))
            .unwrap();
        config.save(&path).unwrap();

        let mut loaded = Config::load(&path).unwrap();
        loaded.clear_session();
        loaded.save(&path).unwrap();

        let reloaded = Config::load(&path).unwrap();
        assert_eq!(reloaded.browser(), "Firefox");
        assert!(reloaded.session().unwrap().is_none());
    }

    #[test]
    fn set_session_requires_a_derived_key() {
        let mut config = Config::default();
        let unauthenticated = SrpSession::new(Encoding::Base64);
        assert!(matches!(
            config.set_session(&unauthenticated),
            Err(Error::NoSession)
        ));
    }

    #[test]
    fn pending_auth_round_trips_and_preserves_the_public_key() {
        let home = TempHome::new("pending");
        let path = home.path().join("pending-auth.json");

        let mut session = SrpSession::new(Encoding::Base64);
        session
            .set_server_hello(
                crypto::from_bytes_be(&[0x33; 384]),
                crypto::from_bytes_be(&[0x44; 16]),
            )
            .unwrap();

        PendingAuth::capture(&session).unwrap().save(&path).unwrap();
        assert_eq!(mode_of(&path), FILE_MODE);

        let restored = PendingAuth::load(&path).unwrap().restore().unwrap();
        assert_eq!(restored.username(), session.username());
        assert_eq!(restored.client_public(), session.client_public());
        assert_eq!(restored.server_public(), session.server_public());
        assert_eq!(restored.salt(), session.salt());

        remove_if_present(&path).unwrap();
        assert!(PendingAuth::load(&path).is_err());
        // Removing an absent file is not an error.
        remove_if_present(&path).unwrap();
    }

    #[test]
    fn capture_refuses_a_handshake_with_no_server_hello() {
        let session = SrpSession::new(Encoding::Base64);
        assert!(PendingAuth::capture(&session).is_err());
    }

    #[test]
    fn write_private_replaces_a_world_readable_file() {
        let home = TempHome::new("replace");
        let path = home.path().join("config.json");
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        write_private(&path, b"new").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(mode_of(&path), FILE_MODE);
        // No temp file left behind.
        let leftovers: Vec<_> = fs::read_dir(home.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left temp files: {leftovers:?}");
    }

    #[test]
    fn paths_follow_the_environment_overrides() {
        let paths = Paths {
            home: PathBuf::from("/state"),
            socket: PathBuf::from("/state/s.sock"),
        };
        assert_eq!(paths.config(), PathBuf::from("/state/config.json"));
        assert_eq!(
            paths.pending_auth(),
            PathBuf::from("/state/pending-auth.json")
        );
        assert_eq!(
            paths.service_log(),
            PathBuf::from("/state/logs/service.log")
        );

        let moved = paths.clone().with_socket(PathBuf::from("/tmp/other.sock"));
        assert_eq!(moved.socket, PathBuf::from("/tmp/other.sock"));
        assert_eq!(moved.home, PathBuf::from("/state"));
    }

    #[test]
    fn stored_encoding_maps_both_ways() {
        for encoding in [Encoding::Base64, Encoding::Hex] {
            assert_eq!(Encoding::from(StoredEncoding::from(encoding)), encoding);
        }
        assert_eq!(
            serde_json::to_string(&StoredEncoding::Base64).unwrap(),
            "\"base64\""
        );
    }
}
