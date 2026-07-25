//! Error and status types.
//!
//! [`Status`] mirrors the status codes the helper reports inside encrypted
//! payloads. It doubles as the process exit code so callers can distinguish
//! "no results" from "session expired" without parsing stderr.

use std::fmt;
use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, Error>;

/// Status codes reported by the Passwords helper in a decrypted payload's
/// `STATUS` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Success,
    GenericError,
    InvalidParam,
    NoResults,
    FailedToDelete,
    FailedToUpdate,
    InvalidMessageFormat,
    DuplicateItem,
    UnknownAction,
    InvalidSession,
    /// Not a helper code: raised locally for malformed handshake responses.
    ServerError,
    /// A code this build does not know about, preserved verbatim.
    Unknown(i64),
}

impl Status {
    pub fn from_code(code: i64) -> Self {
        match code {
            0 => Self::Success,
            1 => Self::GenericError,
            2 => Self::InvalidParam,
            3 => Self::NoResults,
            4 => Self::FailedToDelete,
            5 => Self::FailedToUpdate,
            6 => Self::InvalidMessageFormat,
            7 => Self::DuplicateItem,
            8 => Self::UnknownAction,
            9 => Self::InvalidSession,
            100 => Self::ServerError,
            other => Self::Unknown(other),
        }
    }

    pub fn code(self) -> i64 {
        match self {
            Self::Success => 0,
            Self::GenericError => 1,
            Self::InvalidParam => 2,
            Self::NoResults => 3,
            Self::FailedToDelete => 4,
            Self::FailedToUpdate => 5,
            Self::InvalidMessageFormat => 6,
            Self::DuplicateItem => 7,
            Self::UnknownAction => 8,
            Self::InvalidSession => 9,
            Self::ServerError => 100,
            Self::Unknown(other) => other,
        }
    }

    pub fn is_success(self) -> bool {
        self == Self::Success
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => f.write_str("operation successful"),
            Self::GenericError => f.write_str("the helper reported a generic error"),
            Self::InvalidParam => f.write_str("invalid parameter"),
            Self::NoResults => f.write_str("no matching items"),
            Self::FailedToDelete => f.write_str("failed to delete the item"),
            Self::FailedToUpdate => f.write_str("failed to update the item"),
            Self::InvalidMessageFormat => f.write_str("invalid message format"),
            Self::DuplicateItem => f.write_str("an item for that site and user already exists"),
            Self::UnknownAction => f.write_str("unknown action"),
            Self::InvalidSession => f.write_str("session rejected; re-run `apwh auth`"),
            Self::ServerError => f.write_str("unexpected response from the Passwords helper"),
            Self::Unknown(code) => write!(f, "unrecognized status code {code}"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The helper answered, but reported a non-success status.
    #[error("{0}")]
    Status(Status),

    /// The helper's answer did not parse as the protocol requires.
    #[error("unexpected response from the Passwords helper: {0}")]
    Protocol(String),

    #[error("no authenticated session; run `apwh auth`")]
    NoSession,

    #[error("incorrect PIN")]
    IncorrectPin,

    #[error(
        "the service is not accepting connections at {path} (start it with `apwh serve`): {source}"
    )]
    ServiceUnavailable {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("a apwh service is already listening on {0}")]
    ServiceAlreadyRunning(PathBuf),

    #[error("timed out after {0:?} waiting for the Passwords helper")]
    Timeout(std::time::Duration),

    #[error(
        "the Passwords helper is not installed on this system; it ships with macOS 14 and later"
    )]
    HelperMissing,

    #[error("the Passwords helper exited")]
    HelperExited,

    /// macOS killed the helper at launch because of its parent launch
    /// constraint. See `apwh doctor` and the "macOS 26" section of `README.md`.
    #[error(
        "macOS killed the Passwords helper immediately (SIGKILL at launch).\n\
         The helper's code signature carries a parent launch constraint: only a signed browser \
         from Apple's allowlist (Chrome, Edge, Firefox, Arc, Brave, …), or an app holding the \
         com.apple.developer.web-browser.public-key-credential entitlement, may be its parent \
         process. A CLI cannot satisfy that constraint."
    )]
    HelperBlockedByLaunchConstraint,

    /// The failure has already been described on stdout; `main` should set the
    /// exit code without printing anything further.
    #[error("")]
    Reported(Status),

    /// The helper exited during startup for some other reason.
    #[error("the Passwords helper exited during startup ({0})")]
    HelperDiedAtStartup(String),

    #[error(
        "the socket path is {length} bytes, but a Unix socket path may be at most {limit}: {path}"
    )]
    SocketPathTooLong {
        path: PathBuf,
        length: usize,
        limit: usize,
    },

    #[error("{0}")]
    Crypto(&'static str),

    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }

    pub fn other(message: impl Into<String>) -> Self {
        Self::Other(message.into())
    }

    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    /// Status this error reports to the shell and to `--json` consumers.
    pub fn status(&self) -> Status {
        match self {
            Self::Status(status) | Self::Reported(status) => *status,
            Self::NoSession | Self::IncorrectPin => Status::InvalidSession,
            Self::Protocol(_) => Status::ServerError,
            _ => Status::GenericError,
        }
    }

    /// Exit code for the process. Clamped into the range a shell can observe.
    pub fn exit_code(&self) -> u8 {
        let code = self.status().code();
        if (1..=125).contains(&code) {
            code as u8
        } else {
            1
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(source: std::io::Error) -> Self {
        Self::Io {
            context: "i/o error".to_string(),
            source,
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(source: serde_json::Error) -> Self {
        Self::Protocol(format!("malformed JSON: {source}"))
    }
}

/// Attach context to an [`std::io::Result`].
pub trait IoContext<T> {
    fn context(self, context: impl Into<String>) -> Result<T>;
}

impl<T> IoContext<T> for std::io::Result<T> {
    fn context(self, context: impl Into<String>) -> Result<T> {
        self.map_err(|source| Error::io(context, source))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_codes_round_trip() {
        for code in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 100, 42] {
            assert_eq!(Status::from_code(code).code(), code);
        }
    }

    #[test]
    fn exit_codes_stay_in_shell_range() {
        assert_eq!(Error::Status(Status::NoResults).exit_code(), 3);
        assert_eq!(Error::NoSession.exit_code(), 9);
        // 0 would falsely read as success, 255 as a signal; both fall back to 1.
        assert_eq!(Error::Status(Status::Success).exit_code(), 1);
        assert_eq!(Error::Status(Status::Unknown(9999)).exit_code(), 1);
        assert_eq!(Error::HelperMissing.exit_code(), 1);
    }
}
