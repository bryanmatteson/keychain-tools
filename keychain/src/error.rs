//! Errors for keychain parsing, crypto, and item lookup.

use std::path::Path;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not a keychain database: the file does not start with \"kych\"")]
    NotAKeychain,

    #[error("keychain is truncated: wanted {length} bytes at offset {offset}")]
    Truncated { offset: usize, length: usize },

    #[error("malformed keychain: {0}")]
    Format(String),

    #[error("keychain has no {0} table")]
    MissingTable(&'static str),

    #[error("incorrect password, or this keychain was not encrypted with one")]
    WrongPassword,

    #[error("the keychain is locked; unlock it with a password first")]
    Locked,

    /// The item's wrapped key is missing from the keychain's key table.
    #[error("no key in this keychain can decrypt that item (label {label})")]
    MissingItemKey { label: String },

    #[error("{0}")]
    Crypto(&'static str),

    #[error("no item matched")]
    NoSuchItem,

    #[error("an item with those attributes already exists")]
    DuplicateItem,

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
    pub fn truncated(offset: usize, length: usize) -> Self {
        Self::Truncated { offset, length }
    }

    pub fn format(message: impl Into<String>) -> Self {
        Self::Format(message.into())
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

    pub fn reading(path: &Path, source: std::io::Error) -> Self {
        Self::io(format!("could not read {}", path.display()), source)
    }

    /// Exit code for the CLI: distinguishes "no match" and "wrong password"
    /// from everything else, the way `security` does.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::NoSuchItem => 44,
            Self::WrongPassword | Self::Locked => 45,
            Self::DuplicateItem => 46,
            _ => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_separate_the_common_outcomes() {
        assert_eq!(Error::NoSuchItem.exit_code(), 44);
        assert_eq!(Error::WrongPassword.exit_code(), 45);
        assert_eq!(Error::DuplicateItem.exit_code(), 46);
        assert_eq!(Error::NotAKeychain.exit_code(), 1);
    }

    #[test]
    fn messages_name_the_problem() {
        assert!(Error::truncated(12, 4).to_string().contains("offset 12"));
        assert!(Error::NotAKeychain.to_string().contains("kych"));
    }
}
