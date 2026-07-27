//! Apple Passwords access on macOS, in two halves.
//!
//! macOS 14 and later ship a native-messaging helper,
//! `PasswordManagerBrowserExtensionHelper`, that browser extensions use to read
//! and write iCloud Keychain items. It speaks Chrome/Firefox native messaging
//! over stdio, so exactly one process may own it at a time, and the SRP session
//! it negotiates lives for as long as that process does.
//!
//! [`service`] owns the helper process and relays framed JSON between it and any
//! number of clients over a Unix domain socket. [`client`] is the other end: it
//! runs the SRP-6a handshake, keeps the derived key in [`config`], and encrypts
//! every subsequent request end-to-end, so the relay never sees plaintext.
//!
//! The protocol was reconstructed from [`apw`](https://github.com/bendews/apw)
//! and [`icloud-passwords-firefox`](https://github.com/au2001/icloud-passwords-firefox);
//! see `README.md` for the wire details and where this deliberately diverges.
//!
//! The on-disk keychain format is a separate crate,
//! [`keychain-db`](https://crates.io/crates/keychain-db), which shares no code
//! with this one.

pub mod client;
pub mod config;
pub mod crypto;
pub mod entries;
pub mod error;
pub mod frame;
pub mod launchd;
pub mod logging;
pub mod output;
pub mod protocol;
pub mod service;
pub mod srp;

pub use client::PasswordsClient;
pub use config::{Config, Paths};
pub use entries::{OtpRecord, PasswordRecord, Payload};
pub use error::{Error, Result, Status};
pub use srp::{SrpServer, SrpSession};
