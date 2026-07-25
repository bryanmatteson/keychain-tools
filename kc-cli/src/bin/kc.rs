//! `kc` — create and read macOS keychain files directly.
//!
//! The file format is parsed, decrypted, and written by this process: nothing
//! goes through the Security framework.

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use keychain::crypto::KeyBlob;
use keychain::edit::{ItemChanges, Settings};
use keychain::format::{self, Record};
use keychain::write::{CreateOptions, NewIdentity, NewItem, create, now_timestamp};
use keychain::{Error, Item, KeychainFile, Query, RecordType, Result};

#[derive(Parser)]
#[command(
    name = "kc",
    version,
    about = "Create and read macOS keychain files without the Security framework",
    long_about = "Create and read macOS keychain (.keychain) files directly.\n\n\
                  The file format is implemented here: no Security framework, no securityd, \
                  no entitlements. Files this writes can be read by `security`, and files \
                  `security` writes can be read by this.",
    disable_help_subcommand = true
)]
struct Cli {
    /// Output format: a field list, JSON, or just the secret
    #[arg(long, global = true, value_enum, value_name = "FORMAT")]
    format: Option<Format>,

    /// Emit JSON instead of text; the same as `--format json`
    #[arg(long, global = true, action = ArgAction::SetTrue, conflicts_with = "format")]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

/// How output is rendered.
#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Aligned field lists, one item at a time
    Text,
    /// A JSON envelope with `ok` and the command's payload
    Json,
    /// Nothing but the secret, so it pipes into other commands
    Secret,
}

impl Cli {
    /// The format to use: `--format` when given, `--json` as its shorthand.
    fn format(&self) -> Format {
        match (self.format, self.json) {
            (Some(format), _) => format,
            (None, true) => Format::Json,
            (None, false) => Format::Text,
        }
    }

    fn is_json(&self) -> bool {
        self.format() == Format::Json
    }

    /// True when only secrets should be printed.
    fn secrets_only(&self) -> bool {
        self.format() == Format::Secret
    }
}

/// Where the keychain password comes from.
///
/// Deliberately never an argument: `ps` shows `argv` to every user on the
/// machine, and shell history keeps it afterwards. The two sources here keep it
/// out of both, and with neither one the password is read from a pipe or
/// prompted for.
#[derive(Args, Clone, Debug, Default)]
struct PasswordSource {
    /// Read the keychain password from this environment variable
    #[arg(
        short = 'e',
        long = "password-env",
        value_name = "NAME",
        group = "password-source"
    )]
    password_env: Option<String>,

    /// Read the keychain password from this file, or from stdin for `-`
    #[arg(
        short = 'f',
        long = "password-file",
        value_name = "FILE",
        group = "password-source"
    )]
    password_file: Option<PathBuf>,
}

/// Where a PKCS#12 container password comes from.
#[derive(Args, Clone, Debug, Default)]
struct Pkcs12PasswordSource {
    /// Read the PKCS#12 password from this environment variable
    #[arg(
        id = "pkcs12-password-env",
        long = "pkcs12-password-env",
        value_name = "NAME",
        group = "pkcs12-password-source"
    )]
    password_env: Option<String>,

    /// Read the PKCS#12 password from this file, or from stdin for `-`
    #[arg(
        id = "pkcs12-password-file",
        long = "pkcs12-password-file",
        value_name = "FILE",
        group = "pkcs12-password-source"
    )]
    password_file: Option<PathBuf>,
}

impl Pkcs12PasswordSource {
    fn resolve(&self) -> Result<String> {
        if let Some(name) = &self.password_env {
            let value = std::env::var(name)
                .map_err(|_| Error::other(format!("the environment variable {name} is not set")))?;
            return Ok(first_line(&value).to_string());
        }
        if let Some(path) = &self.password_file {
            if path.as_os_str() == "-" {
                return read_password_line();
            }
            let text = std::fs::read_to_string(path).map_err(|source| {
                Error::io(format!("could not read {}", path.display()), source)
            })?;
            return Ok(first_line(&text).to_string());
        }
        if !std::io::stdin().is_terminal() {
            return read_password_line();
        }
        rpassword::prompt_password("PKCS#12 password: ")
            .map_err(|source| Error::io("could not read the PKCS#12 password", source))
    }
}

impl PasswordSource {
    /// True when a source was named, rather than left to a pipe or a prompt.
    fn is_explicit(&self) -> bool {
        self.password_env.is_some() || self.password_file.is_some()
    }

    /// Resolve the password, prompting when nothing else supplies it.
    ///
    /// `confirm` asks twice, for a password that is being set rather than used.
    fn resolve(&self, confirm: bool) -> Result<String> {
        if let Some(name) = &self.password_env {
            let value = std::env::var(name)
                .map_err(|_| Error::other(format!("the environment variable {name} is not set")))?;
            return Ok(first_line(&value).to_string());
        }
        if let Some(path) = &self.password_file {
            if path.as_os_str() == "-" {
                return read_password_line();
            }
            let text = std::fs::read_to_string(path).map_err(|source| {
                Error::io(format!("could not read {}", path.display()), source)
            })?;
            return Ok(first_line(&text).to_string());
        }
        if !std::io::stdin().is_terminal() {
            return read_password_line();
        }

        let password = rpassword::prompt_password("Keychain password: ")
            .map_err(|source| Error::io("could not read the password", source))?;
        if confirm {
            let again = rpassword::prompt_password("Confirm: ")
                .map_err(|source| Error::io("could not read the password", source))?;
            if password != again {
                return Err(Error::other("the two entries did not match"));
            }
        }
        Ok(password)
    }

    /// The password, or `None` when the command has nothing to decrypt.
    fn resolve_optional(&self, required: bool) -> Result<Option<String>> {
        if !required && !self.is_explicit() {
            return Ok(None);
        }
        self.resolve(false).map(Some)
    }
}

/// The first line of a password source, without its line ending.
///
/// A password file written with `echo` or a heredoc ends in a newline that is
/// not part of the password.
fn first_line(text: &str) -> &str {
    let line = text.split('\n').next().unwrap_or(text);
    line.strip_suffix('\r').unwrap_or(line)
}

fn read_password_line() -> Result<String> {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|source| Error::io("could not read the password from stdin", source))?;
    Ok(first_line(&line).to_string())
}

#[derive(Subcommand)]
enum Command {
    /// Create a new keychain
    Create {
        #[command(flatten)]
        password: PasswordSource,

        /// Seconds of inactivity before the keychain is considered locked
        #[arg(long, default_value_t = 300)]
        idle_timeout: u32,

        /// Do not set the lock-on-sleep flag
        #[arg(long, action = ArgAction::SetTrue)]
        no_lock_on_sleep: bool,

        keychain: PathBuf,
    },

    /// Show the keychain's format, tables, and key-derivation parameters
    Info { keychain: PathBuf },

    /// Show items and their attributes
    Show {
        #[command(flatten)]
        password: PasswordSource,

        /// Include secrets (requires the password)
        #[arg(short = 'd', long, action = ArgAction::SetTrue)]
        secrets: bool,

        /// Show every relation, not just password items
        #[arg(long, action = ArgAction::SetTrue)]
        all: bool,

        keychain: PathBuf,
    },

    /// List the wrapped item keys
    Ls {
        #[command(flatten)]
        password: PasswordSource,
        keychain: PathBuf,
    },

    /// Check the keychain's internal consistency
    Verify {
        #[command(flatten)]
        password: PasswordSource,
        keychain: PathBuf,
    },

    /// Store an item
    Add {
        #[command(subcommand)]
        kind: AddKind,
    },

    /// Import an identity from a PEM, DER PKCS#12, or PEM PKCS#12 file
    Import {
        #[command(subcommand)]
        kind: ImportKind,
    },

    /// Find an item
    Find {
        #[command(subcommand)]
        kind: FindKind,
    },

    /// Change an item that already exists
    Set {
        #[command(flatten)]
        password: PasswordSource,
        #[command(flatten)]
        selector: Selector,

        /// New secret; read from the terminal or stdin when the flag is given
        /// without a value
        #[arg(short = 'w', long, num_args = 0..=1, default_missing_value = "")]
        secret: Option<String>,
        /// New label (PrintName)
        #[arg(short = 'l', long = "set-label", value_name = "LABEL")]
        new_label: Option<String>,
        /// New kind
        #[arg(short = 'D', long = "set-kind", value_name = "KIND")]
        new_kind: Option<String>,
        /// New comment
        #[arg(short = 'j', long = "set-comment", value_name = "COMMENT")]
        new_comment: Option<String>,
        /// New generic attribute (generic items)
        #[arg(short = 'G', long = "set-generic", value_name = "GENERIC")]
        new_generic: Option<String>,
        /// Set any other attribute, as NAME=VALUE (repeatable)
        #[arg(long = "set", value_name = "NAME=VALUE")]
        set_attributes: Vec<String>,

        keychain: PathBuf,
    },

    /// Delete items
    #[command(visible_alias = "delete")]
    Rm {
        #[command(subcommand)]
        kind: RmKind,
    },

    /// Change which applications may use an item
    Trust {
        #[command(flatten)]
        password: PasswordSource,
        #[command(flatten)]
        selector: Selector,

        /// Allow this application (repeatable)
        #[arg(short = 'T', long = "trust-app", value_name = "PATH")]
        trust_apps: Vec<PathBuf>,
        /// Allow an application named by a requirement blob from `csreq -b`,
        /// as PATH=FILE (repeatable)
        #[arg(long = "trust-requirement", value_name = "PATH=FILE")]
        trust_requirements: Vec<String>,
        /// Allow any application, the way `security -A` does
        #[arg(short = 'A', long, action = ArgAction::SetTrue)]
        any: bool,

        keychain: PathBuf,
    },

    /// Copy an item into another keychain
    Cp {
        #[command(flatten)]
        password: PasswordSource,
        #[command(flatten)]
        selector: Selector,

        /// Password for the destination keychain, from an environment variable
        #[arg(long = "to-password-env", value_name = "NAME")]
        to_password_env: Option<String>,
        /// Password for the destination keychain, from a file
        #[arg(long = "to-password-file", value_name = "FILE")]
        to_password_file: Option<PathBuf>,
        /// Allow only these applications to use the copy (repeatable)
        #[arg(short = 'T', long = "trust-app", value_name = "PATH")]
        trust_apps: Vec<PathBuf>,
        #[arg(long = "trust-requirement", value_name = "PATH=FILE")]
        trust_requirements: Vec<String>,

        source: PathBuf,
        destination: PathBuf,
    },

    /// Write a certificate or private key out of the keychain
    Export {
        #[command(subcommand)]
        kind: ExportKind,
    },

    /// Change the keychain's password
    #[command(visible_alias = "change-password")]
    Passwd {
        #[command(flatten)]
        password: PasswordSource,

        /// New password, from an environment variable
        #[arg(long = "new-password-env", value_name = "NAME")]
        new_password_env: Option<String>,
        /// New password, from a file's first line
        #[arg(long = "new-password-file", value_name = "FILE")]
        new_password_file: Option<PathBuf>,

        keychain: PathBuf,
    },

    /// Show or change the keychain's lock settings
    Settings {
        #[command(flatten)]
        password: PasswordSource,

        /// Seconds of inactivity before the keychain locks
        #[arg(short = 't', long, conflicts_with = "no_timeout")]
        idle_timeout: Option<u32>,
        /// Never lock on idle, which macOS stores as a timeout of INT_MAX
        #[arg(long, action = ArgAction::SetTrue)]
        no_timeout: bool,
        /// Lock when the system sleeps
        #[arg(short = 'l', long, action = ArgAction::SetTrue)]
        lock_on_sleep: bool,
        /// Do not lock when the system sleeps
        #[arg(long, action = ArgAction::SetTrue, conflicts_with = "lock_on_sleep")]
        no_lock_on_sleep: bool,

        keychain: PathBuf,
    },

    /// Print a shell completion script
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

#[derive(Subcommand)]
enum ImportKind {
    /// Import one certificate/private-key identity
    Identity {
        #[command(flatten)]
        password: PasswordSource,
        #[command(flatten)]
        pkcs12_password: Pkcs12PasswordSource,
        /// Label for both records; overrides a PKCS#12 friendly name
        #[arg(short = 'l', long)]
        label: Option<String>,
        /// Restrict use of the private key to this application (repeatable)
        #[arg(short = 'T', long = "trust-app", value_name = "PATH")]
        trust_apps: Vec<PathBuf>,
        /// Restrict use using a PATH=REQUIREMENT_FILE pair (repeatable)
        #[arg(long = "trust-requirement", value_name = "PATH=FILE")]
        trust_requirements: Vec<String>,
        /// Combined PEM identity or PKCS#12/PFX file, in PEM or DER form
        input: PathBuf,
        keychain: PathBuf,
    },
}

/// Which item a mutating command acts on.
///
/// The same flags `find` takes, in one place: a mutation names its target the
/// way a search does, and must match exactly one item unless it says otherwise.
#[derive(Args, Clone, Debug, Default)]
struct Selector {
    /// Item class; without it, every password class is searched
    #[arg(short = 'c', long, value_enum)]
    class: Option<ItemClass>,
    /// Account name
    #[arg(short = 'a', long)]
    account: Option<String>,
    /// Service name (generic items)
    #[arg(short = 's', long)]
    service: Option<String>,
    /// Server name (internet and AppleShare items)
    #[arg(long)]
    server: Option<String>,
    /// Security domain (internet items)
    #[arg(long)]
    security_domain: Option<String>,
    /// Path (internet items)
    #[arg(long)]
    path: Option<String>,
    /// Port (internet items)
    #[arg(short = 'P', long)]
    port: Option<u32>,
    /// Volume (AppleShare items)
    #[arg(short = 'v', long)]
    volume: Option<String>,
    /// Item label (PrintName)
    #[arg(long)]
    label: Option<String>,
    /// Kind
    #[arg(long)]
    kind: Option<String>,
    /// Comment
    #[arg(long)]
    comment: Option<String>,
    /// Generic attribute (generic items)
    #[arg(long)]
    generic: Option<String>,
    /// Match any other attribute, as NAME=VALUE (repeatable)
    #[arg(long = "attr", value_name = "NAME=VALUE")]
    attributes: Vec<String>,
}

impl Selector {
    fn to_query(&self) -> Result<Query> {
        Ok(Query {
            record_type: self.class.map(ItemClass::record_type),
            account: self.account.clone(),
            service: self.service.clone(),
            server: self.server.clone(),
            security_domain: self.security_domain.clone(),
            path: self.path.clone(),
            port: self.port,
            volume: self.volume.clone(),
            label: self.label.clone(),
            description: self.kind.clone(),
            comment: self.comment.clone(),
            generic: self.generic.clone(),
            attributes: attribute_filters(&self.attributes)?,
            ..Query::default()
        })
    }

    /// True when nothing was given: a mutation with no target is refused rather
    /// than applied to whatever happens to be first.
    fn is_empty(&self) -> bool {
        self.to_query()
            .map(|query| query.is_empty())
            .unwrap_or(false)
            && self.class.is_none()
    }
}

/// A password item's class.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum ItemClass {
    Generic,
    Internet,
    #[value(name = "appleshare")]
    AppleShare,
}

impl ItemClass {
    fn record_type(self) -> RecordType {
        match self {
            Self::Generic => RecordType::GENERIC_PASSWORD,
            Self::Internet => RecordType::INTERNET_PASSWORD,
            Self::AppleShare => RecordType::APPLESHARE_PASSWORD,
        }
    }
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // clap subcommands are parsed once, not passed around
enum RmKind {
    /// Delete password items
    #[command(name = "item")]
    Item {
        #[command(flatten)]
        password: PasswordSource,
        #[command(flatten)]
        selector: Selector,

        /// Delete every match, not just a single item
        #[arg(long, action = ArgAction::SetTrue)]
        all: bool,

        keychain: PathBuf,
    },

    /// Delete an identity: its certificate and its private key
    Identity {
        #[command(flatten)]
        password: PasswordSource,
        /// The identity's label (the certificate's PrintName)
        #[arg(short = 'l', long)]
        label: Option<String>,
        /// The identity's public key hash, as hex
        #[arg(long)]
        hash: Option<String>,

        keychain: PathBuf,
    },

    /// Delete a certificate, leaving its private key behind
    #[command(name = "cert", visible_alias = "certificate")]
    Certificate {
        #[command(flatten)]
        password: PasswordSource,
        /// The certificate's label (PrintName)
        #[arg(short = 'l', long)]
        label: Option<String>,
        /// The certificate's public key hash, as hex
        #[arg(long)]
        hash: Option<String>,

        keychain: PathBuf,
    },
}

#[derive(Subcommand)]
enum ExportKind {
    /// Write a certificate out, PEM by default
    #[command(name = "cert", visible_alias = "certificate")]
    Certificate {
        #[command(flatten)]
        password: PasswordSource,
        /// The certificate's label (PrintName)
        #[arg(short = 'l', long)]
        label: Option<String>,
        /// Write DER instead of PEM
        #[arg(long, action = ArgAction::SetTrue)]
        der: bool,
        /// Write to this file instead of stdout
        #[arg(short = 'o', long)]
        out: Option<PathBuf>,
        keychain: PathBuf,
    },

    /// Write a private key out as unencrypted PKCS#8
    Key {
        #[command(flatten)]
        password: PasswordSource,
        #[arg(short = 'l', long)]
        label: Option<String>,
        #[arg(long, action = ArgAction::SetTrue)]
        der: bool,
        #[arg(short = 'o', long)]
        out: Option<PathBuf>,

        keychain: PathBuf,
    },

    /// Write both halves of an identity: certificate then private key
    Identity {
        #[command(flatten)]
        password: PasswordSource,
        #[arg(short = 'l', long)]
        label: Option<String>,
        #[arg(short = 'o', long)]
        out: Option<PathBuf>,
        /// Export an encrypted PKCS#12/PFX container instead of combined PEM
        #[arg(long, action = ArgAction::SetTrue)]
        pkcs12: bool,
        /// PEM-wrap PKCS#12 output instead of writing binary DER
        #[arg(long, action = ArgAction::SetTrue, requires = "pkcs12")]
        pem: bool,
        #[command(flatten)]
        pkcs12_password: Pkcs12PasswordSource,

        keychain: PathBuf,
    },
}

#[derive(Subcommand)]
enum AddKind {
    /// Store a generic password
    Generic {
        #[command(flatten)]
        password: PasswordSource,
        /// Account name
        #[arg(short = 'a', long)]
        account: String,
        /// Service name
        #[arg(short = 's', long)]
        service: String,
        /// Generic attribute: application-defined data stored with the item
        #[arg(short = 'G', long)]
        generic: Option<String>,
        /// The secret to store; read from the terminal or stdin when omitted
        #[arg(short = 'w', long)]
        secret: Option<String>,
        /// Item label, shown in Keychain Access [default: the service]
        #[arg(short = 'l', long)]
        label: Option<String>,
        /// Kind
        #[arg(short = 'D', long)]
        kind: Option<String>,
        /// Comment
        #[arg(short = 'j', long)]
        comment: Option<String>,
        /// Restrict decryption to this application (repeatable)
        #[arg(short = 'T', long = "trust-app", value_name = "PATH")]
        trust_apps: Vec<PathBuf>,
        /// Restrict decryption to an application named by a requirement blob
        /// from `csreq -b`, as PATH=FILE (repeatable)
        #[arg(long = "trust-requirement", value_name = "PATH=FILE")]
        trust_requirements: Vec<String>,

        keychain: PathBuf,
    },

    /// Store an internet password
    Internet {
        #[command(flatten)]
        password: PasswordSource,
        #[arg(short = 'a', long)]
        account: String,
        /// Server name
        #[arg(short = 's', long)]
        server: String,
        /// Security domain: the authentication realm
        /// (`-d`, as `security add-internet-password` spells it)
        #[arg(short = 'S', short_alias = 'd', long)]
        security_domain: Option<String>,
        #[arg(short = 'w', long)]
        secret: Option<String>,
        #[arg(short = 'l', long)]
        label: Option<String>,
        /// Path
        #[arg(long)]
        path: Option<String>,
        /// Port
        #[arg(short = 'P', long)]
        port: Option<u32>,
        /// Protocol, as a four-character code such as http or htps
        #[arg(short = 'r', long)]
        protocol: Option<String>,
        /// Authentication type, as a four-character code such as dflt
        #[arg(short = 't', long)]
        auth_type: Option<String>,
        /// Kind
        #[arg(short = 'D', long)]
        kind: Option<String>,
        /// Comment
        #[arg(short = 'j', long)]
        comment: Option<String>,
        /// Restrict decryption to this application (repeatable)
        #[arg(short = 'T', long = "trust-app", value_name = "PATH")]
        trust_apps: Vec<PathBuf>,
        /// Restrict decryption to an application named by a requirement blob
        /// from `csreq -b`, as PATH=FILE (repeatable)
        #[arg(long = "trust-requirement", value_name = "PATH=FILE")]
        trust_requirements: Vec<String>,

        keychain: PathBuf,
    },

    /// Store an AppleShare password
    #[command(name = "appleshare")]
    AppleShare {
        #[command(flatten)]
        password: PasswordSource,
        #[arg(short = 'a', long)]
        account: String,
        /// Volume name
        #[arg(short = 'v', long)]
        volume: String,
        #[arg(short = 'w', long)]
        secret: Option<String>,
        #[arg(short = 'l', long)]
        label: Option<String>,
        /// Server name
        #[arg(short = 's', long)]
        server: Option<String>,
        /// Address
        #[arg(long)]
        address: Option<String>,
        /// Signature
        #[arg(long)]
        signature: Option<String>,
        /// Protocol, as a four-character code
        #[arg(short = 'r', long)]
        protocol: Option<String>,
        /// Kind
        #[arg(short = 'D', long)]
        kind: Option<String>,
        /// Comment
        #[arg(short = 'j', long)]
        comment: Option<String>,
        /// Restrict decryption to this application (repeatable)
        #[arg(short = 'T', long = "trust-app", value_name = "PATH")]
        trust_apps: Vec<PathBuf>,
        /// Restrict decryption to an application named by a requirement blob
        /// from `csreq -b`, as PATH=FILE (repeatable)
        #[arg(long = "trust-requirement", value_name = "PATH=FILE")]
        trust_requirements: Vec<String>,

        keychain: PathBuf,
    },

    /// Store an identity (certificate + private key)
    Identity {
        #[command(flatten)]
        password: PasswordSource,
        /// Certificate file, PEM or DER
        #[arg(
            short = 'c',
            long = "cert",
            value_name = "FILE",
            required_unless_present = "pkcs12",
            requires = "key",
            conflicts_with = "pkcs12"
        )]
        certificate: Option<PathBuf>,
        /// Private key file: an unencrypted PKCS#8 `PrivateKeyInfo`, PEM or DER
        #[arg(
            short = 'k',
            long = "key",
            value_name = "FILE",
            required_unless_present = "pkcs12",
            requires = "certificate",
            conflicts_with = "pkcs12"
        )]
        key: Option<PathBuf>,
        /// PKCS#12/PFX file containing one identity
        #[arg(
            long = "pkcs12",
            visible_alias = "pfx",
            value_name = "FILE",
            required_unless_present_all = ["certificate", "key"]
        )]
        pkcs12: Option<PathBuf>,
        #[command(flatten)]
        pkcs12_password: Pkcs12PasswordSource,
        /// Label for both records. Defaults to the certificate's common name.
        #[arg(short = 'l', long)]
        label: Option<String>,
        /// Restrict use of the private key to this application (repeatable)
        #[arg(short = 'T', long = "trust-app", value_name = "PATH")]
        trust_apps: Vec<PathBuf>,
        /// Restrict use of the private key to an application named by a
        /// requirement blob from `csreq -b`, as PATH=FILE (repeatable)
        #[arg(long = "trust-requirement", value_name = "PATH=FILE")]
        trust_requirements: Vec<String>,

        keychain: PathBuf,
    },
}

#[derive(Subcommand)]
enum FindKind {
    /// Find a generic password
    Generic {
        #[command(flatten)]
        password: PasswordSource,
        #[arg(short = 'a', long)]
        account: Option<String>,
        #[arg(short = 's', long)]
        service: Option<String>,
        /// Generic attribute
        #[arg(short = 'G', long)]
        generic: Option<String>,
        /// Item label (PrintName), as shown in Keychain Access
        #[arg(short = 'l', long)]
        label: Option<String>,
        /// Kind
        #[arg(short = 'D', long)]
        kind: Option<String>,
        /// Comment
        #[arg(short = 'j', long)]
        comment: Option<String>,
        /// Match any other attribute, as NAME=VALUE (repeatable). NAME is what
        /// `kc show` prints, such as `ptcl` or `atyp`.
        #[arg(long = "attr", value_name = "NAME=VALUE")]
        attributes: Vec<String>,
        /// Print only the secret
        #[arg(short = 'w', long, action = ArgAction::SetTrue)]
        secret_only: bool,

        keychain: PathBuf,
    },

    /// Find an internet password
    Internet {
        #[command(flatten)]
        password: PasswordSource,
        #[arg(short = 'a', long)]
        account: Option<String>,
        #[arg(short = 's', long)]
        server: Option<String>,
        /// Security domain (`-d`, as `security` spells it)
        #[arg(short = 'S', short_alias = 'd', long)]
        security_domain: Option<String>,
        #[arg(long)]
        path: Option<String>,
        #[arg(short = 'P', long)]
        port: Option<u32>,
        /// Item label (PrintName), as shown in Keychain Access
        #[arg(short = 'l', long)]
        label: Option<String>,
        /// Kind
        #[arg(short = 'D', long)]
        kind: Option<String>,
        /// Comment
        #[arg(short = 'j', long)]
        comment: Option<String>,
        /// Match any other attribute, as NAME=VALUE (repeatable). NAME is what
        /// `kc show` prints, such as `ptcl` or `atyp`.
        #[arg(long = "attr", value_name = "NAME=VALUE")]
        attributes: Vec<String>,
        /// Print only the secret
        #[arg(short = 'w', long, action = ArgAction::SetTrue)]
        secret_only: bool,

        keychain: PathBuf,
    },

    /// Find an AppleShare password
    #[command(name = "appleshare")]
    AppleShare {
        #[command(flatten)]
        password: PasswordSource,
        #[arg(short = 'a', long)]
        account: Option<String>,
        #[arg(short = 'v', long)]
        volume: Option<String>,
        #[arg(short = 's', long)]
        server: Option<String>,
        #[arg(long)]
        address: Option<String>,
        #[arg(long)]
        signature: Option<String>,
        /// Item label (PrintName), as shown in Keychain Access
        #[arg(short = 'l', long)]
        label: Option<String>,
        /// Kind
        #[arg(short = 'D', long)]
        kind: Option<String>,
        /// Comment
        #[arg(short = 'j', long)]
        comment: Option<String>,
        /// Match any other attribute, as NAME=VALUE (repeatable). NAME is what
        /// `kc show` prints, such as `ptcl` or `atyp`.
        #[arg(long = "attr", value_name = "NAME=VALUE")]
        attributes: Vec<String>,
        /// Print only the secret
        #[arg(short = 'w', long, action = ArgAction::SetTrue)]
        secret_only: bool,

        keychain: PathBuf,
    },

    /// Find an identity (certificate + private key)
    Identity {
        /// Match on the identity's label (PrintName)
        #[arg(short = 'l', long)]
        label: Option<String>,

        keychain: PathBuf,
    },
}

fn main() -> ExitCode {
    // A CLI should die quietly when its output pipe closes.
    // SAFETY: setting a signal disposition before any threads exist.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if cli.is_json() {
                let _ = writeln!(
                    std::io::stderr(),
                    "{}",
                    serde_json::json!({ "ok": false, "error": error.to_string() })
                );
            } else {
                let _ = writeln!(std::io::stderr(), "kc: {error}");
            }
            ExitCode::from(error.exit_code())
        }
    }
}

fn run(cli: &Cli) -> Result<()> {
    // `--format secret` says "print the secret and nothing else", which only
    // means something for the commands that read secrets.
    if cli.secrets_only() && !matches!(cli.command, Command::Find { .. } | Command::Show { .. }) {
        return Err(Error::other(
            "--format secret applies to `find` and `show`, which are the commands that read secrets",
        ));
    }

    match &cli.command {
        Command::Create {
            password,
            idle_timeout,
            no_lock_on_sleep,
            keychain,
        } => {
            if keychain.exists() {
                return Err(Error::other(format!(
                    "{} already exists",
                    keychain.display()
                )));
            }
            let password = password.resolve(true)?;
            let options = CreateOptions {
                idle_timeout: *idle_timeout,
                lock_on_sleep: !no_lock_on_sleep,
            };
            let file = create(password.as_bytes(), &options)?;
            file.save(keychain)?;
            report(
                cli,
                &format!("created {}", keychain.display()),
                || serde_json::json!({ "ok": true, "keychain": keychain }),
            );
            Ok(())
        }

        Command::Info { keychain } => info(cli, keychain),

        Command::Show {
            password,
            secrets,
            all,
            keychain,
        } => {
            // Printing secrets and nothing else implies asking for them.
            let secrets = *secrets || cli.secrets_only();
            let mut file = KeychainFile::open(keychain)?;
            if secrets {
                let password = password.resolve(false)?;
                file.unlock(password.as_bytes())?;
            }
            show(cli, &file, secrets, *all)
        }

        Command::Ls { password, keychain } => list_keys(cli, keychain, password),

        Command::Verify { password, keychain } => verify(cli, keychain, password),

        Command::Add { kind } => add_command(cli, kind),

        Command::Import { kind } => import_command(cli, kind),

        Command::Find { kind } => find_command(cli, kind),

        Command::Set {
            password,
            selector,
            secret,
            new_label,
            new_kind,
            new_comment,
            new_generic,
            set_attributes,
            keychain,
        } => set_command(
            cli,
            keychain,
            password,
            selector,
            secret.as_deref(),
            &ItemChanges {
                label: new_label.clone(),
                description: new_kind.clone(),
                comment: new_comment.clone(),
                generic: new_generic.as_ref().map(|text| text.as_bytes().to_vec()),
                security_domain: None,
                attributes: attribute_assignments(set_attributes)?,
            },
        ),

        Command::Rm { kind } => rm_command(cli, kind),

        Command::Trust {
            password,
            selector,
            trust_apps,
            trust_requirements,
            any,
            keychain,
        } => {
            let trusted = trusted_applications(trust_apps, trust_requirements)?;
            if trusted.is_empty() && !any {
                return Err(Error::other(
                    "name at least one application with -T, or pass -A to allow any",
                ));
            }
            if !trusted.is_empty() && *any {
                return Err(Error::other(
                    "-A allows any application; -T restricts to one",
                ));
            }
            trust_command(cli, keychain, password, selector, &trusted)
        }

        Command::Cp {
            password,
            selector,
            to_password_env,
            to_password_file,
            trust_apps,
            trust_requirements,
            source,
            destination,
        } => {
            let to = PasswordSource {
                password_env: to_password_env.clone(),
                password_file: to_password_file.clone(),
            };
            copy_command(
                cli,
                source,
                destination,
                password,
                &to,
                selector,
                &trusted_applications(trust_apps, trust_requirements)?,
            )
        }

        Command::Export { kind } => export_command(cli, kind),

        Command::Passwd {
            password,
            new_password_env,
            new_password_file,
            keychain,
        } => {
            let new = PasswordSource {
                password_env: new_password_env.clone(),
                password_file: new_password_file.clone(),
            };
            passwd_command(cli, keychain, password, &new)
        }

        Command::Settings {
            password,
            idle_timeout,
            no_timeout,
            lock_on_sleep,
            no_lock_on_sleep,
            keychain,
        } => settings_command(
            cli,
            keychain,
            password,
            match (idle_timeout, no_timeout) {
                (Some(seconds), _) => Some(*seconds),
                (None, true) => Some(Settings::NO_TIMEOUT),
                (None, false) => None,
            },
            match (*lock_on_sleep, *no_lock_on_sleep) {
                (true, _) => Some(true),
                (_, true) => Some(false),
                _ => None,
            },
        ),

        Command::Completions { shell } => {
            use clap::CommandFactory;
            let mut command = Cli::command();
            let name = command.get_name().to_string();
            clap_complete::generate(*shell, &mut command, name, &mut std::io::stdout());
            Ok(())
        }
    }
}

fn add_command(cli: &Cli, kind: &AddKind) -> Result<()> {
    match kind {
        AddKind::Generic {
            password,
            account,
            service,
            generic,
            secret,
            label,
            kind,
            comment,
            trust_apps,
            trust_requirements,
            keychain,
        } => {
            let item = NewItem {
                label: label.clone(),
                account: Some(account.clone()),
                service: Some(service.clone()),
                generic: generic.as_ref().map(|text| text.as_bytes().to_vec()),
                description: kind.clone(),
                comment: comment.clone(),
                trusted_applications: trusted_applications(trust_apps, trust_requirements)?,
                ..NewItem::default()
            };
            add(
                cli,
                keychain,
                password,
                RecordType::GENERIC_PASSWORD,
                item,
                secret,
            )
        }

        AddKind::Internet {
            password,
            account,
            server,
            security_domain,
            secret,
            label,
            path,
            port,
            protocol,
            auth_type,
            kind,
            comment,
            trust_apps,
            trust_requirements,
            keychain,
        } => {
            let item = NewItem {
                label: label.clone(),
                account: Some(account.clone()),
                server: Some(server.clone()),
                security_domain: security_domain.clone(),
                path: path.clone(),
                port: *port,
                description: kind.clone(),
                comment: comment.clone(),
                trusted_applications: trusted_applications(trust_apps, trust_requirements)?,
                protocol: four_char_code(protocol.as_deref())?,
                // `security` stores kSecAuthenticationTypeDefault when none is
                // given, and this attribute is part of the relation's unique
                // index, so it is defaulted the same way.
                auth_type: four_char_code(auth_type.as_deref())?.or(Some(*b"dflt")),
                ..NewItem::default()
            };
            add(
                cli,
                keychain,
                password,
                RecordType::INTERNET_PASSWORD,
                item,
                secret,
            )
        }

        AddKind::AppleShare {
            password,
            account,
            volume,
            secret,
            label,
            server,
            address,
            signature,
            protocol,
            kind,
            comment,
            trust_apps,
            trust_requirements,
            keychain,
        } => {
            let item = NewItem {
                label: label.clone(),
                account: Some(account.clone()),
                volume: Some(volume.clone()),
                server: server.clone(),
                address: address.clone(),
                signature: signature.clone(),
                protocol: four_char_code(protocol.as_deref())?,
                description: kind.clone(),
                comment: comment.clone(),
                trusted_applications: trusted_applications(trust_apps, trust_requirements)?,
                ..NewItem::default()
            };
            add(
                cli,
                keychain,
                password,
                RecordType::APPLESHARE_PASSWORD,
                item,
                secret,
            )
        }

        AddKind::Identity {
            password,
            certificate,
            key,
            pkcs12,
            pkcs12_password,
            label,
            trust_apps,
            trust_requirements,
            keychain,
        } => {
            let trusted = trusted_applications(trust_apps, trust_requirements)?;
            let identity = if let Some(path) = pkcs12 {
                identity_from_file(path, pkcs12_password, label.clone(), trusted)?
            } else {
                if pkcs12_password.password_env.is_some() || pkcs12_password.password_file.is_some()
                {
                    return Err(Error::other("a PKCS#12 password source requires --pkcs12"));
                }
                let certificate = certificate
                    .as_ref()
                    .expect("clap requires --cert when --pkcs12 is absent");
                let key = key
                    .as_ref()
                    .expect("clap requires --key when --pkcs12 is absent");
                NewIdentity {
                    certificate: read_der(certificate, keychain::der::PEM_CERTIFICATE)?,
                    private_key: read_der(key, keychain::der::PEM_PRIVATE_KEY)?,
                    label: label.clone(),
                    trusted_applications: trusted,
                }
            };
            add_identity(cli, keychain, password, &identity)
        }
    }
}

fn import_command(cli: &Cli, kind: &ImportKind) -> Result<()> {
    match kind {
        ImportKind::Identity {
            password,
            pkcs12_password,
            label,
            trust_apps,
            trust_requirements,
            input,
            keychain,
        } => {
            let trusted = trusted_applications(trust_apps, trust_requirements)?;
            let identity = identity_from_file(input, pkcs12_password, label.clone(), trusted)?;
            add_identity(cli, keychain, password, &identity)
        }
    }
}

fn identity_from_file(
    path: &Path,
    password: &Pkcs12PasswordSource,
    label: Option<String>,
    trusted_applications: Vec<keychain::acl::TrustedApplication>,
) -> Result<NewIdentity> {
    let data = std::fs::read(path).map_err(|source| Error::reading(path, source))?;
    let is_combined_pem = std::str::from_utf8(&data).is_ok_and(|text| {
        text.contains("-----BEGIN CERTIFICATE-----") && text.contains("-----BEGIN PRIVATE KEY-----")
    });
    if is_combined_pem {
        return Ok(NewIdentity {
            certificate: keychain::der::pem_block(&data, keychain::der::PEM_CERTIFICATE)?,
            private_key: keychain::der::pem_block(&data, keychain::der::PEM_PRIVATE_KEY)?,
            label,
            trusted_applications,
        });
    }

    let der = keychain::der::pem_or_der(&data)?;
    let bundle = keychain::pkcs12::decode(&der, &password.resolve()?)?;
    Ok(NewIdentity {
        certificate: bundle.certificate,
        private_key: bundle.private_key,
        label: label.or(bundle.friendly_name),
        trusted_applications,
    })
}

fn find_command(cli: &Cli, kind: &FindKind) -> Result<()> {
    match kind {
        FindKind::Generic {
            password,
            account,
            service,
            generic,
            label,
            kind,
            comment,
            attributes,
            secret_only,
            keychain,
        } => {
            let query = Query {
                record_type: Some(RecordType::GENERIC_PASSWORD),
                account: account.clone(),
                service: service.clone(),
                generic: generic.clone(),
                label: label.clone(),
                description: kind.clone(),
                comment: comment.clone(),
                attributes: attribute_filters(attributes)?,
                ..Query::default()
            };
            find(cli, keychain, password, &query, *secret_only)
        }

        FindKind::Internet {
            password,
            account,
            server,
            security_domain,
            path,
            port,
            label,
            kind,
            comment,
            attributes,
            secret_only,
            keychain,
        } => {
            let query = Query {
                record_type: Some(RecordType::INTERNET_PASSWORD),
                account: account.clone(),
                server: server.clone(),
                security_domain: security_domain.clone(),
                path: path.clone(),
                port: *port,
                label: label.clone(),
                description: kind.clone(),
                comment: comment.clone(),
                attributes: attribute_filters(attributes)?,
                ..Query::default()
            };
            find(cli, keychain, password, &query, *secret_only)
        }

        FindKind::AppleShare {
            password,
            account,
            volume,
            server,
            address,
            signature,
            label,
            kind,
            comment,
            attributes,
            secret_only,
            keychain,
        } => {
            let query = Query {
                record_type: Some(RecordType::APPLESHARE_PASSWORD),
                account: account.clone(),
                volume: volume.clone(),
                server: server.clone(),
                address: address.clone(),
                signature: signature.clone(),
                label: label.clone(),
                description: kind.clone(),
                comment: comment.clone(),
                attributes: attribute_filters(attributes)?,
                ..Query::default()
            };
            find(cli, keychain, password, &query, *secret_only)
        }

        FindKind::Identity { label, keychain } => find_identity(cli, keychain, label.as_deref()),
    }
}

fn info(cli: &Cli, keychain: &Path) -> Result<()> {
    let file = KeychainFile::open(keychain)?;
    let info = file.info()?;

    if cli.is_json() {
        println!(
            "{}",
            keychain::output::pretty(&serde_json::json!({
                "ok": true,
                "keychain": keychain,
                "format_version": format!("0x{:08x}", info.version),
                "blob_version": format!("0x{:08x}", info.blob_version),
                "sequence": info.sequence,
                "idle_timeout": info.idle_timeout,
                "lock_on_sleep": info.lock_on_sleep,
                "salt": info.salt,
                "iv": info.iv,
                "pbkdf2_iterations": info.pbkdf2_iterations,
                "tables": info.tables.iter().map(|(record_type, count)| serde_json::json!({
                    "record_type": format!("0x{:08x}", record_type.0),
                    "name": record_type.name(),
                    "records": count,
                })).collect::<Vec<_>>(),
            }))
        );
        return Ok(());
    }

    println!(
        "{}",
        keychain::output::field_list(&[
            ("keychain", keychain.display().to_string()),
            ("format version", format!("0x{:08x}", info.version)),
            ("blob version", format!("0x{:08x}", info.blob_version)),
            ("sequence", info.sequence.to_string()),
            ("idle timeout", format!("{}s", info.idle_timeout)),
            ("lock on sleep", info.lock_on_sleep.to_string()),
            (
                "key derivation",
                format!(
                    "PBKDF2-HMAC-SHA1, {} iterations, 3DES",
                    info.pbkdf2_iterations
                )
            ),
            ("salt", info.salt),
            ("iv", info.iv),
        ])
    );
    println!("\ntables:");
    for (record_type, count) in &info.tables {
        println!(
            "  0x{:08x}  {count:>4} records  {}",
            record_type.0,
            record_type.name()
        );
    }
    Ok(())
}

fn add(
    cli: &Cli,
    keychain: &Path,
    password: &PasswordSource,
    record_type: RecordType,
    item: NewItem,
    secret: &Option<String>,
) -> Result<()> {
    let mut file = KeychainFile::open(keychain)?;
    let password = password.resolve(false)?;
    file.unlock(password.as_bytes())?;

    let secret = item_secret(secret)?;
    file.add_password(record_type, &item, secret.as_bytes(), &now_timestamp())?;
    file.save(keychain)?;

    report(cli, "stored", || {
        serde_json::json!({
            "ok": true,
            "account": item.account,
            "service": item.service,
            "server": item.server,
            "volume": item.volume,
        })
    });
    Ok(())
}

fn add_identity(
    cli: &Cli,
    keychain: &Path,
    password: &PasswordSource,
    identity: &NewIdentity,
) -> Result<()> {
    let mut file = KeychainFile::open(keychain)?;
    let password = password.resolve(false)?;
    file.unlock(password.as_bytes())?;

    let public_key_hash = file.add_identity(identity)?;
    file.save(keychain)?;

    report(cli, "stored", || {
        serde_json::json!({
            "ok": true,
            "label": identity.label,
            "public_key_hash": hex::encode(public_key_hash),
        })
    });
    Ok(())
}

/// Read a certificate or key file, accepting either PEM or DER.
///
/// `label` names the PEM block to take, so one bundle file can supply both
/// halves of an identity — which is what `kc export identity` writes.
fn read_der(path: &Path, label: &str) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path)
        .map_err(|source| Error::io(format!("could not read {}", path.display()), source))?;
    keychain::der::pem_block(&bytes, label)
}

fn find(
    cli: &Cli,
    keychain: &Path,
    password: &PasswordSource,
    query: &Query,
    secret_only: bool,
) -> Result<()> {
    let mut file = KeychainFile::open(keychain)?;
    // Attribute queries work on a locked keychain; only decryption needs the
    // password, so it is not demanded unless a secret was asked for.
    let secret_only = secret_only || cli.secrets_only();
    let unlocked = match password.resolve_optional(secret_only)? {
        Some(password) => {
            file.unlock(password.as_bytes())?;
            true
        }
        None => false,
    };

    let item = file.find_one(query)?;
    let secret = if unlocked {
        Some(file.secret(&item)?)
    } else {
        None
    };

    if secret_only {
        let secret = secret.ok_or(Error::Locked)?;
        let mut stdout = std::io::stdout();
        stdout
            .write_all(secret.as_slice())
            .and_then(|()| stdout.write_all(b"\n"))
            .map_err(|source| Error::io("could not write the secret", source))?;
        return Ok(());
    }

    if cli.is_json() {
        let rendered = render_item(&item, secret.as_ref().map(|secret| secret.as_slice()));
        println!(
            "{}",
            keychain::output::pretty(&serde_json::json!({ "ok": true, "item": rendered }))
        );
        return Ok(());
    }

    let mut fields: Vec<(&str, String)> = vec![(
        "class",
        item.record_type.short_name().unwrap_or("?").to_string(),
    )];
    for (name, value) in item.attributes() {
        fields.push((name, display_attribute(name, value)));
    }
    if let Some(secret) = &secret {
        fields.push((
            "secret",
            String::from_utf8_lossy(secret.as_slice()).into_owned(),
        ));
    }
    println!("{}", keychain::output::field_list(&fields));
    Ok(())
}

/// Identities are a private key paired with a certificate (or public key) that
/// share the same `Label` attribute.
fn find_identity(cli: &Cli, keychain: &Path, label: Option<&str>) -> Result<()> {
    let file = KeychainFile::open(keychain)?;
    let identities = identities_in(&file, label);

    if identities.is_empty() {
        return Err(Error::NoSuchItem);
    }

    if cli.is_json() {
        println!(
            "{}",
            keychain::output::pretty(&serde_json::json!({
                "ok": true,
                "identities": identities.iter().map(|identity| serde_json::json!({
                    "label": identity.label,
                    "private_key": identity.private_key,
                    "certificate": identity.certificate,
                    "public_key": identity.public_key,
                })).collect::<Vec<_>>(),
            }))
        );
        return Ok(());
    }

    if identities.len() == 1 {
        let identity = &identities[0];
        let mut fields: Vec<(&str, String)> = vec![("class", "identity".to_string())];
        if let Some(label) = &identity.label {
            fields.push(("label", label.clone()));
        }
        fields.push(("private key", format!("record {}", identity.private_key)));
        if let Some(certificate) = identity.certificate {
            fields.push(("certificate", format!("record {certificate}")));
        }
        if let Some(public_key) = identity.public_key {
            fields.push(("public key", format!("record {public_key}")));
        }
        println!("{}", keychain::output::field_list(&fields));
        return Ok(());
    }

    println!("{:<7}  LABEL", "MATCH");
    for (index, identity) in identities.iter().enumerate() {
        println!(
            "{:<7}  {}",
            index + 1,
            identity.label.as_deref().unwrap_or("-")
        );
    }
    Err(Error::other(format!(
        "{} identities match; narrow the query with -l",
        identities.len()
    )))
}

#[derive(Debug)]
struct IdentityMatch {
    label: Option<String>,
    private_key: u32,
    certificate: Option<u32>,
    public_key: Option<u32>,
}

fn identities_in(file: &KeychainFile, label_filter: Option<&str>) -> Vec<IdentityMatch> {
    let schema = file.schema();
    let label_of = |record_type: RecordType, record: &Record| {
        schema
            .attribute(record_type, record, "Label")
            .and_then(|value| value.as_bytes())
            .map(|bytes| bytes.to_vec())
    };
    let print_name_of = |record_type: RecordType, record: &Record| {
        schema
            .attribute(record_type, record, "PrintName")
            .and_then(|value| value.as_bytes())
            .map(|bytes| String::from_utf8_lossy(format::trim_nul(bytes)).into_owned())
            .filter(|name| !name.is_empty())
    };

    // A certificate record has no `Label`: the hash of its public key is what
    // pairs it with a private key, whose `Label` holds the same hash.
    let mut cert_by_label = std::collections::BTreeMap::<Vec<u8>, u32>::new();
    for record_type in [RecordType::X509_CERTIFICATE, RecordType::CERT] {
        for record in file.records_of_type(record_type) {
            let key = schema
                .attribute(record_type, record, "PublicKeyHash")
                .and_then(|value| value.as_bytes())
                .map(<[u8]>::to_vec)
                .or_else(|| label_of(record_type, record));
            if let Some(key) = key {
                cert_by_label.insert(key, record.number);
            }
        }
    }

    let mut public_by_label = std::collections::BTreeMap::<Vec<u8>, u32>::new();
    for record in file.records_of_type(RecordType::PUBLIC_KEY) {
        if let Some(label) = label_of(RecordType::PUBLIC_KEY, record) {
            public_by_label.insert(label, record.number);
        }
    }

    let mut identities = Vec::new();
    for record in file.records_of_type(RecordType::PRIVATE_KEY) {
        let Some(label_bytes) = label_of(RecordType::PRIVATE_KEY, record) else {
            continue;
        };
        let certificate = cert_by_label.get(&label_bytes).copied();
        let public_key = public_by_label.get(&label_bytes).copied();
        if certificate.is_none() && public_key.is_none() {
            continue;
        }
        let label = print_name_of(RecordType::PRIVATE_KEY, record);
        if let Some(wanted) = label_filter
            && label.as_deref() != Some(wanted)
        {
            continue;
        }
        identities.push(IdentityMatch {
            label,
            private_key: record.number,
            certificate,
            public_key,
        });
    }
    identities
}

fn show(cli: &Cli, file: &KeychainFile, secrets: bool, all: bool) -> Result<()> {
    let items = file.items();

    if cli.secrets_only() {
        let mut stdout = std::io::stdout();
        for item in &items {
            let secret = file.secret(item)?;
            stdout
                .write_all(secret.as_slice())
                .and_then(|()| stdout.write_all(b"\n"))
                .map_err(|source| Error::io("could not write the secret", source))?;
        }
        return Ok(());
    }

    if cli.is_json() {
        let rendered: Vec<_> = items
            .iter()
            .map(|item| {
                let secret = if secrets {
                    file.secret(item).ok()
                } else {
                    None
                };
                render_item(item, secret.as_ref().map(|secret| secret.as_slice()))
            })
            .collect();
        let mut body = serde_json::json!({ "ok": true, "items": rendered });
        if all {
            body["relations"] = relations_json(file);
        }
        println!("{}", keychain::output::pretty(&body));
        return Ok(());
    }

    if items.is_empty() {
        eprintln!("kc: no password items");
    }
    for item in &items {
        println!(
            "class: {}  label: {}",
            item.record_type.short_name().unwrap_or("?"),
            item.label().unwrap_or_default()
        );
        for (name, value) in item.attributes() {
            println!("    {name:<12} {}", display_attribute(name, value));
        }
        if secrets {
            match file.secret(item) {
                Ok(secret) => {
                    println!(
                        "    {:<12} {}",
                        "secret",
                        String::from_utf8_lossy(secret.as_slice())
                    );
                }
                Err(error) => println!("    {:<12} <{error}>", "secret"),
            }
        }
    }

    if all {
        println!("\nrelations:");
        for table in &file.keychain().tables {
            println!(
                "  0x{:08x}  {:>4} records  {}",
                table.record_type.0,
                table.record_count(),
                table.record_type.name()
            );
        }
    }
    Ok(())
}

fn list_keys(cli: &Cli, keychain: &Path, password: &PasswordSource) -> Result<()> {
    let mut file = KeychainFile::open(keychain)?;
    let password = password.resolve(false)?;
    file.unlock(password.as_bytes())?;

    let keys: Vec<_> = file
        .records_of_type(RecordType::SYMMETRIC_KEY)
        .iter()
        .filter_map(|record| {
            let blob = KeyBlob::parse(&record.key_data).ok()?;
            Some(serde_json::json!({
                "record": record.number,
                "label": file
                    .schema()
                    .attribute(RecordType::SYMMETRIC_KEY, record, "Label")
                    .and_then(|value| value.as_bytes())
                    .map(hex::encode),
                "item": blob.public_acl.item_name(),
                "trusted_apps": blob.public_acl.trusted_paths(),
                "algorithm": format!("0x{:x}", blob.header.algorithm_id),
                "key_bits": blob.header.logical_key_size_in_bits,
                "wrapped_bytes": blob.crypto_blob.len(),
            }))
        })
        .collect();

    if cli.is_json() {
        println!(
            "{}",
            keychain::output::pretty(&serde_json::json!({ "ok": true, "keys": keys }))
        );
    } else if keys.is_empty() {
        eprintln!("kc: no item keys");
    } else {
        println!("{:<7}  {:<40}  {:<9}  ITEM", "RECORD", "LABEL", "KEY");
        for key in &keys {
            println!(
                "{:<7}  {:<40}  {:<9}  {}",
                key["record"],
                key["label"].as_str().unwrap_or("-"),
                format!("{} bits", key["key_bits"]),
                key["item"].as_str().unwrap_or("-")
            );
        }
    }
    Ok(())
}

/// Check what a reader can check: blob signatures, key unwrapping, that every
/// item's key is present, and that every index region was understood.
fn verify(cli: &Cli, keychain: &Path, password: &PasswordSource) -> Result<()> {
    let mut file = KeychainFile::open(keychain)?;
    let password = password.resolve(false)?;
    let blob = file.db_blob()?;
    let keys = blob.unlock(password.as_bytes())?;

    let database_signature = blob.verify(keys.signing_key.as_slice());
    file.unlock(password.as_bytes())?;

    let mut verified = 0usize;
    let mut total = 0usize;
    for record in file.records_of_type(RecordType::SYMMETRIC_KEY) {
        if let Ok(key_blob) = KeyBlob::parse(&record.key_data) {
            total += 1;
            if key_blob.verify(keys.signing_key.as_slice()) {
                verified += 1;
            }
        }
    }

    let items = file.items();
    let readable = items
        .iter()
        .filter(|item| file.secret(item).is_ok())
        .count();
    let tables = file.keychain().tables.len();
    let indexes_understood = file
        .keychain()
        .tables
        .iter()
        .filter(|table| table.indexes.blob().is_some())
        .count();

    let ok = database_signature
        && verified == total
        && readable == items.len()
        && indexes_understood == tables;

    if cli.is_json() {
        println!(
            "{}",
            keychain::output::pretty(&serde_json::json!({
                "ok": ok,
                "database_signature": database_signature,
                "key_signatures_verified": verified,
                "key_signatures_total": total,
                "items": items.len(),
                "items_readable": readable,
                "tables": tables,
                "index_regions_understood": indexes_understood,
            }))
        );
    } else {
        println!(
            "{}",
            keychain::output::field_list(&[
                ("database signature", pass(database_signature)),
                ("key signatures", format!("{verified}/{total} verified")),
                ("items readable", format!("{readable}/{}", items.len())),
                (
                    "index regions",
                    format!("{indexes_understood}/{tables} understood")
                ),
            ])
        );
    }

    if ok {
        Ok(())
    } else {
        Err(Error::other("keychain did not verify"))
    }
}

fn relations_json(file: &KeychainFile) -> serde_json::Value {
    serde_json::json!(
        file.keychain()
            .tables
            .iter()
            .map(|table| serde_json::json!({
                "record_type": format!("0x{:08x}", table.record_type.0),
                "name": table.record_type.name(),
                "records": table.record_count(),
            }))
            .collect::<Vec<_>>()
    )
}

/// Render an attribute for display, spelling four-char codes as text.
///
/// The same rendering `--attr NAME=VALUE` matches against, so what `kc show`
/// prints is what a filter compares.
fn display_attribute(name: &str, value: &keychain::Value) -> String {
    if keychain::db::FOUR_CHAR_CODE_ATTRIBUTES.contains(&name)
        && let Some(number) = value.as_u32()
    {
        let bytes = number.to_be_bytes();
        if bytes.iter().all(|byte| (0x20..0x7f).contains(byte)) {
            return String::from_utf8_lossy(&bytes).into_owned();
        }
    }
    value.to_display_string()
}

fn pass(value: bool) -> String {
    if value {
        "ok".to_string()
    } else {
        "FAILED".to_string()
    }
}

fn render_item(item: &Item<'_>, secret: Option<&[u8]>) -> serde_json::Value {
    let mut body = serde_json::json!({
        "class": item.record_type.short_name(),
        "record": item.number(),
        "label": item.label(),
        "account": item.account(),
        "service": item.service(),
        "server": item.server(),
        "path": item.path(),
        "port": item.port(),
        "volume": item.volume(),
        "address": item.address(),
        "signature": item.signature(),
        "created": item.created(),
        "modified": item.modified(),
        "has_secret": item.has_secret(),
    });
    if let Some(secret) = secret {
        body["secret"] = serde_json::json!(String::from_utf8_lossy(secret));
    }
    body
}

fn report(cli: &Cli, text: &str, json: impl FnOnce() -> serde_json::Value) {
    if cli.is_json() {
        println!("{}", keychain::output::pretty(&json()));
    } else {
        println!("{text}");
    }
}

/// The secret to store, kept out of `argv` when possible.
fn item_secret(flag: &Option<String>) -> Result<String> {
    if let Some(secret) = flag {
        return Ok(secret.clone());
    }
    if !std::io::stdin().is_terminal() {
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .map_err(|source| Error::io("could not read the secret from stdin", source))?;
        let secret = buffer.strip_suffix('\n').unwrap_or(&buffer);
        return Ok(secret.strip_suffix('\r').unwrap_or(secret).to_string());
    }

    let secret = rpassword::prompt_password("Secret: ")
        .map_err(|source| Error::io("could not read the secret", source))?;
    let again = rpassword::prompt_password("Confirm: ")
        .map_err(|source| Error::io("could not read the secret", source))?;
    if secret != again {
        return Err(Error::other("the two entries did not match"));
    }
    Ok(secret)
}

/// Resolve `-T` and `--trust-requirement` into the applications an item's ACL
/// should name. An empty result means "any application", which is what
/// `security -A` stores.
fn trusted_applications(
    paths: &[PathBuf],
    requirements: &[String],
) -> Result<Vec<keychain::acl::TrustedApplication>> {
    let mut applications = Vec::with_capacity(paths.len() + requirements.len());
    for path in paths {
        applications.push(keychain::requirement::for_application(path)?);
    }
    for spec in requirements {
        let (path, file) = spec
            .split_once('=')
            .ok_or_else(|| Error::other(format!("expected PATH=FILE, got {spec:?}")))?;
        let blob = std::fs::read(file)
            .map_err(|source| Error::io(format!("could not read {file}"), source))?;
        applications.push(keychain::requirement::from_blob(path, blob)?);
    }
    Ok(applications)
}

/// `kc set`: change an item that already exists.
fn set_command(
    cli: &Cli,
    keychain: &Path,
    password: &PasswordSource,
    selector: &Selector,
    secret: Option<&str>,
    changes: &ItemChanges,
) -> Result<()> {
    if selector.is_empty() {
        return Err(Error::other(
            "name the item to change, for example with -a and -s",
        ));
    }
    if changes.is_empty() && secret.is_none() {
        return Err(Error::other(
            "nothing to change; pass -w for the secret or one of the --set-* flags",
        ));
    }

    let mut file = KeychainFile::open(keychain)?;
    // Only a new secret needs the keys; renaming an item does not.
    if secret.is_some() {
        let password = password.resolve(false)?;
        file.unlock(password.as_bytes())?;
    }

    let (record_type, number, label) = {
        let item = file.find_one(&selector.to_query()?)?;
        (item.record_type, item.number(), item.label())
    };

    // `-w` with no value means "prompt for it", the way `add` does.
    let secret = match secret {
        None => None,
        Some("") => Some(item_secret(&None)?),
        Some(given) => Some(given.to_string()),
    };

    file.update_item(
        record_type,
        number,
        changes,
        secret.as_ref().map(|secret| secret.as_bytes()),
        &now_timestamp(),
    )?;
    file.save(keychain)?;

    report(cli, "updated", || {
        serde_json::json!({
            "ok": true,
            "class": record_type.short_name(),
            "record": number,
            "label": label,
            "secret_changed": secret.is_some(),
        })
    });
    Ok(())
}

/// `kc rm`: delete items or identities.
fn rm_command(cli: &Cli, kind: &RmKind) -> Result<()> {
    match kind {
        RmKind::Item {
            password,
            selector,
            all,
            keychain,
        } => {
            if selector.is_empty() {
                return Err(Error::other(
                    "name the item to delete, for example with -a and -s",
                ));
            }
            let mut file = KeychainFile::open(keychain)?;
            // Deleting touches no ciphertext, so the password is optional; it is
            // still accepted so a script can pass one uniformly.
            if let Some(password) = password.resolve_optional(false)? {
                file.unlock(password.as_bytes())?;
            }

            let targets: Vec<(RecordType, u32, Option<String>)> = file
                .find(&selector.to_query()?)
                .iter()
                .map(|item| (item.record_type, item.number(), item.label()))
                .collect();
            match targets.len() {
                0 => return Err(Error::NoSuchItem),
                1 => {}
                count if !*all => {
                    return Err(Error::other(format!(
                        "{count} items match; narrow the query or pass --all"
                    )));
                }
                _ => {}
            }

            let mut deleted = Vec::new();
            for (record_type, number, label) in &targets {
                let records = file.delete_item(*record_type, *number)?;
                deleted.push(serde_json::json!({
                    "class": record_type.short_name(),
                    "record": number,
                    "label": label,
                    "records_removed": records,
                }));
            }
            file.save(keychain)?;

            report(
                cli,
                &format!("deleted {} item(s)", deleted.len()),
                || serde_json::json!({ "ok": true, "deleted": deleted }),
            );
            Ok(())
        }

        RmKind::Identity {
            password,
            label,
            hash,
            keychain,
        } => rm_identity(
            cli,
            keychain,
            password,
            label.as_deref(),
            hash.as_deref(),
            true,
        ),

        RmKind::Certificate {
            password,
            label,
            hash,
            keychain,
        } => rm_identity(
            cli,
            keychain,
            password,
            label.as_deref(),
            hash.as_deref(),
            false,
        ),
    }
}

/// `kc rm identity` and `kc rm cert`, which differ only in whether the private
/// key goes with the certificate.
fn rm_identity(
    cli: &Cli,
    keychain: &Path,
    password: &PasswordSource,
    label: Option<&str>,
    hash: Option<&str>,
    with_key: bool,
) -> Result<()> {
    let mut file = KeychainFile::open(keychain)?;
    if let Some(password) = password.resolve_optional(false)? {
        file.unlock(password.as_bytes())?;
    }
    let hash = identity_hash(&file, label, hash)?;
    let removed = if with_key {
        file.delete_identity(&hash)?
    } else {
        file.delete_certificate(&hash)?
    };
    file.save(keychain)?;

    report(cli, &format!("deleted {removed} record(s)"), || {
        serde_json::json!({
            "ok": true,
            "public_key_hash": hex::encode(&hash),
            "records_removed": removed,
            "private_key_removed": with_key,
        })
    });
    Ok(())
}

/// The public key hash of the identity a label or hex hash names.
fn identity_hash(file: &KeychainFile, label: Option<&str>, hash: Option<&str>) -> Result<Vec<u8>> {
    if let Some(hash) = hash {
        return hex::decode(hash)
            .map_err(|error| Error::other(format!("{hash:?} is not hex: {error}")));
    }
    let identities = file.identities();
    let matches: Vec<_> = identities
        .iter()
        .filter(|identity| match label {
            None => true,
            Some(wanted) => identity.label.as_deref() == Some(wanted),
        })
        .collect();
    match matches.len() {
        0 => Err(Error::NoSuchItem),
        1 => Ok(matches[0].public_key_hash.clone()),
        count => Err(Error::other(format!(
            "{count} identities match; narrow it with -l or --hash"
        ))),
    }
}

/// `kc trust`: rewrite an item's access-control list.
fn trust_command(
    cli: &Cli,
    keychain: &Path,
    password: &PasswordSource,
    selector: &Selector,
    trusted: &[keychain::acl::TrustedApplication],
) -> Result<()> {
    if selector.is_empty() {
        return Err(Error::other("name the item, for example with -a and -s"));
    }
    let mut file = KeychainFile::open(keychain)?;
    let password = password.resolve(false)?;
    file.unlock(password.as_bytes())?;

    let (record_type, number, label) = {
        let item = file.find_one(&selector.to_query()?)?;
        (item.record_type, item.number(), item.label())
    };
    file.set_item_trust(record_type, number, trusted)?;
    file.save(keychain)?;

    report(cli, "access updated", || {
        serde_json::json!({
            "ok": true,
            "class": record_type.short_name(),
            "record": number,
            "label": label,
            "trusted_applications": trusted
                .iter()
                .map(|application| application.path.clone())
                .collect::<Vec<_>>(),
        })
    });
    Ok(())
}

/// `kc cp`: copy an item into another keychain.
fn copy_command(
    cli: &Cli,
    source: &Path,
    destination: &Path,
    from: &PasswordSource,
    to: &PasswordSource,
    selector: &Selector,
    trusted: &[keychain::acl::TrustedApplication],
) -> Result<()> {
    if selector.is_empty() {
        return Err(Error::other("name the item, for example with -a and -s"));
    }

    let mut origin = KeychainFile::open(source)?;
    let source_password = from.resolve(false)?;
    origin.unlock(source_password.as_bytes())?;

    let item = origin.find_one(&selector.to_query()?)?;
    let record_type = item.record_type;
    let secret = origin.secret(&item)?;
    let new = NewItem {
        label: item.label(),
        account: item.account(),
        service: item.service(),
        generic: item
            .attribute("gena")
            .and_then(|value| value.as_bytes())
            .map(<[u8]>::to_vec),
        server: item.server(),
        security_domain: item.text("sdmn"),
        path: item.path(),
        port: item.port(),
        protocol: four_char_code(item.display_attribute("ptcl").as_deref())?,
        auth_type: four_char_code(item.text("atyp").as_deref())?,
        volume: item.volume(),
        address: item.address(),
        signature: item.signature(),
        description: item.text("desc"),
        comment: item.text("icmt"),
        trusted_applications: trusted.to_vec(),
    };
    let summary = serde_json::json!({
        "ok": true,
        "class": record_type.short_name(),
        "label": new.label,
        "account": new.account,
        "destination": destination,
    });

    let mut target = KeychainFile::open(destination)?;
    // The destination may use a different password; when none is given, the
    // source's is tried, which is the common case.
    let destination_password = match to.is_explicit() {
        true => to.resolve(false)?,
        false => source_password.clone(),
    };
    target.unlock(destination_password.as_bytes())?;
    target.add_password(record_type, &new, secret.as_slice(), &now_timestamp())?;
    target.save(destination)?;

    report(cli, "copied", || summary);
    Ok(())
}

/// `kc export`: write a certificate or private key out.
fn export_command(cli: &Cli, kind: &ExportKind) -> Result<()> {
    match kind {
        ExportKind::Certificate {
            password,
            label,
            der,
            out,
            keychain,
        } => {
            let mut file = KeychainFile::open(keychain)?;
            if let Some(password) = password.resolve_optional(false)? {
                file.unlock(password.as_bytes())?;
            }
            let identity = one_identity(&file, label.as_deref())?;
            let bytes = if *der {
                identity.certificate.clone()
            } else {
                keychain::der::to_pem(keychain::der::PEM_CERTIFICATE, &identity.certificate)
                    .into_bytes()
            };
            write_export(cli, out.as_deref(), &bytes, "certificate", &identity.label)
        }

        ExportKind::Key {
            password,
            label,
            der,
            out,
            keychain,
        } => {
            let mut file = KeychainFile::open(keychain)?;
            let password = password.resolve(false)?;
            file.unlock(password.as_bytes())?;

            let identity = one_identity(&file, label.as_deref())?;
            let record = identity
                .private_key_record
                .ok_or_else(|| Error::other("that identity has no private key in this keychain"))?;
            let key = file.private_key_pkcs8(record)?;
            let bytes = if *der {
                key.as_slice().to_vec()
            } else {
                keychain::der::to_pem(keychain::der::PEM_PRIVATE_KEY, key.as_slice()).into_bytes()
            };
            write_export(cli, out.as_deref(), &bytes, "private key", &identity.label)
        }

        ExportKind::Identity {
            password,
            label,
            out,
            pkcs12,
            pem,
            pkcs12_password,
            keychain,
        } => {
            let mut file = KeychainFile::open(keychain)?;
            let password = password.resolve(false)?;
            file.unlock(password.as_bytes())?;

            let identity = one_identity(&file, label.as_deref())?;
            let record = identity
                .private_key_record
                .ok_or_else(|| Error::other("that identity has no private key in this keychain"))?;
            let key = file.private_key_pkcs8(record)?;
            let bytes = if *pkcs12 {
                let bundle = keychain::pkcs12::Identity {
                    certificate: identity.certificate.clone(),
                    private_key: key.as_slice().to_vec(),
                    friendly_name: identity.label.clone(),
                };
                let der = keychain::pkcs12::encode(&bundle, &pkcs12_password.resolve()?)?;
                if *pem {
                    keychain::der::to_pem(keychain::der::PEM_PKCS12, &der).into_bytes()
                } else {
                    der
                }
            } else {
                if pkcs12_password.password_env.is_some() || pkcs12_password.password_file.is_some()
                {
                    return Err(Error::other("a PKCS#12 password source requires --pkcs12"));
                }
                let mut pem =
                    keychain::der::to_pem(keychain::der::PEM_CERTIFICATE, &identity.certificate)
                        .into_bytes();
                pem.extend_from_slice(
                    keychain::der::to_pem(keychain::der::PEM_PRIVATE_KEY, key.as_slice())
                        .as_bytes(),
                );
                pem
            };
            write_export(cli, out.as_deref(), &bytes, "identity", &identity.label)
        }
    }
}

/// The one identity a label names, or an error naming the ambiguity.
fn one_identity(
    file: &KeychainFile,
    label: Option<&str>,
) -> Result<keychain::edit::StoredIdentity> {
    let identities = file.identities();
    let mut matches: Vec<_> = identities
        .into_iter()
        .filter(|identity| match label {
            None => true,
            Some(wanted) => identity.label.as_deref() == Some(wanted),
        })
        .collect();
    match matches.len() {
        0 => Err(Error::NoSuchItem),
        1 => Ok(matches.remove(0)),
        count => Err(Error::other(format!(
            "{count} certificates match; narrow it with -l"
        ))),
    }
}

/// Write exported bytes to a file or to stdout.
fn write_export(
    cli: &Cli,
    out: Option<&Path>,
    bytes: &[u8],
    what: &str,
    label: &Option<String>,
) -> Result<()> {
    match out {
        Some(path) => {
            use std::io::Write as _;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

            // An exported private key is key material: create it owner-only,
            // and take an existing file's permissions down rather than
            // inheriting them.
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)
                .map_err(|source| {
                    Error::io(format!("could not create {}", path.display()), source)
                })?;
            std::fs::set_permissions(path, PermissionsExt::from_mode(0o600)).map_err(|source| {
                Error::io(format!("could not secure {}", path.display()), source)
            })?;
            file.write_all(bytes).map_err(|source| {
                Error::io(format!("could not write {}", path.display()), source)
            })?;
            report(
                cli,
                &format!("wrote {} to {}", what, path.display()),
                || {
                    serde_json::json!({
                        "ok": true,
                        "wrote": path,
                        "what": what,
                        "label": label,
                        "bytes": bytes.len(),
                    })
                },
            );
        }
        None => {
            std::io::stdout()
                .write_all(bytes)
                .map_err(|source| Error::io("could not write the export", source))?;
        }
    }
    Ok(())
}

/// `kc passwd`: change the keychain's password.
fn passwd_command(
    cli: &Cli,
    keychain: &Path,
    old: &PasswordSource,
    new: &PasswordSource,
) -> Result<()> {
    let mut file = KeychainFile::open(keychain)?;
    let old_password = old.resolve(false)?;
    // Fail before rewriting anything if the old password is wrong.
    file.unlock(old_password.as_bytes())?;

    let new_password = if new.is_explicit() {
        new.resolve(false)?
    } else if std::io::stdin().is_terminal() {
        let entered = rpassword::prompt_password("New keychain password: ")
            .map_err(|source| Error::io("could not read the password", source))?;
        let again = rpassword::prompt_password("Confirm: ")
            .map_err(|source| Error::io("could not read the password", source))?;
        if entered != again {
            return Err(Error::other("the two entries did not match"));
        }
        entered
    } else {
        // Piped input: the old password came from the first line, the new one
        // comes from the second, so the whole change scripts without a tty.
        read_password_line()?
    };

    file.change_password(old_password.as_bytes(), new_password.as_bytes())?;
    file.save(keychain)?;

    report(
        cli,
        "password changed",
        || serde_json::json!({ "ok": true, "keychain": keychain }),
    );
    Ok(())
}

/// `kc settings`: show or change the lock settings.
fn settings_command(
    cli: &Cli,
    keychain: &Path,
    password: &PasswordSource,
    idle_timeout: Option<u32>,
    lock_on_sleep: Option<bool>,
) -> Result<()> {
    let mut file = KeychainFile::open(keychain)?;
    let changing = idle_timeout.is_some() || lock_on_sleep.is_some();
    if changing {
        // The settings live in the signed part of the database blob.
        let password = password.resolve(false)?;
        file.unlock(password.as_bytes())?;
    }

    let mut settings = file.settings()?;
    if changing {
        if let Some(timeout) = idle_timeout {
            settings.idle_timeout = timeout;
        }
        if let Some(lock) = lock_on_sleep {
            settings.lock_on_sleep = lock;
        }
        file.set_settings(&settings)?;
        file.save(keychain)?;
    }

    if cli.is_json() {
        println!(
            "{}",
            keychain::output::pretty(&serde_json::json!({
                "ok": true,
                "idle_timeout": settings.idle_timeout,
                "never_times_out": settings.never_times_out(),
                "lock_on_sleep": settings.lock_on_sleep,
                "changed": changing,
            }))
        );
        return Ok(());
    }
    println!(
        "{}",
        keychain::output::field_list(&[
            (
                "idle timeout",
                if settings.never_times_out() {
                    "never".to_string()
                } else {
                    format!("{}s", settings.idle_timeout)
                }
            ),
            ("lock on sleep", settings.lock_on_sleep.to_string()),
        ])
    );
    Ok(())
}

/// Parse `--set NAME=VALUE` assignments into attribute values.
///
/// Everything is written as a blob unless it parses as a number and the
/// relation says the attribute is one, which [`KeychainFile::update_item`]
/// checks; here the text is taken as given.
fn attribute_assignments(specs: &[String]) -> Result<Vec<(String, keychain::Value)>> {
    specs
        .iter()
        .map(|spec| {
            let (name, value) = spec
                .split_once('=')
                .ok_or_else(|| Error::other(format!("expected NAME=VALUE, got {spec:?}")))?;
            Ok((
                name.to_string(),
                keychain::Value::Blob(value.as_bytes().to_vec()),
            ))
        })
        .collect()
}

/// Parse `--attr NAME=VALUE` filters.
fn attribute_filters(specs: &[String]) -> Result<Vec<(String, String)>> {
    specs
        .iter()
        .map(|spec| {
            spec.split_once('=')
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .ok_or_else(|| Error::other(format!("expected NAME=VALUE, got {spec:?}")))
        })
        .collect()
}

/// Parse a four-character code such as `http`. Short codes are space-padded, the
/// way the codes stored in the format are.
fn four_char_code(text: Option<&str>) -> Result<Option<[u8; 4]>> {
    let Some(text) = text else {
        return Ok(None);
    };
    let bytes = text.as_bytes();
    if bytes.len() > 4 {
        return Err(Error::other(format!(
            "{text:?} is longer than four characters"
        )));
    }
    let mut code = *b"    ";
    code[..bytes.len()].copy_from_slice(bytes);
    Ok(Some(code))
}
