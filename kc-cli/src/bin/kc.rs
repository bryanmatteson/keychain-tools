//! `kc` — create and read macOS keychain files directly.
//!
//! The file format is parsed, decrypted, and written by this process: nothing
//! goes through the Security framework.

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use keychain::crypto::KeyBlob;
use keychain::edit::{ItemChanges, Settings};
use keychain::write::{CreateOptions, NewIdentity, NewItem, create, now_timestamp};
use keychain::{Error, Item, KeychainFile, Query, RecordType, Result};

#[path = "../config.rs"]
mod config;

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

    /// Permit a keychain access policy to ask for confirmation
    #[arg(long, global = true, action = ArgAction::SetTrue)]
    interactive: bool,

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
/// Environment variables and files avoid exposing a password in process
/// arguments. Omit the options to prompt; `-P` may also take a shell expression.
#[derive(Args, Clone, Debug, Default)]
struct PasswordSource {
    /// Use PASSWORD (visible in argv; prefer a shell expression)
    #[arg(
        short = 'P',
        long = "password",
        value_name = "PASSWORD",
        group = "password-source"
    )]
    password: Option<String>,

    /// Read the password from ENV_VAR [default when omitted: KC_PASSWORD]
    #[arg(
        short = 'E',
        visible_short_alias = 'e',
        long = "password-env",
        value_name = "ENV_VAR",
        num_args = 0..=1,
        default_missing_value = "KC_PASSWORD",
        group = "password-source"
    )]
    password_env: Option<String>,

    /// Read the keychain password from this file, or from stdin for `-`
    #[arg(
        short = 'F',
        visible_short_alias = 'f',
        long = "password-file",
        value_name = "FILE",
        group = "password-source"
    )]
    password_file: Option<PathBuf>,

    /// Generate a new password [default template when omitted: sha1]
    #[arg(
        long = "password-gen",
        value_name = "TEMPLATE",
        num_args = 0..=1,
        default_missing_value = "sha1",
        require_equals = true,
        group = "password-source"
    )]
    password_gen: Option<String>,

    /// Character policy for a generated password
    #[arg(long = "password-policy", value_enum, requires = "password_gen")]
    password_policy: Option<PasswordPolicy>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum PasswordPolicy {
    /// Letters and digits
    Alphanumeric,
    /// Letters and digits, with lowercase, uppercase, and a digit guaranteed
    MixedCase,
    /// Letters, digits, and punctuation
    Symbol,
    /// All classes, with lowercase, uppercase, digit, and punctuation guaranteed
    Secure,
}

/// Where a PKCS#12 container password comes from.
#[derive(Args, Clone, Debug, Default)]
struct Pkcs12PasswordSource {
    /// Prompt, or use PASSWORD (visible in argv; prefer a shell expression)
    #[arg(
        id = "pkcs12-password",
        long = "pkcs12-password",
        value_name = "PASSWORD",
        num_args = 0..=1,
        group = "pkcs12-password-source"
    )]
    password: Option<Option<String>>,

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
        if let Some(password) = &self.password {
            return password.clone().map_or_else(
                || {
                    rpassword::prompt_password("PKCS#12 password: ")
                        .map_err(|source| Error::io("could not read the PKCS#12 password", source))
                },
                Ok,
            );
        }
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
        self.password.is_some()
            || self.password_env.is_some()
            || self.password_file.is_some()
            || self.password_gen.is_some()
    }

    /// Resolve the password, prompting when nothing else supplies it.
    ///
    /// `confirm` asks twice, for a password that is being set rather than used.
    fn resolve(&self, confirm: bool) -> Result<String> {
        if let Some(password) = &self.password {
            return Ok(password.clone());
        }
        if let Some(template) = &self.password_gen {
            if !confirm {
                return Err(Error::other(
                    "--password-gen can only be used when setting a new password",
                ));
            }
            return generate_password(template, self.password_policy);
        }
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

    /// True when resolving the password would consume standard input.
    fn reads_stdin(&self) -> bool {
        self.password_file
            .as_ref()
            .is_some_and(|path| path.as_os_str() == "-")
    }

    /// The password, or `None` when the command has nothing to decrypt.
    fn resolve_optional(&self, required: bool) -> Result<Option<String>> {
        if !required && !self.is_explicit() {
            return Ok(None);
        }
        self.resolve(false).map(Some)
    }
}

fn generate_password(template: &str, policy: Option<PasswordPolicy>) -> Result<String> {
    match template {
        "sha1" if policy.is_none() => Ok(hex::encode(keychain::secret::random_bytes(20))),
        "sha1" => generate_policy_password(40, policy.expect("checked above")),
        _ => Err(Error::other(format!(
            "unknown password template {template:?}; expected sha1"
        ))),
    }
}

fn generate_policy_password(length: usize, policy: PasswordPolicy) -> Result<String> {
    const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"0123456789";
    const SYMBOLS: &[u8] = b"!#$%&()*+,-./:;<=>?@[]^_{|}~";

    let (alphabet, required): (Vec<u8>, &[&[u8]]) = match policy {
        PasswordPolicy::Alphanumeric => ([LOWER, UPPER, DIGITS].concat(), &[]),
        PasswordPolicy::MixedCase => ([LOWER, UPPER, DIGITS].concat(), &[LOWER, UPPER, DIGITS]),
        PasswordPolicy::Symbol => ([LOWER, UPPER, DIGITS, SYMBOLS].concat(), &[]),
        PasswordPolicy::Secure => (
            [LOWER, UPPER, DIGITS, SYMBOLS].concat(),
            &[LOWER, UPPER, DIGITS, SYMBOLS],
        ),
    };
    let mut output = Vec::with_capacity(length);
    for class in required {
        output.push(random_character(class));
    }
    while output.len() < length {
        output.push(random_character(&alphabet));
    }
    for index in (1..output.len()).rev() {
        let selected = random_index(index + 1);
        output.swap(index, selected);
    }
    String::from_utf8(output).map_err(|_| Error::other("generated password was not UTF-8"))
}

fn random_character(alphabet: &[u8]) -> u8 {
    alphabet[random_index(alphabet.len())]
}

fn random_index(upper: usize) -> usize {
    let limit = 256 - (256 % upper);
    loop {
        let byte = keychain::secret::random_bytes(1)[0] as usize;
        if byte < limit {
            return byte % upper;
        }
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

fn resolve_keychain(keychain: &Option<PathBuf>) -> Result<PathBuf> {
    config::Config::load()?.resolve(keychain.as_deref())
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

        /// Keychain-wide enforcement mode [default: hybrid]
        #[arg(long, value_enum, default_value = "hybrid")]
        access_mode: CliAccessMode,

        /// Default secret-access decision [default: prompt]
        #[arg(long, value_enum, default_value = "prompt")]
        access_default: CliAccessDefault,

        /// Create only the database, without saving an access policy
        #[arg(long, action = ArgAction::SetTrue)]
        no_access_policy: bool,

        /// Output path or bare keychain name
        keychain: PathBuf,
    },

    /// Show the keychain's format, tables, and key-derivation parameters
    Info { keychain: Option<PathBuf> },

    /// Query keychain items, certificates, and key records
    Get {
        #[command(flatten)]
        password: PasswordSource,

        /// ANDed FIELD:VALUE predicates
        #[arg(value_name = "PREDICATE")]
        predicates: Vec<String>,

        /// Parse one quoted query expression in addition to positional predicates
        #[arg(long = "where", value_name = "EXPRESSION")]
        expression: Option<String>,

        /// Output fields, `*` for detail, or `@ref` for mutation-safe references
        #[arg(
            short = 'o',
            long = "output",
            value_delimiter = ',',
            value_name = "FIELD,..."
        )]
        output: Vec<String>,

        /// Emit each projected row tuple only once, preserving first-seen order
        #[arg(short = 'u', long, action = ArgAction::SetTrue)]
        distinct: bool,

        /// Permit a secret projection to return more than one item
        #[arg(long, action = ArgAction::SetTrue)]
        all: bool,

        /// Override the environment or configured default keychain
        #[arg(long, value_name = "KEYCHAIN")]
        keychain: Option<PathBuf>,
    },

    /// Check the keychain's internal consistency
    Verify {
        #[command(flatten)]
        password: PasswordSource,
        keychain: Option<PathBuf>,
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

    /// Change every item selected by a query or reference stream
    Set {
        /// NAME=VALUE assignments to apply
        #[arg(value_name = "ASSIGNMENT")]
        assignments: Vec<String>,

        /// Query expression, or `-` to consume `kc get -o @ref` from stdin
        #[arg(long = "for", required = true, value_name = "EXPRESSION|-")]
        selection: String,

        /// Replace the item secret; read from the terminal or stdin when the
        /// value is omitted
        #[arg(short = 'w', long = "secret", value_name = "SECRET", num_args = 0..=1)]
        secret: Option<Option<String>>,

        /// Permit a secret change to affect more than one item
        #[arg(long, action = ArgAction::SetTrue, requires = "secret")]
        all: bool,

        #[command(flatten)]
        password: PasswordSource,

        /// Override the environment or configured default keychain
        #[arg(long, value_name = "KEYCHAIN")]
        keychain: Option<PathBuf>,
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
        /// Pre-authorize no application, so securityd prompts every caller
        #[arg(long, action = ArgAction::SetTrue)]
        prompt: bool,

        keychain: Option<PathBuf>,
    },

    /// Copy an item into another keychain
    Cp {
        #[command(flatten)]
        password: PasswordSource,
        #[command(flatten)]
        selector: Selector,

        /// Prompt for the destination password, or use the supplied value
        #[arg(
            long = "to-password",
            value_name = "PASSWORD",
            num_args = 0..=1,
            group = "to-password-source"
        )]
        to_password: Option<Option<String>>,
        /// Password for the destination keychain, from an environment variable
        #[arg(
            long = "to-password-env",
            value_name = "NAME",
            group = "to-password-source"
        )]
        to_password_env: Option<String>,
        /// Password for the destination keychain, from a file
        #[arg(
            long = "to-password-file",
            value_name = "FILE",
            group = "to-password-source"
        )]
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

        /// Prompt for the new password, or use the supplied value
        #[arg(
            long = "new-password",
            value_name = "PASSWORD",
            num_args = 0..=1,
            group = "new-password-source"
        )]
        new_password: Option<Option<String>>,
        /// Generate the new password
        #[arg(long = "new-password-gen", value_name = "TEMPLATE", num_args = 0..=1, default_missing_value = "sha1", require_equals = true, group = "new-password-source")]
        new_password_gen: Option<String>,
        /// Character policy for a generated new password
        #[arg(
            long = "new-password-policy",
            value_enum,
            requires = "new_password_gen"
        )]
        new_password_policy: Option<PasswordPolicy>,
        /// New password, from an environment variable
        #[arg(
            long = "new-password-env",
            value_name = "NAME",
            group = "new-password-source"
        )]
        new_password_env: Option<String>,
        /// New password, from a file's first line
        #[arg(
            long = "new-password-file",
            value_name = "FILE",
            group = "new-password-source"
        )]
        new_password_file: Option<PathBuf>,

        keychain: Option<PathBuf>,
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

        keychain: Option<PathBuf>,
    },

    /// Print a shell completion script
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Show or change persistent keychain-name defaults
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Manage keychain-wide access policy
    Access {
        #[command(subcommand)]
        action: AccessAction,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show the configuration and effective search paths
    Show,
    /// Set a configuration property
    Set {
        /// Property: keychains.default or search.paths
        property: String,
        /// New value; search.paths accepts more than one
        #[arg(required = true, num_args = 1..)]
        values: Vec<String>,
    },
    /// Append values to a list property
    Append {
        /// List property: search.paths
        property: String,
        /// Values to append
        #[arg(required = true, num_args = 1..)]
        values: Vec<String>,
    },
    /// Prepend values to a list property
    Prepend {
        /// List property: search.paths
        property: String,
        /// Values to prepend
        #[arg(required = true, num_args = 1..)]
        values: Vec<String>,
    },
}

#[derive(Subcommand)]
enum AccessAction {
    /// Show the effective policy for a keychain
    Show { keychain: Option<PathBuf> },
    /// Set the authoritative policy for a keychain
    Set {
        /// Direct-reader default
        #[arg(long, value_enum)]
        default: Option<CliAccessDefault>,
        /// Enforcement mode
        #[arg(long, value_enum)]
        mode: Option<CliAccessMode>,
        /// Trust this signed application in native ACLs (repeatable)
        #[arg(short = 'T', long = "trust-app", value_name = "PATH")]
        trust_apps: Vec<PathBuf>,
        /// Trust PATH using a compiled requirement FILE (repeatable)
        #[arg(long = "trust-requirement", value_name = "PATH=FILE")]
        trust_requirements: Vec<String>,
        /// Remove all trusted-application entries
        #[arg(long, action = ArgAction::SetTrue)]
        clear_trust: bool,
        keychain: Option<PathBuf>,
    },
    /// Remove the configured policy for a keychain
    Clear { keychain: Option<PathBuf> },
    /// Project the policy onto every password and private-key item
    Apply {
        #[command(flatten)]
        password: PasswordSource,
        /// Projection target
        #[arg(long, value_enum, default_value = "securityd")]
        to: AccessProjection,
        keychain: Option<PathBuf>,
    },
    /// Compare every native item ACL with the configured policy
    Audit {
        /// Policy representation to compare
        #[arg(long, value_enum, default_value = "securityd")]
        against: AccessProjection,
        keychain: Option<PathBuf>,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum CliAccessMode {
    Extended,
    Native,
    Hybrid,
}

impl From<CliAccessMode> for keychain::AccessMode {
    fn from(value: CliAccessMode) -> Self {
        match value {
            CliAccessMode::Extended => Self::Extended,
            CliAccessMode::Native => Self::Native,
            CliAccessMode::Hybrid => Self::Hybrid,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum CliAccessDefault {
    Allow,
    Prompt,
    Deny,
}

impl From<CliAccessDefault> for keychain::AccessDefault {
    fn from(value: CliAccessDefault) -> Self {
        match value {
            CliAccessDefault::Allow => Self::Allow,
            CliAccessDefault::Prompt => Self::Prompt,
            CliAccessDefault::Deny => Self::Deny,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum AccessProjection {
    Securityd,
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
        #[arg(short = 'l', visible_short_alias = 'L', long)]
        label: Option<String>,
        /// Restrict use of the private key to this application (repeatable)
        #[arg(short = 'T', long = "trust-app", value_name = "PATH")]
        trust_apps: Vec<PathBuf>,
        /// Restrict use using a PATH=REQUIREMENT_FILE pair (repeatable)
        #[arg(long = "trust-requirement", value_name = "PATH=FILE")]
        trust_requirements: Vec<String>,
        /// Combined PEM identity or PKCS#12/PFX file, in PEM or DER form
        input: PathBuf,
        keychain: Option<PathBuf>,
    },
}

/// Which item a mutating command acts on.
///
/// Legacy selector flags shared by commands whose platform-shaped syntax has
/// not moved to the item query language.
#[derive(Args, Clone, Debug, Default)]
struct Selector {
    /// Item class; without it, every password class is searched
    #[arg(short = 'c', long, value_enum)]
    class: Option<ItemClass>,
    /// Account name
    #[arg(short = 'a', long)]
    account: Option<String>,
    /// Service name (generic items)
    #[arg(short = 's', visible_short_alias = 'S', long)]
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
    #[arg(long)]
    port: Option<u32>,
    /// Volume (AppleShare items)
    #[arg(short = 'v', long)]
    volume: Option<String>,
    /// Item label (PrintName)
    #[arg(short = 'l', visible_short_alias = 'L', long)]
    label: Option<String>,
    /// Kind
    #[arg(long)]
    kind: Option<String>,
    /// Comment
    #[arg(short = 'C', long)]
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

        keychain: Option<PathBuf>,
    },

    /// Delete an identity: its certificate and its private key
    Identity {
        #[command(flatten)]
        password: PasswordSource,
        /// The identity's label (the certificate's PrintName)
        #[arg(short = 'l', visible_short_alias = 'L', long)]
        label: Option<String>,
        /// The identity's public key hash, as hex
        #[arg(long)]
        hash: Option<String>,

        keychain: Option<PathBuf>,
    },

    /// Delete a certificate, leaving its private key behind
    #[command(name = "cert", visible_alias = "certificate")]
    Certificate {
        #[command(flatten)]
        password: PasswordSource,
        /// The certificate's label (PrintName)
        #[arg(short = 'l', visible_short_alias = 'L', long)]
        label: Option<String>,
        /// The certificate's public key hash, as hex
        #[arg(long)]
        hash: Option<String>,

        keychain: Option<PathBuf>,
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
        #[arg(short = 'l', visible_short_alias = 'L', long)]
        label: Option<String>,
        /// Write DER instead of PEM
        #[arg(long, action = ArgAction::SetTrue)]
        der: bool,
        /// Write to this file instead of stdout
        #[arg(short = 'o', long)]
        out: Option<PathBuf>,
        keychain: Option<PathBuf>,
    },

    /// Write a private key out as unencrypted PKCS#8
    Key {
        #[command(flatten)]
        password: PasswordSource,
        #[arg(short = 'l', visible_short_alias = 'L', long)]
        label: Option<String>,
        #[arg(long, action = ArgAction::SetTrue)]
        der: bool,
        #[arg(short = 'o', long)]
        out: Option<PathBuf>,

        keychain: Option<PathBuf>,
    },

    /// Write both halves of an identity: certificate then private key
    Identity {
        #[command(flatten)]
        password: PasswordSource,
        #[arg(short = 'l', visible_short_alias = 'L', long)]
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

        keychain: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum AddKind {
    /// Store a generic password
    Generic {
        #[command(flatten)]
        password: PasswordSource,
        /// Account name
        #[arg(short = 'a', visible_short_alias = 'A', long)]
        account: String,
        /// Service name
        #[arg(short = 's', visible_short_alias = 'S', long)]
        service: String,
        /// Generic attribute: application-defined data stored with the item
        #[arg(short = 'G', long)]
        generic: Option<String>,
        /// The secret to store; read from the terminal or stdin when omitted
        #[arg(short = 'w', long)]
        secret: Option<String>,
        /// Item label, shown in Keychain Access [default: the service]
        #[arg(short = 'l', visible_short_alias = 'L', long)]
        label: Option<String>,
        /// Kind
        #[arg(short = 'D', long)]
        kind: Option<String>,
        /// Comment
        #[arg(short = 'j', visible_short_alias = 'C', long)]
        comment: Option<String>,
        /// Restrict decryption to this application (repeatable)
        #[arg(short = 'T', long = "trust-app", value_name = "PATH")]
        trust_apps: Vec<PathBuf>,
        /// Restrict decryption to an application named by a requirement blob
        /// from `csreq -b`, as PATH=FILE (repeatable)
        #[arg(long = "trust-requirement", value_name = "PATH=FILE")]
        trust_requirements: Vec<String>,

        keychain: Option<PathBuf>,
    },

    /// Store an internet password
    Internet {
        #[command(flatten)]
        password: PasswordSource,
        #[arg(short = 'a', visible_short_alias = 'A', long)]
        account: String,
        /// Server name
        #[arg(short = 's', long)]
        server: String,
        /// Security domain: the authentication realm
        /// (`-d`, as `security add-internet-password` spells it)
        #[arg(short = 'S', visible_short_alias = 'd', long)]
        security_domain: Option<String>,
        #[arg(short = 'w', long)]
        secret: Option<String>,
        #[arg(short = 'l', visible_short_alias = 'L', long)]
        label: Option<String>,
        /// Path
        #[arg(long)]
        path: Option<String>,
        /// Port
        #[arg(long)]
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
        #[arg(short = 'j', visible_short_alias = 'C', long)]
        comment: Option<String>,
        /// Restrict decryption to this application (repeatable)
        #[arg(short = 'T', long = "trust-app", value_name = "PATH")]
        trust_apps: Vec<PathBuf>,
        /// Restrict decryption to an application named by a requirement blob
        /// from `csreq -b`, as PATH=FILE (repeatable)
        #[arg(long = "trust-requirement", value_name = "PATH=FILE")]
        trust_requirements: Vec<String>,

        keychain: Option<PathBuf>,
    },

    /// Store an AppleShare password
    #[command(name = "appleshare")]
    AppleShare {
        #[command(flatten)]
        password: PasswordSource,
        #[arg(short = 'a', visible_short_alias = 'A', long)]
        account: String,
        /// Volume name
        #[arg(short = 'v', long)]
        volume: String,
        #[arg(short = 'w', long)]
        secret: Option<String>,
        #[arg(short = 'l', visible_short_alias = 'L', long)]
        label: Option<String>,
        /// Server name
        #[arg(short = 's', visible_short_alias = 'S', long)]
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
        #[arg(short = 'j', visible_short_alias = 'C', long)]
        comment: Option<String>,
        /// Restrict decryption to this application (repeatable)
        #[arg(short = 'T', long = "trust-app", value_name = "PATH")]
        trust_apps: Vec<PathBuf>,
        /// Restrict decryption to an application named by a requirement blob
        /// from `csreq -b`, as PATH=FILE (repeatable)
        #[arg(long = "trust-requirement", value_name = "PATH=FILE")]
        trust_requirements: Vec<String>,

        keychain: Option<PathBuf>,
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
        /// Private key file: an unencrypted PKCS#8 or PKCS#1 RSA key, PEM or DER
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
        #[arg(short = 'l', visible_short_alias = 'L', long)]
        label: Option<String>,
        /// Restrict use of the private key to this application (repeatable)
        #[arg(short = 'T', long = "trust-app", value_name = "PATH")]
        trust_apps: Vec<PathBuf>,
        /// Restrict use of the private key to an application named by a
        /// requirement blob from `csreq -b`, as PATH=FILE (repeatable)
        #[arg(long = "trust-requirement", value_name = "PATH=FILE")]
        trust_requirements: Vec<String>,

        keychain: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    // A CLI should die quietly when its output pipe closes.
    // SAFETY: setting a signal disposition before any threads exist.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let arguments = std::env::args_os().collect::<Vec<_>>();
    if arguments.len() == 3
        && arguments[1] == "add"
        && matches!(arguments[2].to_str(), Some("-h" | "--help"))
    {
        print_add_help();
        return ExitCode::SUCCESS;
    }
    let arguments = match normalize_arguments(arguments) {
        Ok(arguments) => arguments,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "kc: {error}");
            return ExitCode::from(2);
        }
    };
    let cli = Cli::parse_from(arguments);
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

fn print_add_help() {
    println!(
        "Store a password item or identity\n\n\
         Usage:\n  \
           kc add class=CLASS NAME=VALUE... [OPTIONS]\n  \
           kc add identity (--cert FILE --key FILE | --pkcs12 FILE) [OPTIONS] [KEYCHAIN]\n\n\
         Password item classes:\n  \
           generic, internet, appleshare\n\n\
         Options:\n  \
           -w, --secret <SECRET>              Secret; stdin or prompt when omitted\n  \
           -P, --password <PASSWORD>          Keychain password\n  \
           -E, --password-env [ENV_VAR]       Password environment variable [KC_PASSWORD]\n  \
           -F, --password-file <FILE>         Password file; use - for stdin\n  \
           -T, --trust-app <PATH>             Trusted application (repeatable)\n  \
               --trust-requirement <PATH=FILE>\n  \
               --keychain <KEYCHAIN>          Override the effective default\n  \
           -h, --help                         Print help\n\n\
         Examples:\n  \
           kc add class=generic account=machina service=vpn kind=\"api key\"\n  \
           kc add class=internet account=alice server=imap.example.com port=443\n  \
           kc add identity -c certificate.pem -k private-key.pem login"
    );
}

/// Lower the assignment form of `kc add` into the strongly typed legacy
/// subcommands that still implement password-item construction.
///
/// This keeps one schema-aware writer while the public CLI gains the uniform
/// `class=... name=value` grammar.
fn normalize_arguments(
    arguments: Vec<std::ffi::OsString>,
) -> std::result::Result<Vec<std::ffi::OsString>, String> {
    if arguments.len() < 3
        || arguments[1] != "add"
        || !arguments[2..]
            .iter()
            .any(|argument| argument.to_string_lossy().starts_with("class="))
    {
        return Ok(arguments);
    }

    let mut assignments = Vec::<(String, String)>::new();
    let mut passthrough = Vec::<std::ffi::OsString>::new();
    let mut keychain = None;
    let mut index = 2;
    while index < arguments.len() {
        let argument = arguments[index].to_string_lossy();
        if argument == "--keychain" {
            let value = arguments
                .get(index + 1)
                .ok_or_else(|| "--keychain requires a value".to_string())?;
            keychain = Some(value.clone());
            index += 2;
            continue;
        }
        if let Some(value) = argument.strip_prefix("--keychain=") {
            keychain = Some(std::ffi::OsString::from(value));
            index += 1;
            continue;
        }
        if !argument.starts_with('-') {
            let (name, value) = argument
                .split_once('=')
                .ok_or_else(|| format!("expected NAME=VALUE assignment, got {argument:?}"))?;
            assignments.push((name.to_string(), value.to_string()));
            index += 1;
            continue;
        }

        passthrough.push(arguments[index].clone());
        if matches!(argument.as_ref(), "-E" | "-e" | "--password-env") {
            let optional_value = arguments.get(index + 1).filter(|value| {
                let value = value.to_string_lossy();
                !value.starts_with('-') && !value.contains('=')
            });
            if let Some(value) = optional_value {
                passthrough.push(value.clone());
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        let option_takes_value = matches!(
            argument.as_ref(),
            "-P" | "--password"
                | "-F"
                | "--password-file"
                | "-w"
                | "--secret"
                | "-T"
                | "--trust-app"
                | "--trust-requirement"
        );
        if option_takes_value {
            let value = arguments
                .get(index + 1)
                .ok_or_else(|| format!("{argument} requires a value"))?;
            passthrough.push(value.clone());
            index += 2;
        } else {
            index += 1;
        }
    }

    let class = take_assignment(&mut assignments, &["class"])?
        .ok_or_else(|| "kc add requires class=generic|internet|appleshare".to_string())?;
    if !matches!(class.as_str(), "generic" | "internet" | "appleshare") {
        return Err(format!(
            "unsupported password-item class {class:?}; expected generic, internet, or appleshare"
        ));
    }

    let mut lowered = vec![
        arguments[0].clone(),
        std::ffi::OsString::from("add"),
        std::ffi::OsString::from(&class),
    ];
    let mut seen = std::collections::BTreeMap::<String, String>::new();
    for (name, value) in assignments {
        let canonical = keychain::query::canonical_field(&name).to_string();
        if let Some(previous) = seen.insert(canonical.to_ascii_lowercase(), name.clone()) {
            return Err(format!(
                "duplicate assignments {previous:?} and {name:?} name the same attribute"
            ));
        }
        let option = match (class.as_str(), canonical.as_str()) {
            (_, "PrintName") => "--label",
            (_, "acct") => "--account",
            (_, "desc") => "--kind",
            (_, "icmt") => "--comment",
            ("generic", "svce") => "--service",
            ("generic", "gena") => "--generic",
            ("internet", "srvr") | ("appleshare", "srvr") => "--server",
            ("internet", "sdmn") => "--security-domain",
            ("internet", "path") => "--path",
            ("internet", "port") => "--port",
            ("internet", "ptcl") | ("appleshare", "ptcl") => "--protocol",
            ("internet", "atyp") => "--auth-type",
            ("appleshare", "vlme") => "--volume",
            ("appleshare", "addr") => "--address",
            ("appleshare", "ssig") => "--signature",
            (_, "class") => return Err("class may only be assigned once".to_string()),
            _ => {
                return Err(format!(
                    "{class} items have no assignable attribute {name:?}"
                ));
            }
        };
        lowered.push(std::ffi::OsString::from(option));
        lowered.push(std::ffi::OsString::from(value));
    }
    lowered.extend(passthrough);
    if let Some(keychain) = keychain {
        lowered.push(keychain);
    }
    Ok(lowered)
}

fn take_assignment(
    assignments: &mut Vec<(String, String)>,
    names: &[&str],
) -> std::result::Result<Option<String>, String> {
    let matches = assignments
        .iter()
        .enumerate()
        .filter(|(_, (name, _))| names.iter().any(|wanted| name.eq_ignore_ascii_case(wanted)))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Ok(None),
        [index] => Ok(Some(assignments.remove(*index).1)),
        _ => Err(format!("{} may only be assigned once", names[0])),
    }
}

fn run(cli: &Cli) -> Result<()> {
    // `--format secret` says "print the secret and nothing else", which only
    // means something for the commands that read secrets.
    if cli.secrets_only() && !matches!(cli.command, Command::Get { .. }) {
        return Err(Error::other(
            "--format secret applies to `get`, the command that reads secrets",
        ));
    }

    match &cli.command {
        Command::Create {
            password,
            idle_timeout,
            no_lock_on_sleep,
            access_mode,
            access_default,
            no_access_policy,
            keychain,
        } => {
            let mut config = config::Config::load()?;
            let keychain = config.resolve(Some(keychain))?;
            if keychain.exists() {
                return Err(Error::other(format!(
                    "{} already exists",
                    keychain.display()
                )));
            }
            let generated_password = password.password_gen.is_some();
            let password = password.resolve(true)?;
            let options = CreateOptions {
                idle_timeout: *idle_timeout,
                lock_on_sleep: !no_lock_on_sleep,
            };
            let file = create(password.as_bytes(), &options)?;
            file.save(&keychain)?;
            if !no_access_policy {
                config.set_access_policy(config::ConfiguredAccessPolicy {
                    keychain: keychain.to_string_lossy().into_owned(),
                    mode: (*access_mode).into(),
                    default: (*access_default).into(),
                    trust_apps: Vec::new(),
                    trust_requirements: Vec::new(),
                });
                config.save()?;
            }
            let generated = generated_password.then_some(password.as_str());
            report(
                cli,
                &generated.map_or_else(
                    || format!("created {}", keychain.display()),
                    |value| format!("created {}\npassword: {value}", keychain.display()),
                ),
                || {
                    serde_json::json!({
                        "ok": true,
                        "keychain": keychain,
                        "generated_password": generated,
                    })
                },
            );
            Ok(())
        }

        Command::Info { keychain } => info(cli, &resolve_keychain(keychain)?),

        Command::Get {
            password,
            predicates,
            expression,
            output,
            distinct,
            all,
            keychain,
        } => get_command(
            cli,
            password,
            GetRequest {
                predicates,
                whole_expression: expression.as_deref(),
                output,
                distinct: *distinct,
                allow_many_secrets: *all,
                keychain,
            },
        ),

        Command::Verify { password, keychain } => {
            verify(cli, &resolve_keychain(keychain)?, password)
        }

        Command::Add { kind } => add_command(cli, kind),

        Command::Import { kind } => import_command(cli, kind),

        Command::Set {
            assignments,
            selection,
            secret,
            all,
            password,
            keychain,
        } => set_query_command(
            cli,
            assignments,
            selection,
            secret,
            *all,
            password,
            keychain,
        ),

        Command::Rm { kind } => rm_command(cli, kind),

        Command::Trust {
            password,
            selector,
            trust_apps,
            trust_requirements,
            any,
            prompt,
            keychain,
        } => {
            let trusted = trusted_applications(trust_apps, trust_requirements)?;
            if trusted.is_empty() && !any && !prompt {
                return Err(Error::other(
                    "name an application with -T, pass --prompt, or pass -A to allow any",
                ));
            }
            if [!trusted.is_empty(), *any, *prompt]
                .into_iter()
                .filter(|selected| *selected)
                .count()
                > 1
            {
                return Err(Error::other(
                    "-A, --prompt, and trusted applications are mutually exclusive",
                ));
            }
            let access = if *any {
                keychain::ApplicationAccess::AllowAny
            } else if *prompt {
                keychain::ApplicationAccess::Prompt
            } else {
                keychain::ApplicationAccess::TrustedApplications(trusted)
            };
            trust_command(
                cli,
                &resolve_keychain(keychain)?,
                password,
                selector,
                &access,
            )
        }

        Command::Cp {
            password,
            selector,
            to_password,
            to_password_env,
            to_password_file,
            trust_apps,
            trust_requirements,
            source,
            destination,
        } => {
            let source = resolve_keychain(&Some(source.clone()))?;
            let destination = resolve_keychain(&Some(destination.clone()))?;
            let to = PasswordSource {
                password: to_password.as_ref().and_then(Clone::clone),
                password_env: to_password_env.clone(),
                password_file: to_password_file.clone(),
                password_gen: None,
                password_policy: None,
            };
            let destination_password = if matches!(to_password, Some(None)) {
                DestinationPassword::Prompt
            } else {
                DestinationPassword::Source(&to)
            };
            copy_command(
                cli,
                &source,
                &destination,
                password,
                destination_password,
                selector,
                &application_access_for_write(&destination, trust_apps, trust_requirements)?,
            )
        }

        Command::Export { kind } => export_command(cli, kind),

        Command::Passwd {
            password,
            new_password,
            new_password_gen,
            new_password_policy,
            new_password_env,
            new_password_file,
            keychain,
        } => {
            let new = PasswordSource {
                password: new_password.as_ref().and_then(Clone::clone),
                password_env: new_password_env.clone(),
                password_file: new_password_file.clone(),
                password_gen: new_password_gen.clone(),
                password_policy: *new_password_policy,
            };
            passwd_command(cli, &resolve_keychain(keychain)?, password, &new)
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
            &resolve_keychain(keychain)?,
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

        Command::Config { action } => config_command(cli, action),

        Command::Access { action } => access_command(cli, action),
    }
}

fn config_command(cli: &Cli, action: &ConfigAction) -> Result<()> {
    let mut config = config::Config::load()?;
    match action {
        ConfigAction::Show => {
            let path = config::Config::path()?;
            let search_paths = config.all_search_paths()?;
            let environment_default = std::env::var_os("KC_DEFAULT_KEYCHAIN")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from);
            let effective_default = config.resolve(None)?;
            let default_source = if environment_default.is_some() {
                "KC_DEFAULT_KEYCHAIN"
            } else {
                "keychains.default"
            };
            if cli.is_json() {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "path": path,
                        "keychains": { "default": config.default },
                        "effective": {
                            "keychain": effective_default,
                            "source": default_source,
                        },
                        "search": { "paths": search_paths },
                    })
                );
            } else {
                println!("path: {}", path.display());
                println!("keychains.default: {}", config.default);
                println!("effective.keychain: {}", effective_default.display());
                println!("effective.source: {default_source}");
                for search_path in search_paths {
                    println!("search.paths: {}", search_path.display());
                }
            }
            Ok(())
        }
        ConfigAction::Set { property, values } => match property.as_str() {
            "keychains.default" => {
                if values.len() != 1 {
                    return Err(Error::other("keychains.default takes exactly one keychain"));
                }
                config.default.clone_from(&values[0]);
                let path = config.save()?;
                report(cli, &format!("keychains.default: {}", values[0]), || {
                    serde_json::json!({
                        "ok": true,
                        "path": path,
                        "property": property,
                        "value": values[0],
                    })
                });
                Ok(())
            }
            "search.paths" => {
                config.search_paths = values.iter().map(PathBuf::from).collect();
                let path = config.save()?;
                report(cli, &format!("search.paths: {}", values.join(", ")), || {
                    serde_json::json!({
                        "ok": true,
                        "path": path,
                        "property": property,
                        "value": values,
                    })
                });
                Ok(())
            }
            _ => Err(Error::other(format!(
                "unknown configuration property {property:?}; expected keychains.default or search.paths"
            ))),
        },
        ConfigAction::Append { property, values } => {
            update_list_property(cli, &mut config, property, values, false)
        }
        ConfigAction::Prepend { property, values } => {
            update_list_property(cli, &mut config, property, values, true)
        }
    }
}

fn update_list_property(
    cli: &Cli,
    config: &mut config::Config,
    property: &str,
    values: &[String],
    prepend: bool,
) -> Result<()> {
    if property != "search.paths" {
        return Err(Error::other(format!(
            "{property:?} is not a list property; append and prepend support search.paths"
        )));
    }
    let mut additions = Vec::new();
    for value in values {
        let path = PathBuf::from(value);
        if !additions.contains(&path) {
            additions.push(path);
        }
    }
    config.search_paths.retain(|path| !additions.contains(path));
    if prepend {
        let mut paths = additions;
        paths.append(&mut config.search_paths);
        config.search_paths = paths;
    } else {
        config.search_paths.extend(additions);
    }
    let path = config.save()?;
    let operation = if prepend { "prepend" } else { "append" };
    report(
        cli,
        &format!("{operation} search.paths: {}", values.join(", ")),
        || {
            serde_json::json!({
                "ok": true,
                "path": path,
                "operation": operation,
                "property": property,
                "value": config.search_paths,
            })
        },
    );
    Ok(())
}

fn access_command(cli: &Cli, action: &AccessAction) -> Result<()> {
    let mut config = config::Config::load()?;
    match action {
        AccessAction::Show { keychain } => {
            let path = config.resolve(keychain.as_deref())?;
            let policy = config.access_policy_for(&path)?;
            let Some(policy) = policy else {
                return Err(Error::other(format!(
                    "{} has no configured access policy",
                    path.display()
                )));
            };
            report_access_policy(cli, &path, policy);
            Ok(())
        }
        AccessAction::Set {
            default,
            mode,
            trust_apps,
            trust_requirements,
            clear_trust,
            keychain,
        } => {
            if *clear_trust && (!trust_apps.is_empty() || !trust_requirements.is_empty()) {
                return Err(Error::other(
                    "--clear-trust cannot be combined with trusted applications",
                ));
            }
            let path = config.resolve(keychain.as_deref())?;
            let existing = config.access_policy_for(&path)?.cloned();
            let selector = existing.as_ref().map_or_else(
                || {
                    keychain.as_ref().map_or_else(
                        || config.default.clone(),
                        |path| path.to_string_lossy().into_owned(),
                    )
                },
                |policy| policy.keychain.clone(),
            );
            let mut policy = existing.unwrap_or(config::ConfiguredAccessPolicy {
                keychain: selector,
                mode: keychain::AccessMode::Hybrid,
                default: keychain::AccessDefault::Prompt,
                trust_apps: Vec::new(),
                trust_requirements: Vec::new(),
            });
            if let Some(mode) = mode {
                policy.mode = (*mode).into();
            }
            if let Some(default) = default {
                policy.default = (*default).into();
            }
            if *clear_trust {
                policy.trust_apps.clear();
                policy.trust_requirements.clear();
            } else if !trust_apps.is_empty() || !trust_requirements.is_empty() {
                policy.trust_apps.clone_from(trust_apps);
                policy.trust_requirements = trust_requirements
                    .iter()
                    .map(|spec| requirement_source(spec))
                    .collect::<Result<_>>()?;
            }
            config.set_access_policy(policy.clone());
            let saved = config.save()?;
            if cli.is_json() {
                println!(
                    "{}",
                    keychain::output::pretty(&serde_json::json!({
                        "ok": true,
                        "path": saved,
                        "keychain": path,
                        "policy": access_policy_json(&policy),
                    }))
                );
            } else {
                println!("access policy saved: {}", saved.display());
                report_access_policy(cli, &path, &policy);
            }
            Ok(())
        }
        AccessAction::Clear { keychain } => {
            let path = config.resolve(keychain.as_deref())?;
            let selector = config
                .access_policy_for(&path)?
                .map(|policy| policy.keychain.clone())
                .ok_or_else(|| {
                    Error::other(format!(
                        "{} has no configured access policy",
                        path.display()
                    ))
                })?;
            config.clear_access_policy(&selector);
            let saved = config.save()?;
            report(
                cli,
                &format!("access policy removed: {}", path.display()),
                || {
                    serde_json::json!({
                        "ok": true,
                        "path": saved,
                        "keychain": path,
                        "removed": true,
                    })
                },
            );
            Ok(())
        }
        AccessAction::Apply {
            password,
            to: AccessProjection::Securityd,
            keychain,
        } => apply_access_policy(cli, &config, keychain.as_deref(), password),
        AccessAction::Audit {
            against: AccessProjection::Securityd,
            keychain,
        } => audit_access_policy(cli, &config, keychain.as_deref()),
    }
}

fn report_access_policy(cli: &Cli, path: &Path, policy: &config::ConfiguredAccessPolicy) {
    if cli.is_json() {
        println!(
            "{}",
            keychain::output::pretty(&serde_json::json!({
                "ok": true,
                "keychain": path,
                "policy": access_policy_json(policy),
            }))
        );
    } else {
        println!(
            "{}",
            keychain::output::field_list(&[
                ("keychain", path.display().to_string()),
                ("selector", policy.keychain.clone()),
                ("mode", config::access_mode_name(policy.mode).to_string()),
                (
                    "default",
                    config::access_default_name(policy.default).to_string()
                ),
                (
                    "trusted apps",
                    (policy.trust_apps.len() + policy.trust_requirements.len()).to_string()
                ),
            ])
        );
        for path in &policy.trust_apps {
            println!("trust-app: {}", path.display());
        }
        for source in &policy.trust_requirements {
            println!(
                "trust-requirement: {}={}",
                source.application.display(),
                source.file.display()
            );
        }
    }
}

fn access_policy_json(policy: &config::ConfiguredAccessPolicy) -> serde_json::Value {
    serde_json::json!({
        "selector": policy.keychain,
        "mode": config::access_mode_name(policy.mode),
        "default": config::access_default_name(policy.default),
        "trust_apps": policy.trust_apps,
        "trust_requirements": policy.trust_requirements.iter().map(|source| {
            serde_json::json!({
                "application": source.application,
                "file": source.file,
            })
        }).collect::<Vec<_>>(),
    })
}

fn requirement_source(spec: &str) -> Result<config::RequirementSource> {
    let (application, file) = spec
        .split_once('=')
        .ok_or_else(|| Error::other(format!("expected PATH=FILE, got {spec:?}")))?;
    if application.is_empty() || file.is_empty() {
        return Err(Error::other(format!("expected PATH=FILE, got {spec:?}")));
    }
    Ok(config::RequirementSource {
        application: PathBuf::from(application),
        file: PathBuf::from(file),
    })
}

fn resolved_access_policy(
    config: &config::Config,
    path: &Path,
) -> Result<Option<keychain::AccessPolicy>> {
    config
        .access_policy_for(path)?
        .map(|policy| {
            Ok(keychain::AccessPolicy {
                mode: policy.mode,
                default: policy.default,
                trusted_applications: configured_trusted_applications(policy)?,
            })
        })
        .transpose()
}

fn configured_trusted_applications(
    policy: &config::ConfiguredAccessPolicy,
) -> Result<Vec<keychain::TrustedApplication>> {
    let mut applications =
        Vec::with_capacity(policy.trust_apps.len() + policy.trust_requirements.len());
    for path in &policy.trust_apps {
        applications.push(keychain::requirement::for_application(path)?);
    }
    for source in &policy.trust_requirements {
        let blob =
            std::fs::read(&source.file).map_err(|error| Error::reading(&source.file, error))?;
        applications.push(keychain::requirement::from_blob(
            source.application.to_string_lossy(),
            blob,
        )?);
    }
    Ok(applications)
}

fn apply_access_policy(
    cli: &Cli,
    config: &config::Config,
    keychain: Option<&Path>,
    password: &PasswordSource,
) -> Result<()> {
    let path = config.resolve(keychain)?;
    let policy = resolved_access_policy(config, &path)?.ok_or_else(|| {
        Error::other(format!(
            "{} has no configured access policy",
            path.display()
        ))
    })?;
    if policy.default == keychain::AccessDefault::Deny {
        return Err(Error::other(
            "securityd ACLs cannot represent an unconditional deny policy",
        ));
    }
    let mut file = KeychainFile::open(&path)?;
    let password = password.resolve(false)?;
    file.unlock(password.as_bytes())?;
    let password_items: Vec<_> = file
        .items()
        .iter()
        .map(|item| (item.record_type, item.number()))
        .collect();
    let private_keys: Vec<_> = file
        .records_of_type(RecordType::PRIVATE_KEY)
        .iter()
        .map(|record| record.number)
        .collect();
    let expected = policy.native_application_access();
    for (record_type, number) in &password_items {
        file.set_item_access(*record_type, *number, &expected)?;
    }
    for number in &private_keys {
        file.set_private_key_access(*number, &expected)?;
    }
    file.save(&path)?;

    let count = password_items.len() + private_keys.len();
    report(
        cli,
        &format!("applied access policy to {count} item(s)"),
        || {
            serde_json::json!({
                "ok": true,
                "keychain": path,
                "target": "securityd",
                "items_updated": count,
            })
        },
    );
    Ok(())
}

fn audit_access_policy(cli: &Cli, config: &config::Config, keychain: Option<&Path>) -> Result<()> {
    let path = config.resolve(keychain)?;
    let policy = resolved_access_policy(config, &path)?.ok_or_else(|| {
        Error::other(format!(
            "{} has no configured access policy",
            path.display()
        ))
    })?;
    let file = KeychainFile::open(&path)?;
    let expected = policy.native_application_access();
    let mut total = 0usize;
    let mut matching = 0usize;
    let mut unknown = 0usize;

    for item in file.items() {
        total += 1;
        match file.item_application_access(item.record_type, item.number())? {
            Some(actual) if actual == expected => matching += 1,
            Some(_) => {}
            None => unknown += 1,
        }
    }
    for record in file.records_of_type(RecordType::PRIVATE_KEY) {
        let number = record.number;
        total += 1;
        match file.private_key_application_access(number)? {
            Some(actual) if actual == expected => matching += 1,
            Some(_) => {}
            None => unknown += 1,
        }
    }
    let ok = matching == total;
    if cli.is_json() {
        println!(
            "{}",
            keychain::output::pretty(&serde_json::json!({
                "ok": ok,
                "keychain": path,
                "against": "securityd",
                "items": total,
                "matching": matching,
                "mismatched": total - matching - unknown,
                "unknown": unknown,
            }))
        );
    } else {
        println!(
            "{}",
            keychain::output::field_list(&[
                ("keychain", path.display().to_string()),
                ("items", total.to_string()),
                ("matching", matching.to_string()),
                ("mismatched", (total - matching - unknown).to_string()),
                ("unknown", unknown.to_string()),
            ])
        );
    }
    if ok {
        Ok(())
    } else {
        Err(Error::other(
            "native item ACLs do not match the keychain policy",
        ))
    }
}

fn authorize_secret_access(cli: &Cli, keychain: &Path, operation: &str) -> Result<()> {
    let config = config::Config::load()?;
    let Some(policy) = config.access_policy_for(keychain)? else {
        return Ok(());
    };
    let decision = keychain::AccessPolicy {
        mode: policy.mode,
        default: policy.default,
        trusted_applications: Vec::new(),
    }
    .direct_decision();
    match decision {
        keychain::AccessDecision::Allow => Ok(()),
        keychain::AccessDecision::Deny => Err(Error::other(format!(
            "access policy denies permission to {operation} from {}",
            keychain.display()
        ))),
        keychain::AccessDecision::Prompt if !cli.interactive => Err(Error::other(format!(
            "access policy requires confirmation to {operation}; rerun with --interactive"
        ))),
        keychain::AccessDecision::Prompt => prompt_access(keychain, operation),
    }
}

fn prompt_access(keychain: &Path, operation: &str) -> Result<()> {
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|error| {
            Error::io(
                "access confirmation requires an interactive terminal",
                error,
            )
        })?;
    write!(
        tty,
        "Allow kc to {operation} from {}? [y/N] ",
        keychain.display()
    )
    .and_then(|()| tty.flush())
    .map_err(|error| Error::io("could not write the access confirmation", error))?;
    let mut answer = String::new();
    BufReader::new(tty)
        .read_line(&mut answer)
        .map_err(|error| Error::io("could not read the access confirmation", error))?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(Error::other("access was not approved"))
    }
}

fn application_access_for_write(
    keychain: &Path,
    paths: &[PathBuf],
    requirements: &[String],
) -> Result<keychain::ApplicationAccess> {
    if !paths.is_empty() || !requirements.is_empty() {
        return Ok(keychain::ApplicationAccess::TrustedApplications(
            trusted_applications(paths, requirements)?,
        ));
    }
    let config = config::Config::load()?;
    let Some(policy) = resolved_access_policy(&config, keychain)? else {
        return Ok(keychain::ApplicationAccess::AllowAny);
    };
    if policy.mode.projects_native() {
        Ok(policy.native_application_access())
    } else {
        Ok(keychain::ApplicationAccess::AllowAny)
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
            let keychain = resolve_keychain(keychain)?;
            let access = application_access_for_write(&keychain, trust_apps, trust_requirements)?;
            let item = NewItem {
                label: label.clone(),
                account: Some(account.clone()),
                service: Some(service.clone()),
                generic: generic.as_ref().map(|text| text.as_bytes().to_vec()),
                description: kind.clone(),
                comment: comment.clone(),
                ..NewItem::default()
            };
            add(
                cli,
                &keychain,
                password,
                RecordType::GENERIC_PASSWORD,
                item,
                secret,
                &access,
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
            let keychain = resolve_keychain(keychain)?;
            let access = application_access_for_write(&keychain, trust_apps, trust_requirements)?;
            let item = NewItem {
                label: label.clone(),
                account: Some(account.clone()),
                server: Some(server.clone()),
                security_domain: security_domain.clone(),
                path: path.clone(),
                port: *port,
                description: kind.clone(),
                comment: comment.clone(),
                protocol: four_char_code(protocol.as_deref())?,
                // `security` stores kSecAuthenticationTypeDefault when none is
                // given, and this attribute is part of the relation's unique
                // index, so it is defaulted the same way.
                auth_type: four_char_code(auth_type.as_deref())?.or(Some(*b"dflt")),
                ..NewItem::default()
            };
            add(
                cli,
                &keychain,
                password,
                RecordType::INTERNET_PASSWORD,
                item,
                secret,
                &access,
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
            let keychain = resolve_keychain(keychain)?;
            let access = application_access_for_write(&keychain, trust_apps, trust_requirements)?;
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
                ..NewItem::default()
            };
            add(
                cli,
                &keychain,
                password,
                RecordType::APPLESHARE_PASSWORD,
                item,
                secret,
                &access,
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
            let keychain = resolve_keychain(keychain)?;
            let access = application_access_for_write(&keychain, trust_apps, trust_requirements)?;
            let identity = if let Some(path) = pkcs12 {
                identity_from_file(path, pkcs12_password, label.clone(), Vec::new())?
            } else {
                if pkcs12_password.password.is_some()
                    || pkcs12_password.password_env.is_some()
                    || pkcs12_password.password_file.is_some()
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
                    private_key: read_private_key(key)?,
                    label: label.clone(),
                    trusted_applications: Vec::new(),
                }
            };
            add_identity(cli, &keychain, password, &identity, &access)
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
            let keychain = resolve_keychain(keychain)?;
            let access = application_access_for_write(&keychain, trust_apps, trust_requirements)?;
            let identity = identity_from_file(input, pkcs12_password, label.clone(), Vec::new())?;
            add_identity(cli, &keychain, password, &identity, &access)
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
    let container_password = if keychain::is_combined_pem(&data) {
        None
    } else {
        Some(password.resolve()?)
    };
    let bundle = keychain::decode_identity(&data, container_password.as_deref())?;
    Ok(NewIdentity {
        certificate: bundle.certificate,
        private_key: bundle.private_key,
        label: label.or(bundle.friendly_name),
        trusted_applications,
    })
}

struct GetRequest<'a> {
    predicates: &'a [String],
    whole_expression: Option<&'a str>,
    output: &'a [String],
    distinct: bool,
    allow_many_secrets: bool,
    keychain: &'a Option<PathBuf>,
}

fn get_command(cli: &Cli, password: &PasswordSource, request: GetRequest<'_>) -> Result<()> {
    let keychain = resolve_keychain(request.keychain)?;
    let mut expression = keychain::Expression::parse_predicates(request.predicates)?;
    if let Some(whole_expression) = request.whole_expression {
        expression
            .predicates
            .extend(keychain::Expression::parse(whole_expression)?.predicates);
    }

    let fields = if cli.secrets_only() {
        vec!["secret".to_string()]
    } else if request.output.is_empty() {
        vec![
            "class".to_string(),
            "label".to_string(),
            "kind".to_string(),
            "account".to_string(),
            "service".to_string(),
            "server".to_string(),
        ]
    } else {
        request.output.to_vec()
    };
    validate_projection(&fields)?;

    let wants_secret = fields.iter().any(|field| field == "secret");
    let mut file = KeychainFile::open(&keychain)?;
    let selected = file.select(&expression)?;
    if selected.is_empty() && !expression.is_empty() {
        return Err(Error::NoSuchItem);
    }
    if wants_secret && selected.len() > 1 && !request.allow_many_secrets {
        return Err(Error::other(format!(
            "{} items match a secret projection; narrow the query or pass --all",
            selected.len()
        )));
    }
    let selected = selected
        .iter()
        .map(|item| (item.record_type, item.number()))
        .collect::<Vec<_>>();

    if wants_secret {
        authorize_secret_access(cli, &keychain, "read item secrets")?;
        let password = password.resolve(false)?;
        file.unlock(password.as_bytes())?;
    } else if password.is_explicit()
        && let Some(password) = password.resolve_optional(false)?
    {
        file.unlock(password.as_bytes())?;
    }

    let items = selected
        .into_iter()
        .map(|(record_type, number)| {
            file.items_of_type(record_type)
                .into_iter()
                .find(|item| item.number() == number)
                .ok_or(Error::NoSuchItem)
        })
        .collect::<Result<Vec<_>>>()?;

    if fields == ["@ref"] {
        for item in &items {
            println!("{}", file.item_ref(item)?.encode());
        }
        return Ok(());
    }

    if cli.secrets_only() {
        let mut secrets = items
            .iter()
            .map(|item| file.secret(item).map(|secret| secret.as_slice().to_vec()))
            .collect::<Result<Vec<_>>>()?;
        if request.distinct {
            let mut seen = std::collections::BTreeSet::new();
            secrets.retain(|secret| seen.insert(secret.clone()));
        }
        let mut stdout = std::io::stdout();
        for secret in secrets {
            stdout
                .write_all(&secret)
                .and_then(|()| stdout.write_all(b"\n"))
                .map_err(|source| Error::io("could not write the secret", source))?;
        }
        return Ok(());
    }

    if fields == ["*"] {
        return render_full_get(cli, &file, &items);
    }

    let mut projected = items
        .iter()
        .map(|item| {
            fields
                .iter()
                .map(|field| get_property_json(&file, item, field, wants_secret))
                .collect::<Result<Vec<_>>>()
        })
        .collect::<Result<Vec<_>>>()?;
    if request.distinct {
        let mut seen = std::collections::BTreeSet::new();
        projected.retain(|row| {
            seen.insert(serde_json::to_string(row).expect("JSON values always serialize"))
        });
    }

    if cli.is_json() {
        let rendered = projected
            .into_iter()
            .map(|row| {
                fields
                    .iter()
                    .cloned()
                    .zip(row)
                    .collect::<serde_json::Map<_, _>>()
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            keychain::output::pretty(&serde_json::json!({
                "ok": true,
                "items": rendered,
            }))
        );
        return Ok(());
    }

    let rows = projected
        .into_iter()
        .map(|row| row.into_iter().map(get_property_text).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    print_rows(&rows);
    Ok(())
}

fn validate_projection(fields: &[String]) -> Result<()> {
    if fields.is_empty() {
        return Err(Error::other("output projection cannot be empty"));
    }
    if fields.iter().any(|field| field == "@ref") && fields != ["@ref"] {
        return Err(Error::other("@ref must be the only output projection"));
    }
    if fields.iter().any(|field| field == "*") && fields != ["*"] {
        return Err(Error::other("* must be the only output projection"));
    }
    let mut seen = std::collections::BTreeMap::<String, String>::new();
    for field in fields {
        let canonical = keychain::query::canonical_field(field).to_ascii_lowercase();
        if let Some(previous) = seen.insert(canonical, field.clone()) {
            return Err(Error::other(format!(
                "duplicate output fields {previous:?} and {field:?} name the same property"
            )));
        }
    }
    Ok(())
}

fn render_full_get(cli: &Cli, _file: &KeychainFile, items: &[Item<'_>]) -> Result<()> {
    if cli.is_json() {
        let rendered = items
            .iter()
            .map(|item| {
                let mut body = serde_json::Map::new();
                body.insert(
                    "class".to_string(),
                    serde_json::json!(keychain::query::class_name(item.record_type)),
                );
                body.insert("record".to_string(), serde_json::json!(item.number()));
                for (name, value) in item.attributes() {
                    body.insert(name.to_string(), value_json(name, value));
                }
                serde_json::Value::Object(body)
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            keychain::output::pretty(&serde_json::json!({
                "ok": true,
                "items": rendered,
            }))
        );
        return Ok(());
    }

    for (index, item) in items.iter().enumerate() {
        if index != 0 {
            println!();
        }
        let mut fields = vec![
            (
                "class",
                keychain::query::class_name(item.record_type)
                    .unwrap_or("unknown")
                    .to_string(),
            ),
            ("record", item.number().to_string()),
        ];
        for (name, value) in item.attributes() {
            fields.push((name, display_attribute(name, value)));
        }
        println!("{}", keychain::output::field_list(&fields));
    }
    Ok(())
}

fn get_property_json(
    file: &KeychainFile,
    item: &Item<'_>,
    field: &str,
    secrets_unlocked: bool,
) -> Result<serde_json::Value> {
    let canonical = keychain::query::canonical_field(field);
    Ok(match canonical {
        "class" => serde_json::json!(keychain::query::class_name(item.record_type)),
        "record" => serde_json::json!(item.number()),
        "has-secret" => serde_json::json!(item.has_secret()),
        "secret" if secrets_unlocked && item.has_secret() => {
            let secret = file.secret(item)?;
            serde_json::json!(String::from_utf8_lossy(secret.as_slice()))
        }
        "secret" => serde_json::Value::Null,
        "key-bits" | "item" | "trusted-apps" | "algorithm" | "wrapped-bytes" => {
            key_blob_property(item, canonical)
        }
        attribute => item
            .attribute(attribute)
            .map(|value| value_json(attribute, value))
            .unwrap_or(serde_json::Value::Null),
    })
}

fn get_property_text(value: serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "-".to_string(),
        serde_json::Value::String(value) => value,
        serde_json::Value::Array(values) => values
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>()
            .join(","),
        value => value.to_string(),
    }
}

fn value_json(name: &str, value: &keychain::Value) -> serde_json::Value {
    match value {
        keychain::Value::Uint32(value) => serde_json::json!(value),
        keychain::Value::Sint32(value) => serde_json::json!(value),
        _ => serde_json::json!(display_attribute(name, value)),
    }
}

fn key_blob_property(item: &Item<'_>, field: &str) -> serde_json::Value {
    let Ok(blob) = KeyBlob::parse(&item.record.key_data) else {
        return serde_json::Value::Null;
    };
    match field {
        "key-bits" => serde_json::json!(blob.header.logical_key_size_in_bits),
        "item" => serde_json::json!(blob.public_acl.item_name()),
        "trusted-apps" => serde_json::json!(blob.public_acl.trusted_paths()),
        "algorithm" => serde_json::json!(format!("0x{:x}", blob.header.algorithm_id)),
        "wrapped-bytes" => serde_json::json!(blob.crypto_blob.len()),
        _ => serde_json::Value::Null,
    }
}

fn print_rows(rows: &[Vec<String>]) {
    let columns = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths = (0..columns)
        .map(|column| {
            rows.iter()
                .filter_map(|row| row.get(column))
                .map(|value| value.chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect::<Vec<_>>();
    for row in rows {
        for (column, value) in row.iter().enumerate() {
            if column + 1 == row.len() {
                print!("{value}");
            } else {
                print!("{value:<width$}  ", width = widths[column]);
            }
        }
        println!();
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
    access: &keychain::ApplicationAccess,
) -> Result<()> {
    let mut file = KeychainFile::open(keychain)?;
    let password = password.resolve(false)?;
    file.unlock(password.as_bytes())?;

    let secret = item_secret(secret)?;
    file.add_password_with_access(
        record_type,
        &item,
        secret.as_bytes(),
        &now_timestamp(),
        access,
    )?;
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
    access: &keychain::ApplicationAccess,
) -> Result<()> {
    let mut file = KeychainFile::open(keychain)?;
    let password = password.resolve(false)?;
    file.unlock(password.as_bytes())?;

    let public_key_hash = file.add_identity_with_access(identity, access)?;
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

fn read_private_key(path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path)
        .map_err(|source| Error::io(format!("could not read {}", path.display()), source))?;
    keychain::der::decode_private_key(&bytes)
}

/// Check what a reader can check: blob signatures, key unwrapping, that every
/// item's key is present, and that every index region was understood.
fn verify(cli: &Cli, keychain: &Path, password: &PasswordSource) -> Result<()> {
    authorize_secret_access(cli, keychain, "verify item secrets")?;
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

/// Render an attribute for display, spelling four-char codes as text.
///
/// The same rendering query predicates and projections use for native fields.
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

fn set_query_command(
    cli: &Cli,
    assignments: &[String],
    selection: &str,
    secret: &Option<Option<String>>,
    all: bool,
    password: &PasswordSource,
    requested_keychain: &Option<PathBuf>,
) -> Result<()> {
    let changes = changes_from_assignments(assignments)?;
    if changes.is_empty() && secret.is_none() {
        return Err(Error::other(
            "nothing to change; pass NAME=VALUE assignments or -w, --secret",
        ));
    }
    // `--for -` gives stdin to the reference stream, so nothing else may read it.
    if selection == "-" {
        if password.reads_stdin() {
            return Err(Error::other(
                "`--for -` reads item references from stdin; name a password file instead of `-`",
            ));
        }
        if matches!(secret, Some(None)) {
            return Err(Error::other(
                "`--for -` reads item references from stdin; pass the new secret as `-w SECRET`",
            ));
        }
        if secret.is_some() && !password.is_explicit() {
            return Err(Error::other(
                "`--for -` reads item references from stdin; name the keychain password with -P, -E, or -F",
            ));
        }
    }

    let references = if selection == "-" {
        let references = std::io::stdin()
            .lock()
            .lines()
            .map(|line| {
                line.map_err(|source| Error::io("could not read item references", source))
                    .and_then(|line| keychain::ItemRef::decode(&line))
            })
            .collect::<Result<Vec<_>>>()?;
        if references.is_empty() {
            return Err(Error::other("no item references were read from stdin"));
        }
        Some(references)
    } else {
        None
    };
    let keychain = match (requested_keychain, references.as_ref()) {
        (Some(requested), _) => resolve_keychain(&Some(requested.clone()))?,
        (None, Some(references)) => references[0].keychain().to_path_buf(),
        (None, None) => resolve_keychain(&None)?,
    };
    if let Some(references) = &references
        && let Some(other) = references
            .iter()
            .find(|reference| reference.keychain() != keychain)
    {
        return Err(Error::other(format!(
            "item reference names {}, not {}",
            other.keychain().display(),
            keychain.display()
        )));
    }

    let mut file = KeychainFile::open(&keychain)?;
    // Attributes are stored in the clear, so changing them needs no key
    // material; a named password is still verified rather than ignored.
    // Re-sealing a secret needs the item key, so there the password is required.
    if secret.is_some() {
        authorize_secret_access(cli, &keychain, "change item secrets")?;
        let password = password.resolve(false)?;
        file.unlock(password.as_bytes())?;
    } else if password.is_explicit()
        && let Some(password) = password.resolve_optional(false)?
    {
        file.unlock(password.as_bytes())?;
    }

    let targets = if let Some(references) = references {
        let mut seen = std::collections::BTreeSet::new();
        let mut targets = Vec::with_capacity(references.len());
        for reference in &references {
            let item = file.resolve_ref(reference)?;
            if !is_password_class(item.record_type) {
                return Err(Error::other(format!(
                    "{} records cannot be changed with `kc set`",
                    keychain::query::class_name(item.record_type).unwrap_or("unknown")
                )));
            }
            if !seen.insert((item.record_type.0, item.number())) {
                return Err(Error::other(
                    "the reference stream contains a duplicate item",
                ));
            }
            targets.push((item.record_type, item.number(), item.label()));
        }
        targets
    } else {
        let expression = keychain::Expression::parse(selection)?;
        if expression.is_empty() {
            return Err(Error::other("--for must contain at least one predicate"));
        }
        let selected = file.select(&expression)?;
        if selected.is_empty() {
            return Err(Error::NoSuchItem);
        }
        selected
            .into_iter()
            .map(|item| {
                if !is_password_class(item.record_type) {
                    return Err(Error::other(format!(
                        "{} records cannot be changed with `kc set`",
                        keychain::query::class_name(item.record_type).unwrap_or("unknown")
                    )));
                }
                Ok((item.record_type, item.number(), item.label()))
            })
            .collect::<Result<Vec<_>>>()?
    };

    // Read the secret only once the target set is known, so a query that is too
    // broad fails before anything is typed or consumed from stdin.
    let secret = match secret {
        Some(flag) => {
            if targets.len() > 1 && !all {
                return Err(Error::other(format!(
                    "{} items match a secret change; narrow the query or pass --all",
                    targets.len()
                )));
            }
            Some(item_secret(flag)?)
        }
        None => None,
    };

    let timestamp = now_timestamp();
    for (record_type, number, _) in &targets {
        file.update_item(
            *record_type,
            *number,
            &changes,
            secret.as_deref().map(str::as_bytes),
            &timestamp,
        )?;
    }
    file.save(&keychain)?;

    report(cli, &format!("updated {} item(s)", targets.len()), || {
        serde_json::json!({
            "ok": true,
            "updated": targets.iter().map(|(record_type, number, label)| serde_json::json!({
                "class": keychain::query::class_name(*record_type),
                "record": number,
                "label": label,
            })).collect::<Vec<_>>(),
        })
    });
    Ok(())
}

fn changes_from_assignments(assignments: &[String]) -> Result<ItemChanges> {
    let mut changes = ItemChanges::default();
    let mut seen = std::collections::BTreeMap::<String, String>::new();
    for assignment in assignments {
        let (name, value) = assignment.split_once('=').ok_or_else(|| {
            Error::other(format!(
                "expected NAME=VALUE assignment, got {assignment:?}"
            ))
        })?;
        let canonical = keychain::query::canonical_field(name).to_string();
        if let Some(previous) = seen.insert(canonical.to_ascii_lowercase(), name.to_string()) {
            return Err(Error::other(format!(
                "duplicate assignments {previous:?} and {name:?} name the same attribute"
            )));
        }
        match canonical.as_str() {
            "secret" => {
                return Err(Error::other(format!(
                    "{name} is not an attribute; replace it with -w, --secret"
                )));
            }
            "class" | "record" | "has-secret" | "cdat" | "mdat" => {
                return Err(Error::other(format!("{name} cannot be changed")));
            }
            "PrintName" => changes.label = Some(value.to_string()),
            "desc" => changes.description = Some(value.to_string()),
            "icmt" => changes.comment = Some(value.to_string()),
            "gena" => changes.generic = Some(value.as_bytes().to_vec()),
            "sdmn" => changes.security_domain = Some(value.to_string()),
            attribute => changes.attributes.push((
                attribute.to_string(),
                keychain::Value::Blob(value.as_bytes().to_vec()),
            )),
        }
    }
    Ok(changes)
}

fn is_password_class(record_type: RecordType) -> bool {
    matches!(
        record_type,
        RecordType::GENERIC_PASSWORD
            | RecordType::INTERNET_PASSWORD
            | RecordType::APPLESHARE_PASSWORD
    )
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
            let keychain = resolve_keychain(keychain)?;
            if selector.is_empty() {
                return Err(Error::other(
                    "name the item to delete, for example with -a and -s",
                ));
            }
            let mut file = KeychainFile::open(&keychain)?;
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
            file.save(&keychain)?;

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
            &resolve_keychain(keychain)?,
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
            &resolve_keychain(keychain)?,
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
    access: &keychain::ApplicationAccess,
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
    file.set_item_access(record_type, number, access)?;
    file.save(keychain)?;

    report(cli, "access updated", || {
        serde_json::json!({
            "ok": true,
            "class": record_type.short_name(),
            "record": number,
            "label": label,
            "access": match access {
                keychain::ApplicationAccess::AllowAny => "allow-any",
                keychain::ApplicationAccess::Prompt => "prompt",
                keychain::ApplicationAccess::TrustedApplications(_) => "trusted-applications",
            },
            "trusted_applications": match access {
                keychain::ApplicationAccess::TrustedApplications(applications) => applications
                    .iter()
                    .map(|application| application.path.clone())
                    .collect::<Vec<_>>(),
                _ => Vec::new(),
            },
        })
    });
    Ok(())
}

/// `kc cp`: copy an item into another keychain.
enum DestinationPassword<'a> {
    Source(&'a PasswordSource),
    Prompt,
}

fn copy_command(
    cli: &Cli,
    source: &Path,
    destination: &Path,
    from: &PasswordSource,
    to: DestinationPassword<'_>,
    selector: &Selector,
    access: &keychain::ApplicationAccess,
) -> Result<()> {
    if selector.is_empty() {
        return Err(Error::other("name the item, for example with -a and -s"));
    }

    let mut origin = KeychainFile::open(source)?;
    authorize_secret_access(cli, source, "copy a secret")?;
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
        trusted_applications: Vec::new(),
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
    let destination_password = match to {
        DestinationPassword::Prompt => {
            rpassword::prompt_password("Destination keychain password: ")
                .map_err(|error| Error::io("could not read the destination password", error))?
        }
        DestinationPassword::Source(source) if source.is_explicit() => source.resolve(false)?,
        DestinationPassword::Source(_) => source_password.clone(),
    };
    target.unlock(destination_password.as_bytes())?;
    target.add_password_with_access(
        record_type,
        &new,
        secret.as_slice(),
        &now_timestamp(),
        access,
    )?;
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
            let keychain = resolve_keychain(keychain)?;
            let mut file = KeychainFile::open(&keychain)?;
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
            let keychain = resolve_keychain(keychain)?;
            let mut file = KeychainFile::open(&keychain)?;
            authorize_secret_access(cli, &keychain, "export a private key")?;
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
            let keychain = resolve_keychain(keychain)?;
            let mut file = KeychainFile::open(&keychain)?;
            authorize_secret_access(cli, &keychain, "export an identity")?;
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
                if pkcs12_password.password.is_some()
                    || pkcs12_password.password_env.is_some()
                    || pkcs12_password.password_file.is_some()
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
        new.resolve(true)?
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

    let generated = new.password_gen.as_ref().map(|_| new_password.as_str());
    report(
        cli,
        &generated.map_or_else(
            || "password changed".to_string(),
            |value| format!("password changed\npassword: {value}"),
        ),
        || {
            serde_json::json!({
                "ok": true,
                "keychain": keychain,
                "generated_password": generated,
            })
        },
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

#[cfg(test)]
mod cli_compatibility_tests {
    use super::*;

    #[test]
    fn spaced_optional_password_values_remain_accepted() {
        let cli =
            Cli::try_parse_from(["kc", "passwd", "--new-password", "new-value", "login"]).unwrap();
        let Command::Passwd { new_password, .. } = cli.command else {
            panic!("parsed the wrong command");
        };
        assert_eq!(new_password, Some(Some("new-value".to_string())));

        let cli = Cli::try_parse_from([
            "kc",
            "export",
            "identity",
            "--pkcs12",
            "--pkcs12-password",
            "bundle-value",
            "login",
        ])
        .unwrap();
        let Command::Export {
            kind: ExportKind::Identity {
                pkcs12_password, ..
            },
        } = cli.command
        else {
            panic!("parsed the wrong command");
        };
        assert_eq!(
            pkcs12_password.password,
            Some(Some("bundle-value".to_string()))
        );
    }

    #[test]
    fn destination_password_can_still_be_prompt_only() {
        let cli = Cli::try_parse_from([
            "kc",
            "cp",
            "--to-password",
            "-a",
            "alice",
            "source",
            "destination",
        ])
        .unwrap();
        let Command::Cp { to_password, .. } = cli.command else {
            panic!("parsed the wrong command");
        };
        assert_eq!(to_password, Some(None));
    }
}
