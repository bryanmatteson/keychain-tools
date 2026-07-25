//! `apwh` — Apple Passwords from the command line.

use clap::{ArgAction, CommandFactory, Parser, Subcommand};
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use apwh::config::{Paths, PendingAuth};
use apwh::entries::Payload;
use apwh::error::{Error, Result};
use apwh::output::{self, Format};
use apwh::service::{self, ServiceConfig};
use apwh::{PasswordsClient, launchd};

#[derive(Parser)]
#[command(
    name = "apwh",
    version,
    about = "Read and write Apple Passwords (iCloud Keychain) from the command line",
    long_about = "Read and write Apple Passwords (iCloud Keychain) from the command line.\n\n\
                  Requires the background service (`apwh serve`, or `apwh service install` to run \
                  it at login) and a PIN handshake after every service start (`apwh auth`).",
    disable_help_subcommand = true
)]
struct Cli {
    /// Path to the service socket [env: APWH_SOCKET]
    #[arg(long, global = true, value_name = "PATH")]
    socket: Option<PathBuf>,

    /// Emit a JSON envelope instead of text
    #[arg(long, global = true, action = ArgAction::SetTrue)]
    json: bool,

    /// Print the helper's decrypted reply verbatim
    #[arg(long, global = true, action = ArgAction::SetTrue)]
    raw: bool,

    /// Seconds to wait for the service
    #[arg(long, global = true, value_name = "SECONDS", default_value_t = 40)]
    timeout: u64,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the background service in the foreground
    Serve {
        /// Override the helper binary discovered from the native-messaging manifest
        #[arg(long, value_name = "PATH")]
        helper: Option<PathBuf>,

        /// Seconds to wait for the helper before answering a client with a timeout
        #[arg(long, value_name = "SECONDS", default_value_t = 30)]
        helper_timeout: u64,
    },

    /// Authenticate with the PIN macOS displays
    Auth {
        #[command(subcommand)]
        action: Option<AuthAction>,
    },

    /// Forget the stored session key
    Logout,

    /// Show service, session, and agent state
    Status,

    /// Ask the helper what it supports
    Capabilities,

    /// Check whether this Mac will let the service run at all
    Doctor,

    /// List the logins stored for a site
    #[command(visible_alias = "ls")]
    List {
        /// Site or URL, for example example.com
        url: String,
    },

    /// Print the password for a login
    Get {
        /// Site or URL, for example example.com
        url: String,

        /// Which login to read; required when a site has more than one
        username: Option<String>,

        /// Copy to the clipboard instead of printing
        #[arg(long, action = ArgAction::SetTrue)]
        copy: bool,
    },

    /// Save a new login
    Add {
        /// Site or URL to save it under
        url: String,

        /// Login user name
        username: String,

        /// Password (visible to other users via `ps`; prefer --stdin)
        #[arg(long, value_name = "PASSWORD")]
        password: Option<String>,

        /// Read the password from stdin (implied when stdin is not a terminal)
        #[arg(long, action = ArgAction::SetTrue)]
        stdin: bool,
    },

    /// Work with one-time codes
    Otp {
        #[command(subcommand)]
        action: OtpAction,
    },

    /// Manage the launchd agent that runs the service at login
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },

    /// Print a shell completion script
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

#[derive(Subcommand)]
enum AuthAction {
    /// Start a handshake and save its state for `auth complete`
    Begin,
    /// Finish a handshake started by `auth begin`
    Complete {
        /// The PIN; read from the terminal or stdin when omitted
        #[arg(long)]
        pin: Option<String>,
    },
    /// Report whether a session key is stored
    Status,
}

#[derive(Subcommand)]
enum OtpAction {
    /// Print the current one-time code for a site
    Get { url: String },
    /// List one-time-code items for a site
    List { url: String },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Install and load the launchd agent
    Install,
    /// Unload and remove the launchd agent
    Uninstall,
    /// Report the agent's state
    Status,
}

fn main() -> ExitCode {
    // Rust starts processes with SIGPIPE ignored, which turns `apwh get … | head`
    // into a panic on a broken pipe instead of a quiet exit. Restore the default
    // so piping behaves the way it does for every other command-line tool.
    // SAFETY: setting a signal disposition before any threads exist.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();
    let format = Format::select(cli.json, cli.raw);

    match run(&cli, format) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report(&error, format);
            ExitCode::from(error.exit_code())
        }
    }
}

fn report(error: &Error, format: Format) {
    if matches!(error, Error::Reported(_)) {
        return; // Already described on stdout.
    }
    let mut stderr = std::io::stderr();
    let _ = match format {
        Format::Text => writeln!(stderr, "apwh: {error}"),
        _ => writeln!(stderr, "{}", output::pretty(&output::error_envelope(error))),
    };
}

fn run(cli: &Cli, format: Format) -> Result<()> {
    let mut paths = Paths::from_env()?;
    if let Some(socket) = &cli.socket {
        paths = paths.with_socket(socket.clone());
    }
    let timeout = Duration::from_secs(cli.timeout.max(1));

    match &cli.command {
        Commands::Serve {
            helper,
            helper_timeout,
        } => {
            let mut config = ServiceConfig::new(paths);
            config.helper_path = helper.clone();
            config.helper_timeout = Duration::from_secs((*helper_timeout).max(1));
            service::run(config)
        }

        Commands::Auth { action } => match action {
            None => auth_interactive(paths, timeout, format),
            Some(AuthAction::Begin) => auth_begin(paths, timeout, format),
            Some(AuthAction::Complete { pin }) => {
                auth_complete(paths, timeout, pin.clone(), format)
            }
            Some(AuthAction::Status) => auth_status(paths, timeout, format),
        },

        Commands::Logout => {
            let mut client = PasswordsClient::open(paths, timeout)?;
            client.logout()?;
            emit(format, "session cleared", || {
                output::ok_envelope(serde_json::json!([]))
            });
            Ok(())
        }

        Commands::Status => status(paths, timeout, format),
        Commands::Capabilities => capabilities(paths, timeout, format),
        Commands::Doctor => doctor(&paths, format),

        Commands::List { url } => {
            let client = PasswordsClient::open(paths, timeout)?;
            let payload = client.login_names(url)?;
            show_passwords(&payload, format)
        }

        Commands::Get {
            url,
            username,
            copy,
        } => {
            let client = PasswordsClient::open(paths, timeout)?;
            let payload = client.password(url, username.as_deref())?;
            get_password(&payload, format, *copy)
        }

        Commands::Add {
            url,
            username,
            password,
            stdin,
        } => {
            let client = PasswordsClient::open(paths, timeout)?;
            let secret = read_new_password(password.clone(), *stdin)?;
            client.save_account(url, username, &secret)?;
            emit(format, &format!("saved {username} for {url}"), || {
                output::ok_envelope(serde_json::json!([{ "url": url, "username": username }]))
            });
            Ok(())
        }

        Commands::Otp { action } => {
            let client = PasswordsClient::open(paths, timeout)?;
            match action {
                OtpAction::Get { url } => {
                    let payload = client.one_time_code(url)?;
                    show_one_time_codes(&payload, format, true)
                }
                OtpAction::List { url } => {
                    let payload = client.list_one_time_codes(url)?;
                    show_one_time_codes(&payload, format, false)
                }
            }
        }

        Commands::Service { action } => service_agent(&paths, action, format),

        Commands::Completions { shell } => {
            let mut command = Cli::command();
            let name = command.get_name().to_string();
            clap_complete::generate(*shell, &mut command, name, &mut std::io::stdout());
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

fn auth_interactive(paths: Paths, timeout: Duration, format: Format) -> Result<()> {
    let mut client = PasswordsClient::open(paths, timeout)?;
    client.begin_auth()?;

    let pin = prompt_pin()?;
    client.complete_auth(&pin)?;

    emit(format, "authenticated", || {
        output::ok_envelope(serde_json::json!([]))
    });
    Ok(())
}

fn auth_begin(paths: Paths, timeout: Duration, format: Format) -> Result<()> {
    let pending_path = paths.pending_auth();
    let mut client = PasswordsClient::open(paths, timeout)?;
    client.begin_auth()?;
    client.pending_auth()?.save(&pending_path)?;

    emit(
        format,
        &format!(
            "macOS is showing a PIN. Finish with:\n  apwh auth complete --pin <PIN>\n\
             (handshake saved to {})",
            pending_path.display()
        ),
        || output::ok_envelope(serde_json::json!([{ "pending": pending_path }])),
    );
    Ok(())
}

fn auth_complete(
    paths: Paths,
    timeout: Duration,
    pin: Option<String>,
    format: Format,
) -> Result<()> {
    let pending_path = paths.pending_auth();
    let pending = PendingAuth::load(&pending_path)?;
    let mut client = PasswordsClient::open(paths, timeout)?;
    client.adopt_session(pending.restore()?);

    let pin = match pin {
        Some(pin) => output::validate_pin(&pin)?,
        None => prompt_pin()?,
    };
    client.complete_auth(&pin)?;
    apwh::config::remove_if_present(&pending_path)?;

    emit(format, "authenticated", || {
        output::ok_envelope(serde_json::json!([]))
    });
    Ok(())
}

fn auth_status(paths: Paths, timeout: Duration, format: Format) -> Result<()> {
    let client = PasswordsClient::open(paths, timeout)?;
    let authenticated = client.is_authenticated();
    emit(
        format,
        if authenticated {
            "authenticated"
        } else {
            "not authenticated"
        },
        || serde_json::json!({ "ok": true, "authenticated": authenticated }),
    );
    if authenticated {
        Ok(())
    } else {
        Err(Error::NoSession)
    }
}

/// Read the PIN from the terminal, or from stdin when it is a pipe.
fn prompt_pin() -> Result<String> {
    let raw = if std::io::stdin().is_terminal() {
        rpassword::prompt_password("PIN shown by macOS: ")
            .map_err(|error| Error::io("could not read the PIN", error))?
    } else {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|error| Error::io("could not read the PIN from stdin", error))?;
        line
    };
    output::validate_pin(&raw)
}

// ---------------------------------------------------------------------------
// Reads and writes
// ---------------------------------------------------------------------------

fn show_passwords(payload: &Payload, format: Format) -> Result<()> {
    if format == Format::Raw {
        println!("{}", output::pretty(&payload.raw));
        return payload.ensure_success();
    }
    payload.ensure_success()?;

    let records = payload.passwords();
    match format {
        Format::Json => println!("{}", output::pretty(&output::ok_envelope(&records))),
        _ if records.is_empty() => eprintln!("apwh: no logins found"),
        _ => println!("{}", output::password_table(&records)),
    }
    Ok(())
}

fn get_password(payload: &Payload, format: Format, copy: bool) -> Result<()> {
    if format == Format::Raw {
        println!("{}", output::pretty(&payload.raw));
        return payload.ensure_success();
    }
    payload.ensure_success()?;

    let records = payload.passwords();
    if records.len() > 1 {
        // Picking one silently would be a coin flip over which password gets used.
        let names: Vec<&str> = records
            .iter()
            .map(|record| record.username.as_str())
            .collect();
        return Err(Error::other(format!(
            "{} logins match; name one of: {}",
            records.len(),
            names.join(", ")
        )));
    }
    let record = records
        .first()
        .ok_or(Error::Status(apwh::Status::NoResults))?;
    let Some(secret) = &record.password else {
        if payload.requires_local_authentication {
            return Err(Error::other(
                "the helper withheld this password pending local authentication; \
                 approve the prompt on this Mac and try again",
            ));
        }
        return Err(Error::other(
            "the helper returned this login without a password",
        ));
    };

    if format == Format::Json {
        println!("{}", output::pretty(&output::ok_envelope(vec![record])));
        return Ok(());
    }
    if copy {
        copy_to_clipboard(secret)?;
        eprintln!(
            "apwh: copied the password for {} to the clipboard",
            record.username
        );
        return Ok(());
    }
    println!("{secret}");
    Ok(())
}

fn show_one_time_codes(payload: &Payload, format: Format, want_code: bool) -> Result<()> {
    if format == Format::Raw {
        println!("{}", output::pretty(&payload.raw));
        return payload.ensure_success();
    }
    payload.ensure_success()?;

    let records = payload.one_time_codes();
    match format {
        Format::Json => println!("{}", output::pretty(&output::ok_envelope(&records))),
        _ if records.is_empty() => eprintln!("apwh: no one-time codes found"),
        // A single code is the common case, and printing it bare makes it pipeable.
        _ if want_code && records.len() == 1 && records[0].code.is_some() => {
            println!("{}", records[0].code.as_deref().unwrap_or_default());
        }
        _ => println!("{}", output::otp_table(&records)),
    }
    Ok(())
}

/// Resolve the password for `apwh add` without ever putting it in argv.
fn read_new_password(inline: Option<String>, from_stdin: bool) -> Result<String> {
    if let Some(password) = inline {
        eprintln!(
            "apwh: warning: --password is visible to other processes via `ps`; \
             prefer --stdin or the prompt"
        );
        return Ok(password);
    }
    // A pipe is unambiguous: there is nothing to prompt on, and the only thing
    // the caller could mean by piping into `apwh add` is the password.
    if from_stdin || !std::io::stdin().is_terminal() {
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .map_err(|error| Error::io("could not read the password from stdin", error))?;
        // A trailing newline is an artifact of `echo`, not part of the secret.
        let password = buffer.strip_suffix('\n').unwrap_or(&buffer);
        let password = password.strip_suffix('\r').unwrap_or(password);
        if password.is_empty() {
            return Err(Error::other("no password on stdin"));
        }
        return Ok(password.to_string());
    }

    let password = rpassword::prompt_password("New password: ")
        .map_err(|error| Error::io("could not read the password", error))?;
    if password.is_empty() {
        return Err(Error::other("no password entered"));
    }
    let confirmation = rpassword::prompt_password("Confirm: ")
        .map_err(|error| Error::io("could not read the password", error))?;
    if password != confirmation {
        return Err(Error::other("the two entries did not match"));
    }
    Ok(password)
}

fn copy_to_clipboard(secret: &str) -> Result<()> {
    use std::process::{Command, Stdio};

    let mut child = Command::new("/usr/bin/pbcopy")
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|error| Error::io("could not run pbcopy", error))?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| Error::other("pbcopy did not accept input"))?
        .write_all(secret.as_bytes())
        .map_err(|error| Error::io("could not write to pbcopy", error))?;
    let status = child
        .wait()
        .map_err(|error| Error::io("pbcopy failed", error))?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::other("pbcopy exited with an error"))
    }
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

fn status(paths: Paths, timeout: Duration, format: Format) -> Result<()> {
    let client = PasswordsClient::open(paths.clone(), timeout)?;
    let listening = client.transport().is_listening();
    let authenticated = client.is_authenticated();
    let agent = launchd::status().ok();
    let helper = service::discover_helper();

    // Only ask the helper about itself when there is something to ask.
    let capabilities = if listening {
        client.capabilities().ok()
    } else {
        None
    };

    if format == Format::Json || format == Format::Raw {
        println!(
            "{}",
            output::pretty(&serde_json::json!({
                "ok": true,
                "socket": paths.socket,
                "service_running": listening,
                "authenticated": authenticated,
                "helper": helper.as_ref().ok(),
                "helper_missing_reason": helper.as_ref().err().map(ToString::to_string),
                "capabilities": capabilities.as_ref().map(|reply| &reply.capabilities),
                "agent": agent.as_ref().map(|agent| serde_json::json!({
                    "installed": agent.installed,
                    "loaded": agent.loaded,
                    "pid": agent.pid,
                    "last_exit_status": agent.last_exit_status,
                    "plist": agent.plist,
                })),
            }))
        );
        return Ok(());
    }

    let mut fields = vec![
        ("socket", paths.socket.display().to_string()),
        (
            "service",
            if listening {
                "running".into()
            } else {
                "not running".into()
            },
        ),
        (
            "session",
            if authenticated {
                "authenticated".into()
            } else {
                "not authenticated".into()
            },
        ),
        (
            "helper",
            match &helper {
                Ok(path) => path.display().to_string(),
                Err(error) => format!("unavailable ({error})"),
            },
        ),
    ];
    if let Some(reply) = &capabilities {
        if let Some(system) = &reply.capabilities.operating_system {
            fields.push((
                "helper os",
                format!(
                    "{} {}.{}",
                    system.name.clone().unwrap_or_else(|| "?".into()),
                    system.major_version.unwrap_or_default(),
                    system.minor_version.unwrap_or_default()
                ),
            ));
        }
        if let Some(otp) = reply.capabilities.can_fill_one_time_codes {
            fields.push((
                "one-time codes",
                if otp { "supported".into() } else { "no".into() },
            ));
        }
    }
    if let Some(agent) = &agent {
        fields.push((
            "launchd agent",
            match (agent.installed, agent.loaded, agent.pid) {
                (true, true, Some(pid)) => format!("loaded (pid {pid})"),
                (true, true, None) => "loaded, not running".into(),
                (true, false, _) => "installed, not loaded".into(),
                (false, _, _) => "not installed".into(),
            },
        ));
    }
    println!("{}", output::field_list(&fields));

    if !listening {
        eprintln!("apwh: start the service with `apwh serve` or `apwh service install`");
    } else if !authenticated {
        eprintln!("apwh: authenticate with `apwh auth`");
    }
    Ok(())
}

fn capabilities(paths: Paths, timeout: Duration, format: Format) -> Result<()> {
    let client = PasswordsClient::open(paths, timeout)?;
    let reply = client.capabilities()?;

    match format {
        Format::Raw => println!("{}", output::pretty(&reply.raw)),
        Format::Json => println!(
            "{}",
            output::pretty(&serde_json::json!({ "ok": true, "capabilities": reply.capabilities }))
        ),
        Format::Text => {
            let capabilities = &reply.capabilities;
            let yes_no = |value: Option<bool>| match value {
                Some(true) => "yes".to_string(),
                Some(false) => "no".to_string(),
                None => "unreported".to_string(),
            };
            let mut fields = vec![
                (
                    "one-time codes",
                    yes_no(capabilities.can_fill_one_time_codes),
                ),
                ("scan for OTP URI", yes_no(capabilities.scan_for_otp_uri)),
                ("base64 encoding", yes_no(capabilities.should_use_base64)),
            ];
            if let Some(system) = &capabilities.operating_system {
                fields.push((
                    "operating system",
                    format!(
                        "{} {}.{}",
                        system.name.clone().unwrap_or_else(|| "?".into()),
                        system.major_version.unwrap_or_default(),
                        system.minor_version.unwrap_or_default()
                    ),
                ));
            }
            println!("{}", output::field_list(&fields));
        }
    }
    Ok(())
}

/// Check the things that have to be true before anything else can work, and say
/// plainly which one is not.
fn doctor(paths: &Paths, format: Format) -> Result<()> {
    let socket_ok = apwh::config::validate_socket_path(&paths.socket);
    let manifest = service::manifest_path();
    let helper = service::discover_helper();
    let constrained = helper
        .as_ref()
        .ok()
        .and_then(|path| service::has_parent_launch_constraint(path));
    let probe = helper
        .as_ref()
        .map_err(|error| error.to_string())
        .and_then(|path| service::probe_helper(path).map_err(|error| error.to_string()));

    if format != Format::Text {
        println!(
            "{}",
            output::pretty(&serde_json::json!({
                "ok": probe.is_ok() && socket_ok.is_ok(),
                "socket": paths.socket,
                "socket_path_ok": socket_ok.is_ok(),
                "socket_path_problem": socket_ok.as_ref().err().map(ToString::to_string),
                "manifest": manifest,
                "helper": helper.as_ref().ok(),
                "helper_parent_launch_constraint": constrained,
                "helper_launches": probe.is_ok(),
                "helper_problem": probe.as_ref().err(),
            }))
        );
    } else {
        let mut fields = vec![
            (
                "socket path",
                match &socket_ok {
                    Ok(()) => format!("{} (ok)", paths.socket.display()),
                    Err(error) => format!("{}", error),
                },
            ),
            ("manifest", manifest.unwrap_or("not found").to_string()),
            (
                "helper",
                match &helper {
                    Ok(path) => path.display().to_string(),
                    Err(error) => format!("not found ({error})"),
                },
            ),
            (
                "parent launch constraint",
                match constrained {
                    Some(true) => "yes — only allowlisted browsers may launch it".to_string(),
                    Some(false) => "no".to_string(),
                    None => "unknown".to_string(),
                },
            ),
            (
                "helper launches",
                match &probe {
                    Ok(()) => "yes".to_string(),
                    Err(_) => "no".to_string(),
                },
            ),
        ];
        if let Err(problem) = &probe {
            fields.push(("problem", problem.clone()));
        }
        println!("{}", output::field_list(&fields));

        if probe.is_ok() && socket_ok.is_ok() {
            println!("\nThis Mac can run the service. Start it with `apwh serve`.");
        } else {
            println!(
                "\nThe service cannot run on this Mac as-is. If the parent launch constraint is \
                 the cause, no CLI can satisfy it: the helper must be launched by a browser \
                 Apple allowlists. See the macOS 26 section of README.md."
            );
        }
    }

    // Both problems are already on stdout; exit non-zero without repeating them.
    match (socket_ok, probe) {
        (Ok(()), Ok(())) => Ok(()),
        _ => Err(Error::Reported(apwh::Status::GenericError)),
    }
}

// ---------------------------------------------------------------------------
// launchd agent
// ---------------------------------------------------------------------------

fn service_agent(paths: &Paths, action: &ServiceAction, format: Format) -> Result<()> {
    match action {
        ServiceAction::Install => {
            let executable = std::env::current_exe()
                .map_err(|error| Error::io("could not locate the apwh binary", error))?;
            let executable = executable.canonicalize().unwrap_or(executable);
            let plist = launchd::install(paths, &executable)?;
            emit(
                format,
                &format!("loaded {} from {}", launchd::LABEL, plist.display()),
                || output::ok_envelope(serde_json::json!([{ "plist": plist }])),
            );
            Ok(())
        }
        ServiceAction::Uninstall => {
            let removed = launchd::uninstall()?;
            emit(
                format,
                if removed {
                    "removed the launchd agent"
                } else {
                    "no launchd agent installed"
                },
                || serde_json::json!({ "ok": true, "removed": removed }),
            );
            Ok(())
        }
        ServiceAction::Status => {
            let agent = launchd::status()?;
            match format {
                Format::Text => println!(
                    "{}",
                    output::field_list(&[
                        ("plist", agent.plist.display().to_string()),
                        ("installed", agent.installed.to_string()),
                        ("loaded", agent.loaded.to_string()),
                        (
                            "pid",
                            agent
                                .pid
                                .map(|pid| pid.to_string())
                                .unwrap_or_else(|| "-".into())
                        ),
                        (
                            "last exit status",
                            agent
                                .last_exit_status
                                .map(|code| code.to_string())
                                .unwrap_or_else(|| "-".into())
                        ),
                    ])
                ),
                _ => println!(
                    "{}",
                    output::pretty(&serde_json::json!({
                        "ok": true,
                        "plist": agent.plist,
                        "installed": agent.installed,
                        "loaded": agent.loaded,
                        "pid": agent.pid,
                        "last_exit_status": agent.last_exit_status,
                    }))
                ),
            }
            Ok(())
        }
    }
}

/// Print a one-line result in whichever form the caller asked for.
fn emit(format: Format, text: &str, json: impl FnOnce() -> serde_json::Value) {
    match format {
        Format::Text => println!("{text}"),
        _ => println!("{}", output::pretty(&json())),
    }
}
