//! The service half: owns the helper process, relays framed JSON.
//!
//! `PasswordManagerBrowserExtensionHelper` speaks native messaging over stdio,
//! so only one process can hold it, and the SRP session it negotiates dies with
//! that process. This service is that process: it keeps the helper alive and
//! multiplexes any number of short-lived CLI invocations onto it over a Unix
//! socket at `<state dir>/service.sock`.
//!
//! It is a relay, not a proxy with privileges: payloads are encrypted end-to-end
//! between the CLI's SRP session and the helper, so a process that can reach the
//! socket still cannot read a password without the session key. The socket is
//! `0600` inside a `0700` directory, which is the actual access boundary.

use serde_json::json;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command as ProcessCommand, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::{self, Config, Paths};
use crate::error::{Error, IoContext, Result};
use crate::frame::{read_frame, write_frame};
use crate::log_line;
use crate::protocol::Command;

/// Native-messaging manifests that name the helper. Firefox's is checked first
/// only because that is the order the reference implementation used.
pub const MANIFEST_PATHS: [&str; 2] = [
    "/Library/Application Support/Mozilla/NativeMessagingHosts/com.apple.passwordmanager.json",
    "/Library/Google/Chrome/NativeMessagingHosts/com.apple.passwordmanager.json",
];

/// How long the helper gets to answer one request before the client is told the
/// request timed out. Generous because a request may be waiting on the user.
pub const DEFAULT_HELPER_TIMEOUT: Duration = Duration::from_secs(30);

/// Exit code used when the helper goes away and the service cannot continue.
pub const EXIT_HELPER_LOST: i32 = 70;

#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub paths: Paths,
    /// Override for the helper binary; defaults to the manifest's `path`.
    pub helper_path: Option<PathBuf>,
    pub helper_timeout: Duration,
}

impl ServiceConfig {
    pub fn new(paths: Paths) -> Self {
        Self {
            paths,
            helper_path: None,
            helper_timeout: DEFAULT_HELPER_TIMEOUT,
        }
    }
}

/// The first native-messaging manifest present on this system.
pub fn manifest_path() -> Option<&'static str> {
    MANIFEST_PATHS
        .into_iter()
        .find(|path| Path::new(path).exists())
}

/// Whether the helper's signature constrains which process may be its parent.
///
/// `None` means the question could not be answered (no `codesign`, or output in
/// a form this does not recognize) — not that there is no constraint.
pub fn has_parent_launch_constraint(path: &Path) -> Option<bool> {
    let output = ProcessCommand::new("/usr/bin/codesign")
        .arg("--display")
        .arg("--verbose=4")
        .arg(path)
        .output()
        .ok()?;
    let mut text = String::from_utf8_lossy(&output.stderr).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stdout));
    parse_parent_constraint(&text)
}

fn parse_parent_constraint(codesign_output: &str) -> Option<bool> {
    if codesign_output.contains("Has Parent Launch Constraints") {
        return Some(true);
    }
    // Only trust a "no" when the output is recognizably a signature dump.
    if codesign_output.contains("CodeDirectory") {
        Some(false)
    } else {
        None
    }
}

/// Read the helper's path out of a native-messaging manifest.
pub fn discover_helper() -> Result<PathBuf> {
    for manifest_path in MANIFEST_PATHS {
        let Ok(bytes) = std::fs::read(manifest_path) else {
            continue;
        };
        let manifest: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| Error::other(format!("{manifest_path} is not valid JSON: {error}")))?;
        let path = manifest
            .get("path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Error::other(format!("{manifest_path} has no `path` field")))?;
        return Ok(PathBuf::from(path));
    }
    Err(Error::HelperMissing)
}

/// How long to watch a freshly spawned helper before trusting it. A launch
/// constraint violation gets the process killed at `exec`, so this only has to
/// outlast process setup.
const STARTUP_GRACE: Duration = Duration::from_millis(400);

/// Does the helper survive being launched from this process?
///
/// On macOS 26 it does not: the helper's signature carries a parent launch
/// constraint that only signed browsers satisfy, and anything else gets
/// SIGKILLed at `exec` with no output at all. Detecting that here turns a
/// baffling "helper closed its output stream" into an explanation.
pub fn probe_helper(path: &Path) -> Result<()> {
    let mut child = ProcessCommand::new(path)
        .arg(".")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => Error::HelperMissing,
            _ => Error::io(format!("could not launch {}", path.display()), error),
        })?;

    let deadline = std::time::Instant::now() + STARTUP_GRACE;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Err(classify_early_exit(status)),
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Ok(());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => return Err(Error::io("could not wait for the helper", error)),
        }
    }
}

fn classify_early_exit(status: std::process::ExitStatus) -> Error {
    use std::os::unix::process::ExitStatusExt;
    match status.signal() {
        Some(libc::SIGKILL) => Error::HelperBlockedByLaunchConstraint,
        Some(signal) => Error::HelperDiedAtStartup(format!("killed by signal {signal}")),
        None => {
            Error::HelperDiedAtStartup(format!("exit status {}", status.code().unwrap_or_default()))
        }
    }
}

/// Run the service until the helper dies or a signal arrives.
pub fn run(config: ServiceConfig) -> Result<()> {
    let paths = &config.paths;
    crate::config::validate_socket_path(&paths.socket)?;
    paths.ensure_home()?;

    // Take the socket before spawning anything, so a second instance fails
    // without having disturbed the first one's helper.
    claim_socket_path(&paths.socket)?;

    // The helper starts a fresh SRP session each time it launches, so any stored
    // key is already dead. Drop it now rather than letting the user discover it
    // through a decryption failure.
    let mut stored = Config::load(&paths.config())?;
    if stored.session.is_some() {
        stored.clear_session();
        stored.save(&paths.config())?;
        log_line!("cleared the stored session; run `apwh auth` to authenticate");
    }
    config::remove_if_present(&paths.pending_auth())?;

    let helper_path = match &config.helper_path {
        Some(path) => path.clone(),
        None => discover_helper()?,
    };
    // Fail with a diagnosis rather than binding a socket that can never work.
    probe_helper(&helper_path)?;
    let helper = Arc::new(Helper::spawn(&helper_path, config.helper_timeout)?);
    log_line!(
        "launched helper {} (pid {})",
        helper_path.display(),
        helper.pid()
    );

    let listener = UnixListener::bind(&paths.socket)
        .context(format!("could not bind {}", paths.socket.display()))?;
    std::fs::set_permissions(&paths.socket, std::fs::Permissions::from_mode(0o600)).context(
        format!(
            "could not restrict permissions on {}",
            paths.socket.display()
        ),
    )?;

    shutdown::arm(helper.pid(), &paths.socket);
    log_line!("listening on {}", paths.socket.display());

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let helper = Arc::clone(&helper);
                std::thread::spawn(move || serve_connection(stream, helper));
            }
            Err(error) => log_line!("rejected a connection: {error}"),
        }
    }
    Ok(())
}

/// Handle one client connection: framed request in, framed reply out, repeat
/// until the client hangs up.
fn serve_connection(mut stream: UnixStream, helper: Arc<Helper>) {
    loop {
        let request = match read_frame(&mut stream) {
            Ok(Some(request)) => request,
            Ok(None) => return,
            Err(error) => {
                log_line!("dropping connection: {error}");
                return;
            }
        };

        let (reply, fatal) = match helper.request(&request) {
            Ok(reply) => (reply, false),
            Err(Error::Timeout(_)) => {
                log_line!("helper did not answer within {:?}", helper.timeout);
                (
                    json!({ "error": "timeout" }).to_string().into_bytes(),
                    false,
                )
            }
            Err(Error::HelperExited) => (
                json!({ "error": "helper-exited" }).to_string().into_bytes(),
                true,
            ),
            Err(error) => {
                log_line!("helper request failed: {error}");
                (
                    json!({ "error": error.to_string() })
                        .to_string()
                        .into_bytes(),
                    false,
                )
            }
        };

        if let Err(error) = write_frame(&mut stream, &reply) {
            log_line!("could not reply to client: {error}");
            return;
        }
        if fatal {
            log_line!("the helper exited; shutting down so launchd can restart us");
            let _ = stream.flush();
            shutdown::exit(EXIT_HELPER_LOST);
        }
    }
}

/// The helper process and the serialized request path to it.
struct Helper {
    /// Held so the child is reaped, and so its pid stays valid.
    child: Mutex<Child>,
    io: Mutex<HelperIo>,
    timeout: Duration,
    pid: i32,
}

struct HelperIo {
    stdin: ChildStdin,
    /// Frames read from the helper's stdout, in arrival order.
    replies: Receiver<Vec<u8>>,
}

impl Helper {
    fn spawn(path: &Path, timeout: Duration) -> Result<Self> {
        // The single "." argument stands in for the extension origin a browser
        // would pass; the helper only checks that an argument is present.
        let mut child = ProcessCommand::new(path)
            .arg(".")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::NotFound => Error::HelperMissing,
                _ => Error::io(format!("could not launch {}", path.display()), error),
            })?;

        let pid = child.id() as i32;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::other("helper stdin is unavailable"))?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::other("helper stdout is unavailable"))?;

        let (sender, replies) = mpsc::channel();
        std::thread::spawn(move || {
            loop {
                match read_frame(&mut stdout) {
                    Ok(Some(frame)) => {
                        if sender.send(frame).is_err() {
                            return;
                        }
                    }
                    Ok(None) => {
                        log_line!("helper closed its output stream");
                        return;
                    }
                    Err(error) => {
                        log_line!("helper output stream failed: {error}");
                        return;
                    }
                }
            }
        });

        Ok(Self {
            child: Mutex::new(child),
            io: Mutex::new(HelperIo { stdin, replies }),
            timeout,
            pid,
        })
    }

    fn pid(&self) -> i32 {
        self.pid
    }

    /// Send one request and wait for its reply.
    ///
    /// Requests are serialized: the helper has a single stdio pair with no
    /// request ids to match on, so concurrent requests would let one client read
    /// another's reply. Unsolicited messages are logged and skipped rather than
    /// returned, or every later reply would be off by one.
    fn request(&self, body: &[u8]) -> Result<Vec<u8>> {
        let mut io = self
            .io
            .lock()
            .map_err(|_| Error::other("service state is poisoned"))?;

        // Anything queued while idle is either a push or a late reply to a
        // request that already timed out. Neither belongs to this request.
        while let Ok(stale) = io.replies.try_recv() {
            log_line!(
                "discarding unsolicited helper message: {}",
                describe(&stale)
            );
        }

        write_frame(&mut io.stdin, body).map_err(|error| {
            if error.kind() == std::io::ErrorKind::BrokenPipe {
                Error::HelperExited
            } else {
                Error::io("could not write to the helper", error)
            }
        })?;

        loop {
            match io.replies.recv_timeout(self.timeout) {
                Ok(frame) if is_unsolicited(&frame) => {
                    log_line!("ignoring unsolicited helper message: {}", describe(&frame));
                }
                Ok(frame) => return Ok(frame),
                Err(RecvTimeoutError::Timeout) => return Err(Error::Timeout(self.timeout)),
                Err(RecvTimeoutError::Disconnected) => return Err(Error::HelperExited),
            }
        }
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// True for helper-initiated messages that are not a reply to a request.
fn is_unsolicited(frame: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(frame)
        .ok()
        .and_then(|value| value.get("cmd").and_then(serde_json::Value::as_i64))
        .is_some_and(Command::is_unsolicited)
}

/// Describe a frame for the log without leaking its contents.
fn describe(frame: &[u8]) -> String {
    match serde_json::from_slice::<serde_json::Value>(frame)
        .ok()
        .and_then(|value| value.get("cmd").and_then(serde_json::Value::as_i64))
    {
        Some(code) => format!("{} ({} bytes)", Command::describe(code), frame.len()),
        None => format!("unparseable frame ({} bytes)", frame.len()),
    }
}

/// Refuse to start if another service holds the socket; clear it if stale.
fn claim_socket_path(socket: &Path) -> Result<()> {
    if !socket.exists() {
        return Ok(());
    }
    if UnixStream::connect(socket).is_ok() {
        return Err(Error::ServiceAlreadyRunning(socket.to_path_buf()));
    }
    log_line!("removing stale socket {}", socket.display());
    config::remove_if_present(socket)
}

/// Signal-safe cleanup: kill the helper and unlink the socket on the way out.
///
/// Without this, `^C` or `launchctl kickstart -k` would leave an orphaned helper
/// holding the stdio pair, and the next start would refuse a socket that nothing
/// is listening on.
mod shutdown {
    use std::ffi::CString;
    use std::path::Path;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicI32, Ordering};

    static HELPER_PID: AtomicI32 = AtomicI32::new(0);
    static SOCKET_PATH: OnceLock<CString> = OnceLock::new();

    /// Record what to clean up, and install handlers that do it.
    pub fn arm(helper_pid: i32, socket: &Path) {
        HELPER_PID.store(helper_pid, Ordering::SeqCst);
        if let Ok(path) = CString::new(socket.as_os_str().as_encoded_bytes()) {
            let _ = SOCKET_PATH.set(path);
        }
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            // SAFETY: `on_signal` only calls kill(2), unlink(2) and _exit(2),
            // all of which are async-signal-safe.
            unsafe {
                libc::signal(signal, on_signal as *const () as libc::sighandler_t);
            }
        }
    }

    extern "C" fn on_signal(signal: libc::c_int) {
        cleanup();
        // SAFETY: _exit is async-signal-safe; the conventional 128 + signal.
        unsafe { libc::_exit(128 + signal) }
    }

    /// Clean up and leave, from ordinary code rather than a handler.
    pub fn exit(code: i32) -> ! {
        cleanup();
        std::process::exit(code)
    }

    fn cleanup() {
        let pid = HELPER_PID.swap(0, Ordering::SeqCst);
        if pid > 0 {
            // SAFETY: async-signal-safe; a dead pid just yields ESRCH.
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
        }
        if let Some(path) = SOCKET_PATH.get() {
            // SAFETY: async-signal-safe; the CString outlives the process.
            unsafe {
                libc::unlink(path.as_ptr());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsolicited_frames_are_detected_by_command_code() {
        assert!(is_unsolicited(br#"{"cmd":15}"#));
        assert!(is_unsolicited(br#"{"cmd":8,"tabId":3}"#));
        assert!(!is_unsolicited(br#"{"cmd":2,"payload":{}}"#));
        assert!(!is_unsolicited(br#"{"cmd":4}"#));
        // A frame with no cmd is treated as a reply, so it is never swallowed.
        assert!(!is_unsolicited(br#"{"payload":{}}"#));
        assert!(!is_unsolicited(b"garbage"));
    }

    #[test]
    fn frame_descriptions_name_the_command_and_hide_the_body() {
        let description = describe(br#"{"cmd":15,"setUpTOTPURI":"otpauth://secret"}"#);
        assert!(description.starts_with("ONE_TIME_CODE_AVAILABLE (15)"));
        assert!(!description.contains("otpauth"));
        assert_eq!(describe(b"xx"), "unparseable frame (2 bytes)");
    }

    #[test]
    fn claiming_an_unused_path_succeeds_and_clears_stale_sockets() {
        let dir = std::env::temp_dir().join(format!("apwh-claim-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("service.sock");

        // Nothing there at all.
        claim_socket_path(&socket).unwrap();

        // A leftover file that nothing is listening on gets removed.
        std::fs::write(&socket, b"stale").unwrap();
        claim_socket_path(&socket).unwrap();
        assert!(!socket.exists());

        // A live listener is respected.
        let listener = UnixListener::bind(&socket).unwrap();
        assert!(matches!(
            claim_socket_path(&socket),
            Err(Error::ServiceAlreadyRunning(_))
        ));
        drop(listener);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parent_constraint_parsing_distinguishes_no_from_unknown() {
        assert_eq!(
            parse_parent_constraint("Launch Constraints:\n\tHas Parent Launch Constraints\n"),
            Some(true)
        );
        assert_eq!(
            parse_parent_constraint("Identifier=x\nCodeDirectory v=20400 size=1928\n"),
            Some(false)
        );
        // Unrecognized output must not be reported as "no constraint".
        assert_eq!(parse_parent_constraint("codesign: command not found"), None);
        assert_eq!(parse_parent_constraint(""), None);
    }

    #[test]
    fn probing_the_real_helper_agrees_with_its_signature() {
        let Ok(helper) = discover_helper() else {
            return; // No helper on this system.
        };
        let constrained = has_parent_launch_constraint(&helper);
        let probe = probe_helper(&helper);

        match (constrained, &probe) {
            // A parent constraint this process cannot satisfy shows up as an
            // immediate SIGKILL, which is what the probe must report.
            (Some(true), Err(Error::HelperBlockedByLaunchConstraint)) => {}
            (Some(true), Ok(())) => {
                // Allowed on a system where this process does satisfy the
                // constraint; nothing to assert beyond "it started".
            }
            (_, Ok(())) => {}
            (_, Err(error)) => panic!("helper probe failed unexpectedly: {error}"),
        }
    }

    #[test]
    fn helper_discovery_finds_the_manifest_on_a_supported_system() {
        // Both manifests are symlinks into the system cryptex on macOS 14+.
        let installed = MANIFEST_PATHS.iter().any(|path| Path::new(path).exists());
        match discover_helper() {
            Ok(path) => {
                assert!(installed);
                assert!(
                    path.is_absolute(),
                    "helper path should be absolute: {}",
                    path.display()
                );
            }
            Err(Error::HelperMissing) => assert!(!installed),
            Err(other) => panic!("unexpected discovery failure: {other}"),
        }
    }
}
