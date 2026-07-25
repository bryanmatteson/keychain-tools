//! End-to-end tests: real CLI process, real service process, real socket, real
//! SRP handshake and AES-GCM payloads — with `examples/fake_helper` standing in
//! for Apple's helper, since the real one only shows its PIN on screen.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const PIN: &str = "482915";

/// A running service with its own state directory, torn down on drop.
struct Harness {
    home: PathBuf,
    socket: PathBuf,
    helper_pidfile: PathBuf,
    service: Child,
}

impl Harness {
    fn start(tag: &str, mode: &str, helper_timeout: &str) -> Self {
        let home = std::env::temp_dir().join(format!("apwh-e2e-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).expect("create state directory");

        let socket = home.join("s.sock");
        let helper_pidfile = home.join("helper.pid");
        let service = Command::new(apwh_binary())
            .args([
                "serve",
                "--socket",
                socket.to_str().unwrap(),
                "--helper",
                fake_helper().to_str().unwrap(),
                "--helper-timeout",
                helper_timeout,
            ])
            .env("APWH_HOME", &home)
            .env("FAKE_HELPER_MODE", mode)
            .env("FAKE_HELPER_PIN", PIN)
            .env("FAKE_HELPER_PIDFILE", &helper_pidfile)
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn the service");

        let harness = Self {
            home,
            socket,
            helper_pidfile,
            service,
        };
        harness.wait_until_listening();
        harness
    }

    fn normal(tag: &str) -> Self {
        Self::start(tag, "normal", "10")
    }

    fn wait_until_listening(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if UnixStream::connect(&self.socket).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!(
            "service never started listening on {}",
            self.socket.display()
        );
    }

    /// Run the CLI against this service.
    fn apwh(&self, args: &[&str]) -> Output {
        self.apwh_with_stdin(args, None)
    }

    fn apwh_with_stdin(&self, args: &[&str], input: Option<&str>) -> Output {
        let mut child = Command::new(apwh_binary())
            .args(["--socket", self.socket.to_str().unwrap()])
            .args(args)
            .env("APWH_HOME", &self.home)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the CLI");
        if let Some(input) = input {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .expect("write stdin");
        }
        child.wait_with_output().expect("run the CLI")
    }

    /// Authenticate the way a user would: `apwh auth` with the PIN on stdin.
    fn authenticate(&self) {
        let output = self.apwh_with_stdin(&["auth"], Some(PIN));
        assert!(output.status.success(), "auth failed: {}", stderr(&output));
    }

    /// The fake helper's pid, once it has written it. The service binds its
    /// socket as soon as the helper is spawned, so the file may lag slightly
    /// behind the socket becoming connectable.
    fn helper_pid(&self) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(text) = std::fs::read_to_string(&self.helper_pidfile)
                && let Ok(pid) = text.trim().parse()
            {
                return pid;
            }
            assert!(
                Instant::now() < deadline,
                "the helper never wrote its pid file"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn send_signal(&self, signal: i32) {
        // SAFETY: signalling a child this process spawned.
        unsafe {
            libc::kill(self.service.id() as i32, signal);
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.service.kill();
        let _ = self.service.wait();
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn apwh_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_apwh"))
}

fn fake_helper() -> PathBuf {
    let path = apwh_binary()
        .parent()
        .expect("binary directory")
        .join("examples")
        .join("fake_helper");
    assert!(
        path.exists(),
        "build the test helper first: cargo build --example fake_helper ({})",
        path.display()
    );
    path
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn json(output: &Output) -> serde_json::Value {
    serde_json::from_str(&stdout(output))
        .unwrap_or_else(|error| panic!("stdout was not JSON ({error}): {}", stdout(output)))
}

fn process_alive(pid: i32) -> bool {
    // SAFETY: signal 0 only probes for the process's existence.
    unsafe { libc::kill(pid, 0) == 0 }
}

#[test]
fn capabilities_are_readable_before_authenticating() {
    let harness = Harness::normal("caps");

    let output = harness.apwh(&["capabilities", "--json"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let reply = json(&output);
    assert_eq!(reply["capabilities"]["canFillOneTimeCodes"], true);
    assert_eq!(reply["capabilities"]["operatingSystem"]["majorVersion"], 26);

    let status = json(&harness.apwh(&["status", "--json"]));
    assert_eq!(status["service_running"], true);
    assert_eq!(status["authenticated"], false);
}

#[test]
fn data_commands_refuse_to_run_before_authenticating() {
    let harness = Harness::normal("unauth");

    let output = harness.apwh(&["list", "example.com"]);
    assert_eq!(output.status.code(), Some(9), "{}", stderr(&output));
    assert!(stderr(&output).contains("apwh auth"), "{}", stderr(&output));
}

#[test]
fn the_full_flow_works_over_a_real_handshake() {
    let harness = Harness::normal("full");
    harness.authenticate();

    let status = json(&harness.apwh(&["status", "--json"]));
    assert_eq!(status["authenticated"], true);

    // List: two logins, metadata only.
    let listed = json(&harness.apwh(&["list", "example.com", "--json"]));
    let users: Vec<&str> = listed["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["username"].as_str().unwrap())
        .collect();
    assert_eq!(users, vec!["ada@example.com", "grace@example.com"]);
    assert!(
        listed["results"][0].get("password").is_none(),
        "listing must not carry secrets"
    );

    // Text listing is aligned and mentions both logins.
    let text = stdout(&harness.apwh(&["list", "example.com"]));
    assert!(text.contains("USERNAME"));
    assert!(text.contains("ada@example.com"));

    // Get: the password prints bare, so it can be piped.
    let output = harness.apwh(&["get", "example.com", "ada@example.com"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "hunter2\n");
    assert_eq!(
        stdout(&harness.apwh(&["get", "example.com", "grace@example.com"])),
        "s3cr3t\n"
    );

    // One-time codes.
    assert_eq!(
        stdout(&harness.apwh(&["otp", "get", "example.com"])),
        "246810\n"
    );
    let listed_codes = json(&harness.apwh(&["otp", "list", "example.com", "--json"]));
    assert_eq!(listed_codes["results"][0]["username"], "ada@example.com");
    assert!(
        listed_codes["results"][0].get("code").is_none(),
        "listing must not carry codes"
    );

    // Add, with the new password on stdin rather than in argv.
    let output = harness.apwh_with_stdin(&["add", "new.example.com", "carol"], Some("s3kr1t\n"));
    assert!(output.status.success(), "{}", stderr(&output));

    // Raw mode shows the helper's own document.
    let raw = json(&harness.apwh(&["list", "example.com", "--raw"]));
    assert_eq!(raw["STATUS"], 0);
    assert_eq!(raw["Entries"][0]["USR"], "ada@example.com");

    // Logout drops the key, and reads stop working.
    assert!(harness.apwh(&["logout"]).status.success());
    assert_eq!(
        harness.apwh(&["list", "example.com"]).status.code(),
        Some(9)
    );
}

#[test]
fn an_ambiguous_get_names_the_candidates_instead_of_guessing() {
    let harness = Harness::normal("ambiguous");
    harness.authenticate();

    // No user name, and the site has two logins.
    let output = harness.apwh(&["get", "example.com"]);
    assert!(!output.status.success());
    let message = stderr(&output);
    assert!(message.contains("2 logins match"), "{message}");
    assert!(
        message.contains("ada@example.com") && message.contains("grace@example.com"),
        "{message}"
    );
    assert!(
        !stdout(&output).contains("hunter2"),
        "no secret should leak into stdout"
    );
}

#[test]
fn a_wrong_pin_is_reported_as_such_and_leaves_no_session() {
    let harness = Harness::normal("wrongpin");

    let output = harness.apwh_with_stdin(&["auth"], Some("000000"));
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("Incorrect PIN") || stderr(&output).contains("incorrect PIN"),
        "{}",
        stderr(&output)
    );

    let status = json(&harness.apwh(&["status", "--json"]));
    assert_eq!(status["authenticated"], false);
}

#[test]
fn a_two_step_handshake_can_span_two_processes() {
    let harness = Harness::normal("twostep");

    let begun = json(&harness.apwh(&["auth", "begin", "--json"]));
    let pending = PathBuf::from(begun["results"][0]["pending"].as_str().unwrap());
    assert!(pending.exists(), "the pending handshake should be on disk");

    let output = harness.apwh(&["auth", "complete", "--pin", PIN, "--json"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        !pending.exists(),
        "the pending handshake should be deleted once used"
    );

    assert_eq!(
        stdout(&harness.apwh(&["get", "example.com", "ada@example.com"])),
        "hunter2\n"
    );
}

#[test]
fn unsolicited_helper_messages_do_not_desynchronize_replies() {
    // The helper pushes a ONE_TIME_CODE_AVAILABLE before every reply. If the
    // relay returned it as an answer, each later reply would be off by one.
    let harness = Harness::start("push", "push", "10");
    harness.authenticate();

    assert_eq!(
        stdout(&harness.apwh(&["get", "example.com", "ada@example.com"])),
        "hunter2\n"
    );
    assert_eq!(
        stdout(&harness.apwh(&["otp", "get", "example.com"])),
        "246810\n"
    );
    assert_eq!(
        stdout(&harness.apwh(&["get", "example.com", "grace@example.com"])),
        "s3cr3t\n"
    );
}

#[test]
fn a_helper_that_never_answers_produces_a_timeout() {
    let harness = Harness::start("silent", "silent", "1");

    let start = Instant::now();
    let output = harness.apwh(&["capabilities"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("timed out"), "{}", stderr(&output));
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "timeout took too long"
    );

    // The service is still up and still answering after a timeout.
    assert!(UnixStream::connect(&harness.socket).is_ok());
}

#[test]
fn a_helper_that_exits_is_reported_and_takes_the_service_down() {
    let harness = Harness::start("exit", "exit", "5");

    let output = harness.apwh(&["capabilities"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("helper"), "{}", stderr(&output));

    // The service exits so launchd can restart it with a fresh helper.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && harness.socket.exists() {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !harness.socket.exists(),
        "the socket should be unlinked on shutdown"
    );
}

#[test]
fn sigterm_removes_the_socket_and_kills_the_helper() {
    let harness = Harness::normal("sigterm");
    let helper_pid = harness.helper_pid();
    assert!(process_alive(helper_pid));

    harness.send_signal(libc::SIGTERM);

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && (harness.socket.exists() || process_alive(helper_pid)) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!harness.socket.exists(), "socket left behind after SIGTERM");
    assert!(
        !process_alive(helper_pid),
        "helper process {helper_pid} was orphaned"
    );
}

#[test]
fn a_second_service_refuses_to_take_over_the_socket() {
    let harness = Harness::normal("single");

    let output = Command::new(apwh_binary())
        .args([
            "serve",
            "--socket",
            harness.socket.to_str().unwrap(),
            "--helper",
        ])
        .arg(fake_helper())
        .env("APWH_HOME", &harness.home)
        .output()
        .expect("run a second service");

    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("already listening"),
        "{}",
        stderr(&output)
    );
    // The first service is untouched.
    assert!(UnixStream::connect(&harness.socket).is_ok());
}

#[test]
fn the_service_clears_a_stale_session_on_start() {
    let harness = Harness::normal("stale");
    harness.authenticate();
    let config = harness.home.join("config.json");
    assert!(
        std::fs::read_to_string(&config)
            .unwrap()
            .contains("shared_key")
    );

    // Restarting the helper invalidates the key, so a restarted service must
    // drop it rather than let the user hit a decryption failure later.
    drop(harness);
    let harness = Harness::normal("stale");
    let status = json(&harness.apwh(&["status", "--json"]));
    assert_eq!(status["authenticated"], false);
}

#[test]
fn state_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let harness = Harness::normal("perms");
    harness.authenticate();

    let mode = |path: &Path| {
        std::fs::metadata(path)
            .unwrap_or_else(|_| panic!("stat {}", path.display()))
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode(&harness.home.join("config.json")), 0o600);
    assert_eq!(mode(&harness.socket), 0o600);
    assert_eq!(mode(&harness.home), 0o700);
}
