//! Optional launchd integration, so the service comes back after login.
//!
//! A LaunchAgent (not a daemon) is the only correct choice here: the helper runs
//! as the logged-in user, reads that user's iCloud Keychain, and puts a PIN
//! dialog on their screen. None of that works from a system-level daemon.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::{Paths, ensure_private_dir, write_private};
use crate::error::{Error, IoContext, Result};

/// launchd job label, also the plist file name.
pub const LABEL: &str = "dev.matteson.apwh";

/// State of the installed agent, as reported by `launchctl`.
#[derive(Debug, Clone)]
pub struct AgentStatus {
    pub plist: PathBuf,
    pub installed: bool,
    pub loaded: bool,
    /// Present when the agent is currently running.
    pub pid: Option<i32>,
    /// Exit status of the last run, when launchd reports one.
    pub last_exit_status: Option<i32>,
}

pub fn plist_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::other("$HOME is not set"))?;
    Ok(PathBuf::from(home)
        .join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist")))
}

/// Render the LaunchAgent plist.
pub fn plist_contents(executable: &Path, paths: &Paths) -> String {
    let mut environment = String::new();
    // Only pin the state directory when it is not the default, so the plist
    // keeps working if the user later moves their home directory.
    if let Some(default_home) = default_home()
        && default_home != paths.home
    {
        environment = format!(
            "    <key>EnvironmentVariables</key>\n    \
             <dict>\n        <key>{}</key>\n        <string>{}</string>\n    </dict>\n",
            crate::config::HOME_ENV,
            escape_xml(&paths.home.to_string_lossy()),
        );
    }

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{executable}</string>
        <string>serve</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
{environment}    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
</dict>
</plist>
"#,
        label = LABEL,
        executable = escape_xml(&executable.to_string_lossy()),
        environment = environment,
        log = escape_xml(&paths.service_log().to_string_lossy()),
    )
}

/// Write the plist and load it. Replaces any previously loaded copy.
pub fn install(paths: &Paths, executable: &Path) -> Result<PathBuf> {
    if !executable.is_absolute() {
        return Err(Error::other(format!(
            "launchd needs an absolute path to the apwh binary, got {}",
            executable.display()
        )));
    }

    let plist = plist_path()?;
    ensure_private_dir(&paths.log_dir())?;
    if let Some(parent) = plist.parent() {
        std::fs::create_dir_all(parent)
            .context(format!("could not create {}", parent.display()))?;
    }
    write_private(&plist, plist_contents(executable, paths).as_bytes())?;
    // The plist itself holds no secrets and launchd reads it as the user.
    std::fs::set_permissions(&plist, permissions(0o644))
        .context(format!("could not set permissions on {}", plist.display()))?;

    // Unload an older copy first; failure here is expected when none is loaded.
    let _ = launchctl(&["bootout".into(), service_target()]);
    launchctl(&[
        "bootstrap".into(),
        domain_target(),
        plist.to_string_lossy().into_owned(),
    ])?;
    Ok(plist)
}

/// Unload the agent and delete the plist. Returns false if it was not installed.
pub fn uninstall() -> Result<bool> {
    let plist = plist_path()?;
    let _ = launchctl(&["bootout".into(), service_target()]);
    if !plist.exists() {
        return Ok(false);
    }
    crate::config::remove_if_present(&plist)?;
    Ok(true)
}

pub fn status() -> Result<AgentStatus> {
    let plist = plist_path()?;
    let installed = plist.exists();

    let output = Command::new("launchctl")
        .arg("list")
        .arg(LABEL)
        .output()
        .context("could not run launchctl")?;

    if !output.status.success() {
        return Ok(AgentStatus {
            plist,
            installed,
            loaded: false,
            pid: None,
            last_exit_status: None,
        });
    }

    let text = String::from_utf8_lossy(&output.stdout);
    Ok(AgentStatus {
        plist,
        installed,
        loaded: true,
        pid: parse_plist_integer(&text, "PID"),
        last_exit_status: parse_plist_integer(&text, "LastExitStatus"),
    })
}

fn domain_target() -> String {
    // SAFETY: getuid always succeeds.
    let uid = unsafe { libc::getuid() };
    format!("gui/{uid}")
}

fn service_target() -> String {
    format!("{}/{LABEL}", domain_target())
}

fn launchctl(args: &[String]) -> Result<()> {
    let output = Command::new("launchctl")
        .args(args)
        .output()
        .context("could not run launchctl")?;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let detail = if detail.is_empty() {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        detail
    };
    Err(Error::other(format!(
        "launchctl {} failed: {detail}",
        args.join(" ")
    )))
}

fn default_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(|home| PathBuf::from(home).join(".apwh"))
}

fn permissions(mode: u32) -> std::fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    std::fs::Permissions::from_mode(mode)
}

/// Pull `"key" = value;` out of `launchctl list` output.
fn parse_plist_integer(text: &str, key: &str) -> Option<i32> {
    text.lines()
        .find_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix(&format!("\"{key}\""))?;
            rest.trim_start().strip_prefix('=')
        })
        .and_then(|value| value.trim().trim_end_matches(';').trim().parse().ok())
}

fn escape_xml(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            other => escaped.push(other),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths_at(home: &str) -> Paths {
        Paths {
            home: PathBuf::from(home),
            socket: PathBuf::from(home).join("service.sock"),
        }
    }

    #[test]
    fn plist_names_the_binary_the_label_and_the_log() {
        let paths = paths_at("/Users/example/.apwh");
        let plist = plist_contents(Path::new("/usr/local/bin/apwh"), &paths);

        assert!(plist.contains("<string>dev.matteson.apwh</string>"));
        assert!(plist.contains("<string>/usr/local/bin/apwh</string>"));
        assert!(plist.contains("<string>serve</string>"));
        assert!(plist.contains("<string>/Users/example/.apwh/logs/service.log</string>"));
        assert!(plist.contains("<key>KeepAlive</key>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        // Well-formed enough to have balanced dict tags.
        assert_eq!(
            plist.matches("<dict>").count(),
            plist.matches("</dict>").count()
        );
    }

    #[test]
    fn plist_pins_a_non_default_state_directory() {
        let custom = plist_contents(Path::new("/bin/apwh"), &paths_at("/tmp/custom-apwh-home"));
        assert!(custom.contains("<key>APWH_HOME</key>"));
        assert!(custom.contains("<string>/tmp/custom-apwh-home</string>"));
    }

    #[test]
    fn plist_omits_the_environment_for_the_default_state_directory() {
        let Some(default_home) = default_home() else {
            return; // No $HOME in this environment; nothing to compare against.
        };
        let paths = Paths {
            home: default_home.clone(),
            socket: default_home.join("service.sock"),
        };
        assert!(!plist_contents(Path::new("/bin/apwh"), &paths).contains("EnvironmentVariables"));
    }

    #[test]
    fn install_requires_an_absolute_binary_path() {
        let error =
            install(&paths_at("/tmp/apwh-home"), Path::new("target/debug/apwh")).unwrap_err();
        assert!(error.to_string().contains("absolute path"));
    }

    #[test]
    fn xml_special_characters_are_escaped() {
        let paths = paths_at("/tmp/a&b");
        let plist = plist_contents(Path::new("/tmp/<apwh>"), &paths);
        assert!(plist.contains("/tmp/&lt;apwh&gt;"));
        assert!(plist.contains("/tmp/a&amp;b"));
        assert!(!plist.contains("/tmp/a&b/"));
    }

    #[test]
    fn launchctl_output_is_parsed_for_pid_and_exit_status() {
        let output = "{\n\t\"LimitLoadToSessionType\" = \"Aqua\";\n\t\"Label\" = \
                      \"dev.matteson.apwh\";\n\t\"LastExitStatus\" = 0;\n\t\"PID\" = 4321;\n}";
        assert_eq!(parse_plist_integer(output, "PID"), Some(4321));
        assert_eq!(parse_plist_integer(output, "LastExitStatus"), Some(0));
        assert_eq!(parse_plist_integer(output, "Missing"), None);
        // A stopped job reports no PID.
        assert_eq!(
            parse_plist_integer("{\n\t\"LastExitStatus\" = 70;\n}", "PID"),
            None
        );
    }

    #[test]
    fn service_target_includes_the_gui_domain_and_label() {
        let target = service_target();
        assert!(target.starts_with("gui/"));
        assert!(target.ends_with("/dev.matteson.apwh"));
    }
}
