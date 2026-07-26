//! Persistent CLI defaults and keychain-name resolution.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use keychain::{AccessDefault, AccessMode, Error, KeychainLocator, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub default: String,
    pub search_paths: Vec<PathBuf>,
    pub access: Vec<ConfiguredAccessPolicy>,
}

/// A requirement blob source persisted for later native ACL projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequirementSource {
    pub application: PathBuf,
    pub file: PathBuf,
}

/// One named keychain's policy as stored in `keychain.kdl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredAccessPolicy {
    pub keychain: String,
    pub mode: AccessMode,
    pub default: AccessDefault,
    pub trust_apps: Vec<PathBuf>,
    pub trust_requirements: Vec<RequirementSource>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default: "login".to_string(),
            search_paths: Vec::new(),
            access: Vec::new(),
        }
    }
}

impl Config {
    pub fn path() -> Result<PathBuf> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| Error::other("HOME is not set; cannot locate ~/.config/keychain.kdl"))?;
        Ok(home.join(".config/keychain.kdl"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(Error::reading(&path, error)),
        };
        parse(&text)
            .map_err(|error| Error::other(format!("could not parse {}: {error}", path.display())))
    }

    pub fn save(&self) -> Result<PathBuf> {
        static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);

        let path = Self::path()?;
        let parent = path
            .parent()
            .ok_or_else(|| Error::other("configuration path has no parent directory"))?;
        std::fs::create_dir_all(parent)
            .map_err(|error| Error::io(format!("could not create {}", parent.display()), error))?;
        let temporary = path.with_file_name(format!(
            ".keychain.kdl.{}.{}.tmp",
            std::process::id(),
            TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&temporary, self.render()).map_err(|error| {
            Error::io(format!("could not write {}", temporary.display()), error)
        })?;
        std::fs::rename(&temporary, &path)
            .map_err(|error| Error::io(format!("could not replace {}", path.display()), error))?;
        Ok(path)
    }

    pub fn all_search_paths(&self) -> Result<Vec<PathBuf>> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| Error::other("HOME is not set; cannot resolve keychain names"))?;
        let mut paths = vec![home.join("Library/Keychains")];
        for path in &self.search_paths {
            let path = expand_tilde(path)?;
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
        Ok(paths)
    }

    pub fn resolve(&self, input: Option<&Path>) -> Result<PathBuf> {
        let input = input
            .map(Path::to_path_buf)
            .or_else(|| {
                std::env::var_os("KC_DEFAULT_KEYCHAIN")
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from)
            })
            .unwrap_or_else(|| PathBuf::from(&self.default));
        let expanded = expand_tilde(&input)?;
        if expanded.is_absolute() {
            return Ok(stable_path(expanded));
        }
        if input.components().count() > 1 {
            return std::env::current_dir()
                .map(|directory| directory.join(expanded))
                .map(stable_path)
                .map_err(|error| Error::io("could not resolve the current directory", error));
        }
        Ok(KeychainLocator::new(self.all_search_paths()?)?.resolve(input))
    }

    /// The policy whose keychain selector resolves to `path`.
    pub fn access_policy_for(&self, path: &Path) -> Result<Option<&ConfiguredAccessPolicy>> {
        for policy in &self.access {
            if self.resolve(Some(Path::new(&policy.keychain)))? == path {
                return Ok(Some(policy));
            }
        }
        Ok(None)
    }

    /// Replace a keychain's policy, preserving the order of other declarations.
    pub fn set_access_policy(&mut self, policy: ConfiguredAccessPolicy) {
        if let Some(existing) = self
            .access
            .iter_mut()
            .find(|existing| existing.keychain == policy.keychain)
        {
            *existing = policy;
        } else {
            self.access.push(policy);
        }
    }

    /// Remove a keychain's policy.
    pub fn clear_access_policy(&mut self, keychain: &str) -> bool {
        let before = self.access.len();
        self.access.retain(|policy| policy.keychain != keychain);
        self.access.len() != before
    }

    pub fn render(&self) -> String {
        let mut text = format!(
            "version 1\ndefault {}\n",
            serde_json::to_string(&self.default).expect("strings serialize")
        );
        for path in &self.search_paths {
            text.push_str(&format!(
                "search-path {}\n",
                serde_json::to_string(&path.to_string_lossy()).expect("paths serialize")
            ));
        }
        for policy in &self.access {
            text.push_str(&format!(
                "access {} mode={} default={}\n",
                string(&policy.keychain),
                string(access_mode_name(policy.mode)),
                string(access_default_name(policy.default)),
            ));
            for path in &policy.trust_apps {
                text.push_str(&format!(
                    "trust-app {} {}\n",
                    string(&policy.keychain),
                    string(&path.to_string_lossy()),
                ));
            }
            for source in &policy.trust_requirements {
                text.push_str(&format!(
                    "trust-requirement {} {} {}\n",
                    string(&policy.keychain),
                    string(&source.application.to_string_lossy()),
                    string(&source.file.to_string_lossy()),
                ));
            }
        }
        text
    }
}

fn string(value: &str) -> String {
    serde_json::to_string(value).expect("strings serialize")
}

pub fn access_mode_name(mode: AccessMode) -> &'static str {
    match mode {
        AccessMode::Extended => "extended",
        AccessMode::Native => "native",
        AccessMode::Hybrid => "hybrid",
    }
}

pub fn access_default_name(default: AccessDefault) -> &'static str {
    match default {
        AccessDefault::Allow => "allow",
        AccessDefault::Prompt => "prompt",
        AccessDefault::Deny => "deny",
    }
}

fn stable_path(path: PathBuf) -> PathBuf {
    if let Ok(canonical) = std::fs::canonicalize(&path) {
        return canonical;
    }
    let Some(parent) = path.parent() else {
        return path;
    };
    let Some(name) = path.file_name() else {
        return path;
    };
    std::fs::canonicalize(parent)
        .map(|parent| parent.join(name))
        .unwrap_or(path)
}

fn expand_tilde(path: &Path) -> Result<PathBuf> {
    let text = path.to_string_lossy();
    if text == "~" || text.starts_with("~/") {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| Error::other("HOME is not set; cannot expand ~"))?;
        return Ok(if text == "~" {
            home
        } else {
            home.join(&text[2..])
        });
    }
    Ok(path.to_path_buf())
}

fn parse(text: &str) -> std::result::Result<Config, String> {
    let mut config = Config::default();
    for (index, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let tokens = tokens(line, index + 1)?;
        let Some(node) = tokens.first().map(String::as_str) else {
            continue;
        };
        let values = &tokens[1..];
        match node {
            "version" if values == ["1"] => {}
            "version" => {
                return Err(format!(
                    "line {} has unsupported version {}",
                    index + 1,
                    values.join(" ")
                ));
            }
            "default" if values.len() == 1 => config.default.clone_from(&values[0]),
            "search-path" if values.len() == 1 => {
                config.search_paths.push(PathBuf::from(&values[0]))
            }
            "access" => {
                let keychain = positional(values, 0, index + 1, "access keychain")?;
                let mode = property(values, "mode", index + 1)?
                    .map(parse_access_mode)
                    .transpose()?
                    .unwrap_or(AccessMode::Extended);
                let default = property(values, "default", index + 1)?
                    .map(parse_access_default)
                    .transpose()?
                    .unwrap_or(AccessDefault::Prompt);
                if config
                    .access
                    .iter()
                    .any(|policy| policy.keychain == keychain)
                {
                    return Err(format!(
                        "line {} repeats access policy for {keychain:?}",
                        index + 1
                    ));
                }
                config.access.push(ConfiguredAccessPolicy {
                    keychain,
                    mode,
                    default,
                    trust_apps: Vec::new(),
                    trust_requirements: Vec::new(),
                });
            }
            "trust-app" => {
                let keychain = positional(values, 0, index + 1, "trust-app keychain")?;
                let path = positional(values, 1, index + 1, "trusted application path")?;
                access_mut(&mut config, &keychain, index + 1)?
                    .trust_apps
                    .push(PathBuf::from(path));
            }
            "trust-requirement" => {
                let keychain = positional(values, 0, index + 1, "trust-requirement keychain")?;
                let application = positional(values, 1, index + 1, "trusted application path")?;
                let file = positional(values, 2, index + 1, "requirement file")?;
                access_mut(&mut config, &keychain, index + 1)?
                    .trust_requirements
                    .push(RequirementSource {
                        application: PathBuf::from(application),
                        file: PathBuf::from(file),
                    });
            }
            "default" | "search-path" => {
                return Err(format!(
                    "line {} has the wrong number of values for {node}",
                    index + 1
                ));
            }
            _ => return Err(format!("line {} has unknown node {node:?}", index + 1)),
        }
    }
    Ok(config)
}

fn access_mut<'a>(
    config: &'a mut Config,
    keychain: &str,
    line: usize,
) -> std::result::Result<&'a mut ConfiguredAccessPolicy, String> {
    config
        .access
        .iter_mut()
        .find(|policy| policy.keychain == keychain)
        .ok_or_else(|| {
            format!("line {line} adds trust to {keychain:?} before declaring its access policy")
        })
}

fn parse_access_mode(value: String) -> std::result::Result<AccessMode, String> {
    match value.as_str() {
        "extended" => Ok(AccessMode::Extended),
        "native" => Ok(AccessMode::Native),
        "hybrid" => Ok(AccessMode::Hybrid),
        _ => Err(format!(
            "unknown access mode {value:?}; expected extended, native, or hybrid"
        )),
    }
}

fn parse_access_default(value: String) -> std::result::Result<AccessDefault, String> {
    match value.as_str() {
        "allow" => Ok(AccessDefault::Allow),
        "prompt" => Ok(AccessDefault::Prompt),
        "deny" => Ok(AccessDefault::Deny),
        _ => Err(format!(
            "unknown access default {value:?}; expected allow, prompt, or deny"
        )),
    }
}

fn positional(
    values: &[String],
    index: usize,
    line: usize,
    description: &str,
) -> std::result::Result<String, String> {
    values
        .iter()
        .filter(|value| !value.contains('='))
        .nth(index)
        .cloned()
        .ok_or_else(|| format!("line {line} has no {description}"))
}

fn property(
    values: &[String],
    name: &str,
    line: usize,
) -> std::result::Result<Option<String>, String> {
    let prefix = format!("{name}=");
    let found: Vec<_> = values
        .iter()
        .filter_map(|value| value.strip_prefix(&prefix))
        .collect();
    match found.as_slice() {
        [] => Ok(None),
        [value] => Ok(Some((*value).to_string())),
        _ => Err(format!("line {line} repeats property {name:?}")),
    }
}

fn strip_comment(line: &str) -> &str {
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            '/' if !quoted && line[index..].starts_with("//") => return &line[..index],
            _ => {}
        }
    }
    line
}

fn tokens(line: &str, number: usize) -> std::result::Result<Vec<String>, String> {
    let mut output = Vec::new();
    let mut token = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for character in line.chars() {
        if escaped {
            token.push(character);
            escaped = false;
            continue;
        }
        match character {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            character if character.is_whitespace() && !quoted => {
                if !token.is_empty() {
                    output.push(std::mem::take(&mut token));
                }
            }
            _ => token.push(character),
        }
    }
    if quoted || escaped {
        return Err(format!("line {number} has an unterminated string"));
    }
    if !token.is_empty() {
        output.push(token);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_round_trips() {
        let config = Config {
            default: "machina".to_string(),
            search_paths: vec![PathBuf::from("~/keys"), PathBuf::from("/Volumes/keys")],
            access: vec![ConfiguredAccessPolicy {
                keychain: "machina".to_string(),
                mode: AccessMode::Hybrid,
                default: AccessDefault::Prompt,
                trust_apps: vec![PathBuf::from("/usr/bin/security")],
                trust_requirements: vec![RequirementSource {
                    application: PathBuf::from("/Applications/Example.app"),
                    file: PathBuf::from("~/requirements/example.bin"),
                }],
            }],
        };
        assert_eq!(parse(&config.render()).unwrap(), config);
    }

    #[test]
    fn system_is_the_system_keychain() {
        assert_eq!(
            Config::default()
                .resolve(Some(Path::new("system")))
                .unwrap(),
            PathBuf::from(keychain::SYSTEM_KEYCHAIN)
        );
    }
}
