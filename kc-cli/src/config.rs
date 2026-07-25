//! Persistent CLI defaults and keychain-name resolution.

use std::path::{Path, PathBuf};

use keychain::{Error, KeychainLocator, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub default: String,
    pub search_paths: Vec<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default: "login".to_string(),
            search_paths: Vec::new(),
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
        let path = Self::path()?;
        let parent = path
            .parent()
            .ok_or_else(|| Error::other("configuration path has no parent directory"))?;
        std::fs::create_dir_all(parent)
            .map_err(|error| Error::io(format!("could not create {}", parent.display()), error))?;
        let temporary = path.with_extension("kdl.tmp");
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
            .unwrap_or_else(|| PathBuf::from(&self.default));
        let expanded = expand_tilde(&input)?;
        if expanded.is_absolute() || input.components().count() > 1 {
            return Ok(expanded);
        }
        Ok(KeychainLocator::new(self.all_search_paths()?)?.resolve(input))
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
        text
    }
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
        let line = raw.split("//").next().unwrap_or(raw).trim();
        if line.is_empty() {
            continue;
        }
        let (node, value) = line
            .split_once(char::is_whitespace)
            .ok_or_else(|| format!("line {} has no value", index + 1))?;
        let value = value.trim();
        match node {
            "version" if value == "1" => {}
            "version" => {
                return Err(format!(
                    "line {} has unsupported version {value}",
                    index + 1
                ));
            }
            "default" => config.default = parse_string(value, index + 1)?,
            "search-path" => config
                .search_paths
                .push(PathBuf::from(parse_string(value, index + 1)?)),
            _ => return Err(format!("line {} has unknown node {node:?}", index + 1)),
        }
    }
    Ok(config)
}

fn parse_string(value: &str, line: usize) -> std::result::Result<String, String> {
    serde_json::from_str(value)
        .map_err(|error| format!("line {line} has an invalid string: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_round_trips() {
        let config = Config {
            default: "machina".to_string(),
            search_paths: vec![PathBuf::from("~/keys"), PathBuf::from("/Volumes/keys")],
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
