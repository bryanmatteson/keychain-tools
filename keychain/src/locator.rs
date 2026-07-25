//! Resolve human-friendly keychain names to database paths.

use std::path::{Path, PathBuf};

/// The system keychain, which does not live in a user's keychain directory.
pub const SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";

/// Resolves a bare keychain name against ordered search directories.
///
/// Existing files are preferred in `.keychain-db`, `.keychain`, then exact-name
/// order. If no candidate exists, the conventional `.keychain-db` path in the
/// first search directory is returned. Absolute and multi-component paths pass
/// through unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeychainLocator {
    search_paths: Vec<PathBuf>,
}

impl KeychainLocator {
    /// Create a locator. At least one search path is required.
    pub fn new(search_paths: impl IntoIterator<Item = PathBuf>) -> crate::Result<Self> {
        let search_paths: Vec<_> = search_paths.into_iter().collect();
        if search_paths.is_empty() {
            return Err(crate::Error::other(
                "a keychain locator requires at least one search path",
            ));
        }
        Ok(Self { search_paths })
    }

    /// The ordered directories searched for bare keychain names.
    pub fn search_paths(&self) -> &[PathBuf] {
        &self.search_paths
    }

    /// Resolve a path or bare name.
    pub fn resolve(&self, input: impl AsRef<Path>) -> PathBuf {
        let input = input.as_ref();
        if input.is_absolute() || input.components().count() > 1 {
            return input.to_path_buf();
        }

        let name = input.to_string_lossy();
        if name.eq_ignore_ascii_case("system") {
            return PathBuf::from(SYSTEM_KEYCHAIN);
        }

        let candidates = if name.ends_with(".keychain") || name.ends_with(".keychain-db") {
            vec![name.into_owned()]
        } else {
            vec![
                format!("{name}.keychain-db"),
                format!("{name}.keychain"),
                name.into_owned(),
            ]
        };
        for directory in &self.search_paths {
            for candidate in &candidates {
                let path = directory.join(candidate);
                if path.exists() {
                    return path;
                }
            }
        }
        self.search_paths[0].join(&candidates[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_is_special() {
        let locator = KeychainLocator::new([PathBuf::from("/tmp")]).unwrap();
        assert_eq!(locator.resolve("system"), PathBuf::from(SYSTEM_KEYCHAIN));
    }

    #[test]
    fn absent_names_use_the_primary_database_path() {
        let locator = KeychainLocator::new([PathBuf::from("/keys")]).unwrap();
        assert_eq!(
            locator.resolve("machina"),
            PathBuf::from("/keys/machina.keychain-db")
        );
    }
}
