//! Designated requirements for trusted-application ACLs.
//!
//! An ACL entry that names a trusted application embeds that application's
//! designated requirement — byte for byte the blob in its own code signature,
//! magic and length header included. There is nothing to compute: the blob is
//! copied out of the binary.
//!
//! With the `trust-apps` feature, [`crate::requirement::for_application`] reads
//! it directly via `macho-codesign`. Without it, supply the bytes yourself —
//! `csreq -b` writes the same blob — and use [`crate::requirement::from_blob`].

use crate::acl::TrustedApplication;
use crate::error::{Error, Result};

/// Trust an application whose requirement blob you already have.
///
/// The blob must start with the `CSMAGIC_REQUIREMENT` magic (`0xfade0c00`); a
/// requirement in any other encoding would be silently ignored by macOS.
pub fn from_blob(path: impl Into<String>, requirement: Vec<u8>) -> Result<TrustedApplication> {
    if requirement.len() < 8 || requirement[..4] != [0xfa, 0xde, 0x0c, 0x00] {
        return Err(Error::other(
            "a designated requirement must begin with the 0xfade0c00 magic",
        ));
    }
    let declared = u32::from_be_bytes([
        requirement[4],
        requirement[5],
        requirement[6],
        requirement[7],
    ]) as usize;
    if declared != requirement.len() {
        return Err(Error::other(format!(
            "requirement declares {declared} bytes but is {}",
            requirement.len()
        )));
    }
    Ok(TrustedApplication::new(path, requirement))
}

/// Trust the application at `path`, reading its designated requirement from its
/// code signature.
#[cfg(feature = "trust-apps")]
pub fn for_application(path: &std::path::Path) -> Result<TrustedApplication> {
    let bytes = std::fs::read(path)
        .map_err(|source| Error::io(format!("could not read {}", path.display()), source))?;
    let container = macho_core::parse(&bytes).map_err(|error| {
        Error::other(format!("{} is not a Mach-O image: {error}", path.display()))
    })?;

    // A universal binary's slices share one signing identity, so the first
    // image's requirement is the one macOS records.
    for macho in container.macho_files() {
        let signature = macho_codesign::parse_code_signature(macho).map_err(|error| {
            Error::other(format!(
                "{} has no readable code signature: {error}",
                path.display()
            ))
        })?;
        if let Some(requirement) = signature.designated_requirement() {
            return from_blob(path.to_string_lossy().into_owned(), requirement.to_vec());
        }
    }
    Err(Error::other(format!(
        "{} has no designated requirement; it may be unsigned",
        path.display()
    )))
}

/// Without the `trust-apps` feature there is no way to read a signature.
#[cfg(not(feature = "trust-apps"))]
pub fn for_application(path: &std::path::Path) -> Result<TrustedApplication> {
    Err(Error::other(format!(
        "cannot read the designated requirement of {} — rebuild with `--features trust-apps`, \
         or pass a requirement blob from `csreq -b`",
        path.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The designated requirement of `/usr/bin/security`, as macOS stores it in
    /// both the binary and the ACL.
    fn sample() -> Vec<u8> {
        hex::decode(concat!(
            "fade0c000000003000000001000000060000000200000012",
            "636f6d2e6170706c652e7365637572697479000000000003",
        ))
        .unwrap()
    }

    #[test]
    fn accepts_a_well_formed_requirement_blob() {
        let app = from_blob("/usr/bin/security", sample()).unwrap();
        assert_eq!(app.path, "/usr/bin/security");
        assert_eq!(app.requirement, sample());
        assert_eq!(
            app.legacy_hash, [0u8; 20],
            "left zeroed: it is not evaluated"
        );
    }

    #[test]
    fn rejects_anything_that_is_not_a_requirement() {
        assert!(from_blob("/bin/ls", Vec::new()).is_err());
        assert!(from_blob("/bin/ls", b"designated => anchor apple".to_vec()).is_err());

        // A truncated blob declares more than it carries.
        let mut truncated = sample();
        truncated.truncate(16);
        assert!(from_blob("/bin/ls", truncated).is_err());
    }

    #[cfg(feature = "trust-apps")]
    #[test]
    fn reads_the_requirement_out_of_a_signed_binary() {
        let app = for_application(std::path::Path::new("/usr/bin/security")).unwrap();
        assert_eq!(app.requirement, sample(), "must match what the ACL embeds");
    }

    #[cfg(not(feature = "trust-apps"))]
    #[test]
    fn without_the_feature_the_error_says_what_to_do() {
        let error = for_application(std::path::Path::new("/usr/bin/security")).unwrap_err();
        assert!(error.to_string().contains("trust-apps"));
        assert!(error.to_string().contains("csreq"));
    }
}
