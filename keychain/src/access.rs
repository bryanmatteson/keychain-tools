//! Keychain-wide access policy primitives.
//!
//! A keychain file stores access control on each item, not on the database as a
//! whole. [`AccessPolicy`] is the higher-level model applications can use to
//! make one policy authoritative for a keychain and project it onto items when
//! desired. The library deliberately returns decisions instead of prompting:
//! terminal UI belongs to callers such as `kc`.

use crate::acl::TrustedApplication;

/// How a keychain-wide policy is enforced.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AccessMode {
    /// Enforce the policy in the direct reader only.
    #[default]
    Extended,
    /// Project trusted applications into Apple's per-item ACLs.
    Native,
    /// Enforce in the direct reader and project into Apple's per-item ACLs.
    Hybrid,
}

impl AccessMode {
    /// Whether direct readers should evaluate this policy.
    pub const fn enforces_direct(self) -> bool {
        matches!(self, Self::Extended | Self::Hybrid)
    }

    /// Whether newly written items should receive native ACLs from the policy.
    pub const fn projects_native(self) -> bool {
        matches!(self, Self::Native | Self::Hybrid)
    }
}

/// Default result when a direct reader requests an item's secret.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AccessDefault {
    /// Read without another confirmation.
    Allow,
    /// Require an interactive confirmation.
    #[default]
    Prompt,
    /// Refuse the read.
    Deny,
}

/// A decision returned to a direct reader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessDecision {
    Allow,
    Prompt,
    Deny,
}

/// One keychain-wide policy.
///
/// `trusted_applications` can be written into every new or existing item's
/// native ACL. It is not used to identify the parent of a command-line process:
/// that cannot be authenticated from ordinary shell process metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessPolicy {
    pub mode: AccessMode,
    pub default: AccessDefault,
    pub trusted_applications: Vec<TrustedApplication>,
}

impl Default for AccessPolicy {
    fn default() -> Self {
        Self {
            mode: AccessMode::Extended,
            default: AccessDefault::Prompt,
            trusted_applications: Vec::new(),
        }
    }
}

impl AccessPolicy {
    /// The decision a direct reader must honor.
    pub const fn direct_decision(&self) -> AccessDecision {
        if !self.mode.enforces_direct() {
            return AccessDecision::Allow;
        }
        match self.default {
            AccessDefault::Allow => AccessDecision::Allow,
            AccessDefault::Prompt => AccessDecision::Prompt,
            AccessDefault::Deny => AccessDecision::Deny,
        }
    }

    /// Applications to place in a native item ACL.
    ///
    /// An empty list has Apple's established "allow any application" meaning.
    pub fn native_trusted_applications(&self) -> &[TrustedApplication] {
        &self.trusted_applications
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_only_does_not_claim_to_gate_direct_reads() {
        let policy = AccessPolicy {
            mode: AccessMode::Native,
            default: AccessDefault::Deny,
            ..AccessPolicy::default()
        };
        assert_eq!(policy.direct_decision(), AccessDecision::Allow);
        assert!(policy.mode.projects_native());
    }

    #[test]
    fn extended_and_hybrid_return_the_configured_decision() {
        for mode in [AccessMode::Extended, AccessMode::Hybrid] {
            let policy = AccessPolicy {
                mode,
                default: AccessDefault::Deny,
                ..AccessPolicy::default()
            };
            assert_eq!(policy.direct_decision(), AccessDecision::Deny);
        }
    }
}
