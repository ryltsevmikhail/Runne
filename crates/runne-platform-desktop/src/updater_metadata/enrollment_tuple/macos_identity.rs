#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code)
)]
use runne_api::MacOsCodeIdentityExpectationV1;
use runne_platform_ports::provider_credential_broker::{
    VerifiedWriterArtifact, VerifiedWriterLaunchSpec,
};

/// Private Desktop adapter from a signed expectation to a code requirement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct MacOsCodeIdentityV1 {
    identifier: String,
    team_identifier: String,
    cdhash: String,
}

impl MacOsCodeIdentityV1 {
    pub(super) fn from_expectation(identity: &MacOsCodeIdentityExpectationV1) -> Self {
        Self {
            identifier: identity.identifier().to_owned(),
            team_identifier: identity.team_identifier().to_owned(),
            cdhash: identity.cdhash().to_owned(),
        }
    }

    pub(super) fn requirement(&self) -> String {
        format!(
            "identifier \"{}\" and anchor apple generic and certificate leaf[subject.OU] = \"{}\" and cdhash H\"{}\"",
            self.identifier, self.team_identifier, self.cdhash
        )
    }
}

/// Opaque macOS launch admitted by one signed release tuple.
pub struct VerifiedMacOsWriterLaunch {
    launch: VerifiedWriterLaunchSpec,
    code_requirement: String,
    daemon_image_digest: [u8; 32],
    daemon_code_requirement: String,
}

impl VerifiedMacOsWriterLaunch {
    pub(super) fn new(
        artifact: VerifiedWriterArtifact,
        identity: &MacOsCodeIdentityV1,
        daemon_image_digest: [u8; 32],
        daemon_identity: &MacOsCodeIdentityV1,
    ) -> Self {
        Self {
            launch: VerifiedWriterLaunchSpec::new(artifact),
            code_requirement: identity.requirement(),
            daemon_image_digest,
            daemon_code_requirement: daemon_identity.requirement(),
        }
    }

    #[cfg(test)]
    pub(crate) const fn test_only(
        artifact: VerifiedWriterArtifact,
        code_requirement: String,
    ) -> Self {
        Self {
            launch: VerifiedWriterLaunchSpec::new(artifact),
            code_requirement,
            daemon_image_digest: [0; 32],
            daemon_code_requirement: String::new(),
        }
    }

    pub(crate) const fn launch(&self) -> &VerifiedWriterLaunchSpec {
        &self.launch
    }
    pub(crate) fn code_requirement(&self) -> String {
        self.code_requirement.clone()
    }
    #[must_use]
    pub const fn daemon_image_digest(&self) -> [u8; 32] {
        self.daemon_image_digest
    }
    #[must_use]
    pub fn daemon_code_requirement(&self) -> String {
        self.daemon_code_requirement.clone()
    }

    #[cfg(test)]
    pub(crate) fn with_test_requirement(&self, code_requirement: &str) -> Self {
        Self {
            launch: self.launch.clone(),
            code_requirement: code_requirement.to_owned(),
            daemon_image_digest: self.daemon_image_digest,
            daemon_code_requirement: self.daemon_code_requirement.clone(),
        }
    }
}

impl std::fmt::Debug for VerifiedMacOsWriterLaunch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedMacOsWriterLaunch(<signed-tuple>)")
    }
}
