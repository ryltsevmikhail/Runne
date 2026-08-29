use runne_platform_ports::provider_credential_broker::{
    VerifiedWriterArtifact, VerifiedWriterLaunchSpec,
};
use serde::{Deserialize, Serialize};

/// Exact signed identity of one non-ad-hoc macOS native image.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct MacOsCodeIdentityV1 {
    identifier: String,
    team_identifier: String,
    cdhash: String,
}

impl MacOsCodeIdentityV1 {
    pub(super) fn new(
        identifier: impl Into<String>,
        team_identifier: impl Into<String>,
        cdhash: impl Into<String>,
    ) -> Option<Self> {
        let identity = Self {
            identifier: identifier.into(),
            team_identifier: team_identifier.into(),
            cdhash: cdhash.into(),
        };
        identity.valid().then_some(identity)
    }

    pub(super) fn valid(&self) -> bool {
        !self.identifier.is_empty()
            && self
                .identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
            && self.team_identifier.len() == 10
            && self
                .team_identifier
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
            && self.cdhash.len() == 40
            && self
                .cdhash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    }

    pub(super) fn digest_fields(&self) -> [&str; 3] {
        [&self.identifier, &self.team_identifier, &self.cdhash]
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

    /// Exact daemon image digest admitted by the same signed release tuple.
    #[must_use]
    pub const fn daemon_image_digest(&self) -> [u8; 32] {
        self.daemon_image_digest
    }

    /// Exact daemon code requirement admitted by the same signed release tuple.
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
