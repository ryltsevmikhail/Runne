use runne_platform_ports::provider_credential_broker::{
    VerifiedWriterArtifact, VerifiedWriterLaunchSpec,
};
use serde::{Deserialize, Serialize};

/// Exact signed identity of one non-ad-hoc macOS writer image.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct MacOsWriterCodeIdentityV1 {
    identifier: String,
    team_identifier: String,
    cdhash: String,
}

impl MacOsWriterCodeIdentityV1 {
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
#[expect(
    dead_code,
    reason = "the live SecCode admission slice consumes this opaque launch"
)]
pub struct VerifiedMacOsWriterLaunch {
    launch: VerifiedWriterLaunchSpec,
    identity: MacOsWriterCodeIdentityV1,
}

#[expect(
    dead_code,
    reason = "the live SecCode admission slice consumes this opaque launch"
)]
impl VerifiedMacOsWriterLaunch {
    pub(super) const fn new(
        artifact: VerifiedWriterArtifact,
        identity: MacOsWriterCodeIdentityV1,
    ) -> Self {
        Self {
            launch: VerifiedWriterLaunchSpec::new(artifact),
            identity,
        }
    }

    pub(crate) const fn launch(&self) -> &VerifiedWriterLaunchSpec {
        &self.launch
    }

    pub(crate) fn code_requirement(&self) -> String {
        self.identity.requirement()
    }
}

impl std::fmt::Debug for VerifiedMacOsWriterLaunch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedMacOsWriterLaunch(<signed-tuple>)")
    }
}
