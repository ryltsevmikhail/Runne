use serde::{Deserialize, Serialize};

use super::{MacOsCodeIdentityExpectationV1, NativeEnrollmentTupleV3};

pub const QUALIFICATION_BOOTSTRAP_DESKTOP_ENDPOINT_V1: &str =
    "com.runne.qualification-runner.desktop-bootstrap.v1";
pub const QUALIFICATION_BOOTSTRAP_RUNTIME_ENDPOINT_V1: &str =
    "com.runne.qualification-runner.runtime-bootstrap.v1";
pub const QUALIFICATION_BOOTSTRAP_ROOT_ENDPOINT_V1: &str =
    "com.runne.qualification-runner.root-consume.v1";
const MAX_BOOTSTRAP_IDENTIFIER_BYTES: usize = 255;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationBootstrapClientArtifactV1 {
    identity: MacOsCodeIdentityExpectationV1,
    image_sha256: String,
}

impl QualificationBootstrapClientArtifactV1 {
    pub fn new(
        identity: MacOsCodeIdentityExpectationV1,
        image_sha256: impl Into<String>,
    ) -> Option<Self> {
        let artifact = Self {
            identity,
            image_sha256: image_sha256.into(),
        };
        artifact.valid().then_some(artifact)
    }

    pub const fn identity(&self) -> &MacOsCodeIdentityExpectationV1 {
        &self.identity
    }

    pub const fn image_sha256(&self) -> &str {
        self.image_sha256.as_str()
    }

    fn valid(&self) -> bool {
        bounded_identity(&self.identity)
            && self.identity.valid()
            && nonzero_sha256(&self.image_sha256).is_some()
    }
}

/// Signed, descriptive bootstrap routing data. It creates no qualification or grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationBootstrapClientV1 {
    schema_version: u32,
    protocol_version: u32,
    desktop_endpoint: String,
    runtime_endpoint: String,
    root_endpoint: String,
    desktop_identity: MacOsCodeIdentityExpectationV1,
    runtime_identity: MacOsCodeIdentityExpectationV1,
    executor: QualificationBootstrapClientArtifactV1,
    root: QualificationBootstrapClientArtifactV1,
    qualification_profile_sha256: String,
}

impl QualificationBootstrapClientV1 {
    pub fn new(
        desktop_identity: MacOsCodeIdentityExpectationV1,
        runtime_identity: MacOsCodeIdentityExpectationV1,
        executor: QualificationBootstrapClientArtifactV1,
        root: QualificationBootstrapClientArtifactV1,
        qualification_profile_sha256: impl Into<String>,
    ) -> Option<Self> {
        let client = Self {
            schema_version: 1,
            protocol_version: 1,
            desktop_endpoint: QUALIFICATION_BOOTSTRAP_DESKTOP_ENDPOINT_V1.into(),
            runtime_endpoint: QUALIFICATION_BOOTSTRAP_RUNTIME_ENDPOINT_V1.into(),
            root_endpoint: QUALIFICATION_BOOTSTRAP_ROOT_ENDPOINT_V1.into(),
            desktop_identity,
            runtime_identity,
            executor,
            root,
            qualification_profile_sha256: qualification_profile_sha256.into(),
        };
        client.valid().then_some(client)
    }

    pub const fn desktop_identity(&self) -> &MacOsCodeIdentityExpectationV1 {
        &self.desktop_identity
    }

    pub const fn runtime_identity(&self) -> &MacOsCodeIdentityExpectationV1 {
        &self.runtime_identity
    }

    pub const fn executor_identity(&self) -> &MacOsCodeIdentityExpectationV1 {
        self.executor.identity()
    }

    pub const fn executor_image_sha256(&self) -> &str {
        self.executor.image_sha256()
    }

    pub const fn root_identity(&self) -> &MacOsCodeIdentityExpectationV1 {
        self.root.identity()
    }

    pub const fn root_image_sha256(&self) -> &str {
        self.root.image_sha256()
    }

    pub fn qualification_profile_sha256(&self) -> [u8; 32] {
        nonzero_sha256(&self.qualification_profile_sha256).unwrap_or_default()
    }

    pub(super) fn valid_for_v3(&self, tuple: &NativeEnrollmentTupleV3) -> bool {
        let identities = tuple.code_identities().values();
        let digests = tuple.digests();
        self.valid()
            && self.desktop_identity == *identities[0]
            && self.runtime_identity == *identities[2]
            && self.executor.identity.team_identifier() == self.desktop_identity.team_identifier()
            && self.root.identity.team_identifier() == self.desktop_identity.team_identifier()
            && distinct_identity(self.executor.identity(), &identities)
            && distinct_identity(self.root.identity(), &identities)
            && self.executor.identity.cdhash() != self.root.identity.cdhash()
            && self.executor.identity.identifier() != self.root.identity.identifier()
            && distinct_image(self.executor.image_sha256(), digests)
            && distinct_image(self.root.image_sha256(), digests)
            && self.executor.image_sha256() != self.root.image_sha256()
    }

    fn valid(&self) -> bool {
        self.schema_version == 1
            && self.protocol_version == 1
            && self.desktop_endpoint == QUALIFICATION_BOOTSTRAP_DESKTOP_ENDPOINT_V1
            && self.runtime_endpoint == QUALIFICATION_BOOTSTRAP_RUNTIME_ENDPOINT_V1
            && self.root_endpoint == QUALIFICATION_BOOTSTRAP_ROOT_ENDPOINT_V1
            && bounded_identity(&self.desktop_identity)
            && bounded_identity(&self.runtime_identity)
            && self.desktop_identity.valid()
            && self.runtime_identity.valid()
            && self.executor.valid()
            && self.root.valid()
            && nonzero_sha256(&self.qualification_profile_sha256).is_some()
    }
}

fn bounded_identity(identity: &MacOsCodeIdentityExpectationV1) -> bool {
    identity.identifier().len() <= MAX_BOOTSTRAP_IDENTIFIER_BYTES
}

fn distinct_identity(
    artifact: &MacOsCodeIdentityExpectationV1,
    identities: &[&MacOsCodeIdentityExpectationV1; 4],
) -> bool {
    identities.iter().all(|identity| {
        artifact.cdhash() != identity.cdhash() && artifact.identifier() != identity.identifier()
    })
}

fn distinct_image(image: &str, digests: &super::NativeEnrollmentTupleV3Digests) -> bool {
    [
        &digests.desktop_sha256,
        &digests.writer_sha256,
        &digests.daemon_sha256,
        &digests.credential_service_sha256,
    ]
    .iter()
    .all(|expected| expected.as_str() != image)
}

fn nonzero_sha256(value: &str) -> Option<[u8; 32]> {
    (value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')))
    .then(|| hex::decode(value).ok())??
    .try_into()
    .ok()
    .filter(|digest: &[u8; 32]| digest.iter().any(|byte| *byte != 0))
}
