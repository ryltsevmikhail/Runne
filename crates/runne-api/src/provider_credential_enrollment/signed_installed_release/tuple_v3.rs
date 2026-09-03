use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::model::UpdateTargetV2;
use super::qualification::NativeEnrollmentQualificationRowV1;
use super::tuple::{decode_digest, digest_valid};
use super::{MacOsCodeIdentityExpectationV1, NativeEnrollmentTupleError};

#[path = "tuple_v3/protocol.rs"]
mod protocol;
#[path = "tuple_v3/qualification.rs"]
mod qualification;
pub use protocol::{
    NativeEnrollmentTupleV3ProtocolCompatibility, NativeEnrollmentTupleV3ProtocolVersions,
};

const TUPLE_DOMAIN: &[u8] = b"gocode/native-enrollment-release-tuple/v3\0";
const TEAM_ID: &str = "758F9Z45SR";
const HELPER_ID: &str = "com.runne.credential-service";
const APPLICATION_ID_GROUP: &str = "758F9Z45SR.com.runne.credential-service";
const DESKTOP_ENDPOINT: &str = "com.runne.credential-service.desktop.v1";
const RUNTIME_ENDPOINT: &str = "com.runne.credential-service.runtime.v1";
const WRITER_ENDPOINT: &str = "com.runne.credential-service.writer.v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeEnrollmentTupleV3Digests {
    pub candidate_sha256: String,
    pub desktop_sha256: String,
    pub writer_sha256: String,
    pub daemon_sha256: String,
    pub credential_service_sha256: String,
    pub launch_agent_plist_sha256: String,
    pub entitlements_sha256: String,
    pub provisioning_sha256: String,
    pub xpc_protocol_sha256: String,
    pub contract_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeEnrollmentTupleV3Deployment {
    helper_bundle_identifier: String,
    service_application_id_group: String,
    desktop_mach_service: String,
    runtime_mach_service: String,
    writer_mach_service: String,
    xpc_transport: String,
    xpc_protocol_versions: NativeEnrollmentTupleV3ProtocolVersions,
}

impl NativeEnrollmentTupleV3Deployment {
    pub fn exact(xpc_protocol_versions: NativeEnrollmentTupleV3ProtocolVersions) -> Self {
        Self::for_application_id_group(APPLICATION_ID_GROUP, xpc_protocol_versions)
    }

    pub fn for_application_id_group(
        service_application_id_group: impl Into<String>,
        xpc_protocol_versions: NativeEnrollmentTupleV3ProtocolVersions,
    ) -> Self {
        Self {
            helper_bundle_identifier: HELPER_ID.into(),
            service_application_id_group: service_application_id_group.into(),
            desktop_mach_service: DESKTOP_ENDPOINT.into(),
            runtime_mach_service: RUNTIME_ENDPOINT.into(),
            writer_mach_service: WRITER_ENDPOINT.into(),
            xpc_transport: "nsxpc".into(),
            xpc_protocol_versions,
        }
    }

    pub const fn service_application_id_group(&self) -> &str {
        self.service_application_id_group.as_str()
    }
    pub const fn protocol_versions(&self) -> &NativeEnrollmentTupleV3ProtocolVersions {
        &self.xpc_protocol_versions
    }
    pub(super) fn digest_fields(&self) -> [&str; 6] {
        [
            &self.helper_bundle_identifier,
            &self.service_application_id_group,
            &self.desktop_mach_service,
            &self.runtime_mach_service,
            &self.writer_mach_service,
            &self.xpc_transport,
        ]
    }
    fn valid(&self) -> bool {
        self.helper_bundle_identifier == HELPER_ID
            && valid_application_id_group(&self.service_application_id_group)
            && self.desktop_mach_service == DESKTOP_ENDPOINT
            && self.runtime_mach_service == RUNTIME_ENDPOINT
            && self.writer_mach_service == WRITER_ENDPOINT
            && self.xpc_transport == "nsxpc"
            && self.xpc_protocol_versions.valid()
    }
}

fn valid_application_id_group(value: &str) -> bool {
    (12..=128).contains(&value.len())
        && value.starts_with("758F9Z45SR.")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeEnrollmentTupleV3CodeIdentities {
    desktop: MacOsCodeIdentityExpectationV1,
    writer: MacOsCodeIdentityExpectationV1,
    daemon: MacOsCodeIdentityExpectationV1,
    credential_service: MacOsCodeIdentityExpectationV1,
}

impl NativeEnrollmentTupleV3CodeIdentities {
    pub const fn new(
        desktop: MacOsCodeIdentityExpectationV1,
        writer: MacOsCodeIdentityExpectationV1,
        daemon: MacOsCodeIdentityExpectationV1,
        credential_service: MacOsCodeIdentityExpectationV1,
    ) -> Self {
        Self {
            desktop,
            writer,
            daemon,
            credential_service,
        }
    }

    pub(super) fn values(&self) -> [&MacOsCodeIdentityExpectationV1; 4] {
        [
            &self.desktop,
            &self.writer,
            &self.daemon,
            &self.credential_service,
        ]
    }
    fn valid(&self) -> bool {
        let values = self.values();
        let expected = ["com.runne.desktop", "runne", "runned", HELPER_ID];
        values.iter().zip(expected).all(|(identity, identifier)| {
            identity.valid()
                && identity.identifier() == identifier
                && identity.team_identifier() == TEAM_ID
        }) && values.iter().enumerate().all(|(index, identity)| {
            !values[..index]
                .iter()
                .any(|prior| prior.cdhash() == identity.cdhash())
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeEnrollmentTupleV3 {
    schema_version: u32,
    digests: NativeEnrollmentTupleV3Digests,
    deployment: NativeEnrollmentTupleV3Deployment,
    code_identities: NativeEnrollmentTupleV3CodeIdentities,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_enrollment_qualification: Option<NativeEnrollmentQualificationRowV1>,
    tuple_sha256: String,
}

impl NativeEnrollmentTupleV3 {
    pub fn new(
        digests: NativeEnrollmentTupleV3Digests,
        deployment: NativeEnrollmentTupleV3Deployment,
        code_identities: NativeEnrollmentTupleV3CodeIdentities,
        target: &UpdateTargetV2,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        let mut tuple = Self {
            schema_version: 3,
            digests,
            deployment,
            code_identities,
            native_enrollment_qualification: None,
            tuple_sha256: String::new(),
        };
        tuple
            .valid_base(target, false)
            .then_some(())
            .ok_or(NativeEnrollmentTupleError::Rejected)?;
        tuple.tuple_sha256 = tuple.digest_for(target);
        Ok(tuple)
    }

    pub(super) fn valid_signed(&self, target: &UpdateTargetV2) -> bool {
        self.valid_base(target, true) && self.qualification_valid(target)
    }
    pub(super) fn valid_without_qualification(&self, target: &UpdateTargetV2) -> bool {
        self.valid_base(target, true)
    }
    pub(super) fn tuple_digest(&self) -> Option<[u8; 32]> {
        decode_digest(&self.tuple_sha256)
    }
    pub(super) const fn digests(&self) -> &NativeEnrollmentTupleV3Digests {
        &self.digests
    }
    pub const fn deployment(&self) -> &NativeEnrollmentTupleV3Deployment {
        &self.deployment
    }
    pub(super) const fn code_identities(&self) -> &NativeEnrollmentTupleV3CodeIdentities {
        &self.code_identities
    }

    fn valid_base(&self, target: &UpdateTargetV2, require_digest: bool) -> bool {
        let digests = self.digest_values();
        self.schema_version == 3
            && target.platform == "macos"
            && matches!(target.arch.as_str(), "arm64" | "aarch64")
            && digests.iter().all(|value| digest_valid(value))
            && digests.iter().enumerate().all(|(index, value)| {
                !digests[..index].contains(value) && *value != target.artifact_sha256
            })
            && self.digests.candidate_sha256 == target.release_candidate_sha256
            && self.digests.contract_sha256 == target.bundle_sha256
            && self.deployment.valid()
            && self.code_identities.valid()
            && ((!require_digest && self.tuple_sha256.is_empty())
                || (digest_valid(&self.tuple_sha256)
                    && self.tuple_sha256 == self.digest_for(target)))
    }

    fn digest_values(&self) -> [&str; 10] {
        [
            &self.digests.candidate_sha256,
            &self.digests.desktop_sha256,
            &self.digests.writer_sha256,
            &self.digests.daemon_sha256,
            &self.digests.credential_service_sha256,
            &self.digests.launch_agent_plist_sha256,
            &self.digests.entitlements_sha256,
            &self.digests.provisioning_sha256,
            &self.digests.xpc_protocol_sha256,
            &self.digests.contract_sha256,
        ]
    }

    fn digest_for(&self, target: &UpdateTargetV2) -> String {
        let mut hasher = Sha256::new();
        hasher.update(TUPLE_DOMAIN);
        hasher.update(self.schema_version.to_be_bytes());
        for value in [
            target.product_id.as_str(),
            target.version.as_str(),
            target.platform.as_str(),
            target.arch.as_str(),
            target.profile_id.as_str(),
            target.artifact_sha256.as_str(),
        ]
        .into_iter()
        .chain(self.digest_values())
        .chain(self.deployment.digest_fields())
        {
            hash_string(&mut hasher, value);
        }
        hash_string(&mut hasher, "compatibility-bundles");
        hasher.update(
            (self
                .deployment
                .xpc_protocol_versions
                .compatibility_bundles()
                .count() as u32)
                .to_be_bytes(),
        );
        for bundle in self
            .deployment
            .xpc_protocol_versions
            .compatibility_bundles()
        {
            for version in bundle.values() {
                hasher.update(version.to_be_bytes());
            }
        }
        for identity in self.code_identities.values() {
            for value in identity.digest_fields() {
                hash_string(&mut hasher, value);
            }
        }
        hex::encode(hasher.finalize())
    }
}

fn hash_string(hasher: &mut Sha256, value: &str) {
    hasher.update(u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
    hasher.update(value.as_bytes());
}
