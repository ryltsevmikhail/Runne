use subtle::ConstantTimeEq;

use super::super::{
    MacOsCodeIdentityExpectationV1, NativeEnrollmentTupleV3, NativeEnrollmentTupleV3CodeIdentities,
    NativeEnrollmentTupleV3Deployment, NativeEnrollmentTupleV3Digests,
    NativeEnrollmentTupleV3ProtocolCompatibility,
};
use super::SignedInstalledReleaseVerificationErrorV2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSignedNativeEnrollmentTupleV3 {
    tuple_digest: [u8; 32],
    digests: [[u8; 32]; 10],
    deployment: NativeEnrollmentTupleV3Deployment,
    code_identities: NativeEnrollmentTupleV3CodeIdentities,
}

impl VerifiedSignedNativeEnrollmentTupleV3 {
    pub const fn tuple_digest(&self) -> [u8; 32] {
        self.tuple_digest
    }
    pub const fn service_application_id_group(&self) -> &str {
        self.deployment.service_application_id_group()
    }
    pub fn protocol_compatibility_bundles(
        &self,
    ) -> impl Iterator<Item = NativeEnrollmentTupleV3ProtocolCompatibility> + '_ {
        self.deployment.protocol_versions().compatibility_bundles()
    }
    pub fn credential_service_identity(&self) -> &MacOsCodeIdentityExpectationV1 {
        self.code_identities.values()[3]
    }
    pub fn matches_release_digests(&self, candidate: &NativeEnrollmentTupleV3Digests) -> bool {
        let Some(candidate) = decode_digests(candidate) else {
            return false;
        };
        self.digests
            .iter()
            .zip(candidate.iter())
            .all(|(expected, actual)| bool::from(expected.ct_eq(actual)))
    }
    pub fn matches_credential_service_identity(
        &self,
        identifier: &str,
        team_identifier: &str,
        cdhash: &str,
    ) -> bool {
        self.matches_identity(3, identifier, team_identifier, cdhash)
    }
    pub fn matches_desktop_identity(
        &self,
        identifier: &str,
        team_identifier: &str,
        cdhash: &str,
    ) -> bool {
        self.matches_identity(0, identifier, team_identifier, cdhash)
    }
    pub fn matches_writer_identity(
        &self,
        identifier: &str,
        team_identifier: &str,
        cdhash: &str,
    ) -> bool {
        self.matches_identity(1, identifier, team_identifier, cdhash)
    }
    pub fn matches_daemon_identity(
        &self,
        identifier: &str,
        team_identifier: &str,
        cdhash: &str,
    ) -> bool {
        self.matches_identity(2, identifier, team_identifier, cdhash)
    }
    fn matches_identity(
        &self,
        role: usize,
        identifier: &str,
        team_identifier: &str,
        cdhash: &str,
    ) -> bool {
        matches_identity(
            self.code_identities.values()[role],
            identifier,
            team_identifier,
            cdhash,
        )
    }
}

pub(super) fn verified_tuple_v3(
    tuple: &NativeEnrollmentTupleV3,
) -> Result<VerifiedSignedNativeEnrollmentTupleV3, SignedInstalledReleaseVerificationErrorV2> {
    Ok(VerifiedSignedNativeEnrollmentTupleV3 {
        tuple_digest: tuple
            .tuple_digest()
            .ok_or(SignedInstalledReleaseVerificationErrorV2::InvalidMetadata)?,
        digests: decode_digests(tuple.digests())
            .ok_or(SignedInstalledReleaseVerificationErrorV2::InvalidMetadata)?,
        deployment: tuple.deployment().clone(),
        code_identities: tuple.code_identities().clone(),
    })
}

fn decode_digests(value: &NativeEnrollmentTupleV3Digests) -> Option<[[u8; 32]; 10]> {
    Some([
        decode(&value.candidate_sha256)?,
        decode(&value.desktop_sha256)?,
        decode(&value.writer_sha256)?,
        decode(&value.daemon_sha256)?,
        decode(&value.credential_service_sha256)?,
        decode(&value.launch_agent_plist_sha256)?,
        decode(&value.entitlements_sha256)?,
        decode(&value.provisioning_sha256)?,
        decode(&value.xpc_protocol_sha256)?,
        decode(&value.contract_sha256)?,
    ])
}

fn decode(value: &str) -> Option<[u8; 32]> {
    hex::decode(value).ok()?.try_into().ok()
}

fn matches_identity(
    expected: &MacOsCodeIdentityExpectationV1,
    identifier: &str,
    team_identifier: &str,
    cdhash: &str,
) -> bool {
    expected.identifier() == identifier
        && expected.team_identifier() == team_identifier
        && expected.cdhash() == cdhash
}
