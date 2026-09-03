use subtle::ConstantTimeEq;

use super::super::{
    MacOsCodeIdentityExpectationV1, NativeEnrollmentTupleV3, NativeEnrollmentTupleV3CodeIdentities,
    NativeEnrollmentTupleV3Deployment, NativeEnrollmentTupleV3Digests,
    NativeEnrollmentTupleV3ProtocolCompatibility, UpdateMetadataV2,
};
use super::SignedInstalledReleaseVerificationErrorV2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedInstalledReleaseCandidateV3 {
    native_enrollment_tuple: VerifiedSignedNativeEnrollmentTupleV3,
    target_manifest_digest: [u8; 32],
    release_binding_digest: [u8; 32],
    qualification_receipt_digest: [u8; 32],
    qualification_binding_digest: [u8; 32],
    qualified_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

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
    pub fn desktop_identity(&self) -> &MacOsCodeIdentityExpectationV1 {
        self.code_identities.values()[0]
    }
    pub fn writer_identity(&self) -> &MacOsCodeIdentityExpectationV1 {
        self.code_identities.values()[1]
    }
    pub fn daemon_identity(&self) -> &MacOsCodeIdentityExpectationV1 {
        self.code_identities.values()[2]
    }
    pub const fn desktop_digest(&self) -> [u8; 32] {
        self.digests[1]
    }
    pub const fn writer_digest(&self) -> [u8; 32] {
        self.digests[2]
    }
    pub const fn daemon_digest(&self) -> [u8; 32] {
        self.digests[3]
    }
    pub const fn credential_service_digest(&self) -> [u8; 32] {
        self.digests[4]
    }
    pub const fn candidate_digest(&self) -> [u8; 32] {
        self.digests[0]
    }
    pub fn matches_measured_tuple(&self, measured: &NativeEnrollmentTupleV3) -> bool {
        measured.qualification().is_none()
            && measured
                .tuple_digest()
                .is_some_and(|digest| bool::from(self.tuple_digest.ct_eq(&digest)))
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

impl SignedInstalledReleaseCandidateV3 {
    pub const fn native_enrollment_tuple(&self) -> &VerifiedSignedNativeEnrollmentTupleV3 {
        &self.native_enrollment_tuple
    }
    pub const fn target_manifest_digest(&self) -> [u8; 32] {
        self.target_manifest_digest
    }
    pub const fn release_binding_digest(&self) -> [u8; 32] {
        self.release_binding_digest
    }
    pub const fn qualification_receipt_digest(&self) -> [u8; 32] {
        self.qualification_receipt_digest
    }
    pub const fn qualification_binding_digest(&self) -> [u8; 32] {
        self.qualification_binding_digest
    }
    pub const fn qualified_at_unix_seconds(&self) -> u64 {
        self.qualified_at_unix_seconds
    }
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
}

pub(super) fn candidate_v3(
    metadata: &UpdateMetadataV2,
    raw: &NativeEnrollmentTupleV3,
    tuple: &VerifiedSignedNativeEnrollmentTupleV3,
    now: u64,
) -> Result<Option<SignedInstalledReleaseCandidateV3>, SignedInstalledReleaseVerificationErrorV2> {
    let Some(row) = raw.qualification() else {
        return Ok(None);
    };
    if row.qualified_at() > now || now >= row.expires_at() {
        return Ok(None);
    }
    let qualification_binding_digest = row
        .binding_digest()
        .ok_or(SignedInstalledReleaseVerificationErrorV2::InvalidMetadata)?;
    let target_manifest_digest = super::manifest_digest(metadata)?;
    let release_binding_digest = super::release_digest(
        target_manifest_digest,
        tuple.tuple_digest,
        qualification_binding_digest,
    );
    Ok(Some(SignedInstalledReleaseCandidateV3 {
        native_enrollment_tuple: tuple.clone(),
        target_manifest_digest,
        release_binding_digest,
        qualification_receipt_digest: row
            .receipt_digest()
            .ok_or(SignedInstalledReleaseVerificationErrorV2::InvalidMetadata)?,
        qualification_binding_digest,
        qualified_at_unix_seconds: row.qualified_at(),
        expires_at_unix_seconds: row.expires_at(),
    }))
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
