use sha2::{Digest, Sha256};

use super::model::{UpdateMetadataV2, UpdateTargetV2, update_metadata_signing_bytes};
use super::tuple::NativeEnrollmentTupleV2;
use super::tuple_identity::MacOsCodeIdentityExpectationV1;
use super::verification::SignedInstalledReleaseVerificationErrorV2;

#[path = "binding/candidate_binding.rs"]
mod candidate_binding;
#[path = "binding/exact.rs"]
mod exact;
mod matchers;
#[path = "binding/v3.rs"]
mod v3;
pub(super) use exact::{exact, exact_with_matcher};
pub use v3::{SignedInstalledReleaseCandidateV3, VerifiedSignedNativeEnrollmentTupleV3};

const MANIFEST_DOMAIN: &[u8] = b"GOCODE_SIGNED_INSTALLED_RELEASE_MANIFEST_V1\0";
const RELEASE_DOMAIN: &[u8] = b"GOCODE_SIGNED_INSTALLED_RELEASE_BINDING_V1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSignedNativeEnrollmentTupleV2 {
    candidate_digest: [u8; 32],
    inner_tuple_digest: [u8; 32],
    desktop_image_digest: [u8; 32],
    writer_image_digest: [u8; 32],
    daemon_image_digest: [u8; 32],
    contract_digest: [u8; 32],
    desktop_code_identity: Option<MacOsCodeIdentityExpectationV1>,
    writer_code_identity: Option<MacOsCodeIdentityExpectationV1>,
    daemon_code_identity: Option<MacOsCodeIdentityExpectationV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedInstalledReleaseCandidateV2 {
    native_enrollment_tuple: VerifiedSignedNativeEnrollmentTupleV2,
    target_manifest_digest: [u8; 32],
    release_binding_digest: [u8; 32],
    qualification_receipt_digest: [u8; 32],
    qualification_binding_digest: [u8; 32],
    qualified_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSignedUpdateMetadataV2 {
    metadata: UpdateMetadataV2,
    verified_at_unix_seconds: u64,
    native_enrollment_tuple: Option<VerifiedSignedNativeEnrollmentTupleV2>,
    native_enrollment_tuple_v3: Option<VerifiedSignedNativeEnrollmentTupleV3>,
    qualified_release_candidate: Option<SignedInstalledReleaseCandidateV2>,
    qualified_release_candidate_v3: Option<SignedInstalledReleaseCandidateV3>,
}

#[derive(Eq, PartialEq)]
pub struct VerifiedSignedInstalledReleaseV2 {
    signed_candidate: Option<SignedInstalledReleaseCandidateV2>,
    signed_candidate_v3: Option<SignedInstalledReleaseCandidateV3>,
    candidate_binding_v3: Option<candidate_binding::VerifiedCandidateBindingV3>,
}

impl core::fmt::Debug for VerifiedSignedInstalledReleaseV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VerifiedSignedInstalledReleaseV2(<opaque>)")
    }
}

impl VerifiedSignedUpdateMetadataV2 {
    pub const fn metadata(&self) -> &UpdateMetadataV2 {
        &self.metadata
    }
    pub const fn target(&self) -> &UpdateTargetV2 {
        &self.metadata.targets.target
    }
    pub const fn verified_at_unix_seconds(&self) -> u64 {
        self.verified_at_unix_seconds
    }
    pub const fn native_enrollment_tuple(&self) -> Option<&VerifiedSignedNativeEnrollmentTupleV2> {
        self.native_enrollment_tuple.as_ref()
    }
    pub const fn native_enrollment_tuple_v3(
        &self,
    ) -> Option<&VerifiedSignedNativeEnrollmentTupleV3> {
        self.native_enrollment_tuple_v3.as_ref()
    }
    pub const fn qualified_release_candidate(&self) -> Option<&SignedInstalledReleaseCandidateV2> {
        self.qualified_release_candidate.as_ref()
    }
    pub const fn qualified_release_candidate_v3(
        &self,
    ) -> Option<&SignedInstalledReleaseCandidateV3> {
        self.qualified_release_candidate_v3.as_ref()
    }
}

impl VerifiedSignedInstalledReleaseV2 {
    /// Returns the exact qualified V3 tuple retained for native writer admission.
    #[doc(hidden)]
    pub const fn native_enrollment_tuple_v3(
        &self,
    ) -> Option<&VerifiedSignedNativeEnrollmentTupleV3> {
        match self.signed_candidate_v3.as_ref() {
            Some(candidate) => Some(candidate.native_enrollment_tuple()),
            None => None,
        }
    }
}

impl VerifiedSignedNativeEnrollmentTupleV2 {
    pub const fn candidate_digest(&self) -> [u8; 32] {
        self.candidate_digest
    }
    pub const fn inner_tuple_digest(&self) -> [u8; 32] {
        self.inner_tuple_digest
    }
    pub const fn desktop_image_digest(&self) -> [u8; 32] {
        self.desktop_image_digest
    }
    pub const fn writer_image_digest(&self) -> [u8; 32] {
        self.writer_image_digest
    }
    pub const fn daemon_image_digest(&self) -> [u8; 32] {
        self.daemon_image_digest
    }
    pub const fn contract_digest(&self) -> [u8; 32] {
        self.contract_digest
    }
    pub const fn desktop_code_identity(&self) -> Option<&MacOsCodeIdentityExpectationV1> {
        self.desktop_code_identity.as_ref()
    }
    pub const fn writer_code_identity(&self) -> Option<&MacOsCodeIdentityExpectationV1> {
        self.writer_code_identity.as_ref()
    }
    pub const fn daemon_code_identity(&self) -> Option<&MacOsCodeIdentityExpectationV1> {
        self.daemon_code_identity.as_ref()
    }
}

impl SignedInstalledReleaseCandidateV2 {
    pub const fn native_enrollment_tuple(&self) -> &VerifiedSignedNativeEnrollmentTupleV2 {
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

pub(super) fn build_verified(
    metadata: &UpdateMetadataV2,
    now: u64,
) -> Result<VerifiedSignedUpdateMetadataV2, SignedInstalledReleaseVerificationErrorV2> {
    let tuple = metadata.targets.target.native_enrollment_tuple.as_ref();
    let verified_tuple = tuple.map(verified_tuple).transpose()?;
    let verified_tuple_v3 = metadata
        .targets
        .target
        .native_enrollment_tuple_v3
        .as_ref()
        .map(v3::verified_tuple_v3)
        .transpose()?;
    let qualified_release_candidate = match (tuple, verified_tuple.as_ref()) {
        (Some(raw), Some(verified)) => candidate(metadata, raw, verified, now)?,
        _ => None,
    };
    let qualified_release_candidate_v3 = match (
        metadata.targets.target.native_enrollment_tuple_v3.as_ref(),
        verified_tuple_v3.as_ref(),
    ) {
        (Some(raw), Some(verified)) => v3::candidate_v3(metadata, raw, verified, now)?,
        _ => None,
    };
    Ok(VerifiedSignedUpdateMetadataV2 {
        metadata: metadata.clone(),
        verified_at_unix_seconds: now,
        native_enrollment_tuple: verified_tuple,
        native_enrollment_tuple_v3: verified_tuple_v3,
        qualified_release_candidate,
        qualified_release_candidate_v3,
    })
}

fn verified_tuple(
    tuple: &NativeEnrollmentTupleV2,
) -> Result<VerifiedSignedNativeEnrollmentTupleV2, SignedInstalledReleaseVerificationErrorV2> {
    let [
        desktop_code_identity,
        writer_code_identity,
        daemon_code_identity,
    ] = tuple.identities();
    Ok(VerifiedSignedNativeEnrollmentTupleV2 {
        candidate_digest: tuple
            .candidate_digest()
            .ok_or(SignedInstalledReleaseVerificationErrorV2::InvalidMetadata)?,
        inner_tuple_digest: tuple
            .tuple_digest()
            .ok_or(SignedInstalledReleaseVerificationErrorV2::InvalidMetadata)?,
        desktop_image_digest: tuple
            .desktop_digest()
            .ok_or(SignedInstalledReleaseVerificationErrorV2::InvalidMetadata)?,
        writer_image_digest: tuple
            .writer_digest()
            .ok_or(SignedInstalledReleaseVerificationErrorV2::InvalidMetadata)?,
        daemon_image_digest: tuple
            .daemon_digest()
            .ok_or(SignedInstalledReleaseVerificationErrorV2::InvalidMetadata)?,
        contract_digest: tuple
            .contract_digest()
            .ok_or(SignedInstalledReleaseVerificationErrorV2::InvalidMetadata)?,
        desktop_code_identity: desktop_code_identity.cloned(),
        writer_code_identity: writer_code_identity.cloned(),
        daemon_code_identity: daemon_code_identity.cloned(),
    })
}

fn candidate(
    metadata: &UpdateMetadataV2,
    raw: &NativeEnrollmentTupleV2,
    tuple: &VerifiedSignedNativeEnrollmentTupleV2,
    now: u64,
) -> Result<Option<SignedInstalledReleaseCandidateV2>, SignedInstalledReleaseVerificationErrorV2> {
    let Some(row) = raw.qualification() else {
        return Ok(None);
    };
    if row.qualified_at() > now || now >= row.expires_at() {
        return Ok(None);
    }
    let qualification_binding_digest = row
        .binding_digest()
        .ok_or(SignedInstalledReleaseVerificationErrorV2::InvalidMetadata)?;
    let target_manifest_digest = manifest_digest(metadata)?;
    let release_binding_digest = release_digest(
        target_manifest_digest,
        tuple.inner_tuple_digest,
        qualification_binding_digest,
    );
    Ok(Some(SignedInstalledReleaseCandidateV2 {
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

pub(super) fn manifest_digest(
    metadata: &UpdateMetadataV2,
) -> Result<[u8; 32], SignedInstalledReleaseVerificationErrorV2> {
    let bytes = update_metadata_signing_bytes(&metadata.targets)
        .map_err(|_| SignedInstalledReleaseVerificationErrorV2::InvalidMetadata)?;
    let mut hasher = Sha256::new();
    hasher.update(MANIFEST_DOMAIN);
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}

pub(super) fn release_digest(
    manifest: [u8; 32],
    tuple: [u8; 32],
    qualification: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RELEASE_DOMAIN);
    hasher.update(manifest);
    hasher.update(tuple);
    hasher.update(qualification);
    hasher.finalize().into()
}
