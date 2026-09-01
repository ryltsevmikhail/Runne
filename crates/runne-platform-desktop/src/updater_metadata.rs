//! Desktop policy adapter for threshold-signed release metadata.

#![allow(clippy::missing_errors_doc)]

use thiserror::Error;

const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;

pub use runne_api::{
    MacOsCodeIdentityExpectationV1, NativeEnrollmentQualificationRowV1, NativeEnrollmentTupleError,
    NativeEnrollmentTupleV2, UpdateMetadataSigningError, UpdateMetadataV2, UpdateRootRoleV2,
    UpdateSignatureV2, UpdateSnapshotRoleV2, UpdateTargetV2, UpdateTargetsRoleV2,
    UpdateTimestampRoleV2, UpdateTrustRootV2, VerifiedSignedNativeEnrollmentTupleV2,
    update_metadata_signing_bytes,
};

#[path = "updater_metadata/enrollment_tuple/macos_identity.rs"]
mod macos_identity;
pub use macos_identity::VerifiedMacOsWriterLaunch;
#[path = "updater_metadata/enrollment_tuple/qualification.rs"]
mod enrollment_qualification;
pub use enrollment_desktop_peer_claim::EnrollmentTransitionFacts;
pub use enrollment_qualification::{
    NativeEnrollmentQualification, NativeEnrollmentQualificationBinding,
};
#[path = "updater_metadata/enrollment_tuple/admission.rs"]
mod enrollment_admission;
pub use enrollment_admission::NativeEnrollmentTupleAdmission;

include!("updater_metadata/enrollment_tuple.rs");

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateTargetV2Binding<'a> {
    pub product_id: &'a str,
    pub platform: &'a str,
    pub arch: &'a str,
    pub min_os: &'a str,
    pub profile_id: &'a str,
    pub bundle_sha256: &'a str,
    pub runtime_version: &'a str,
    pub runtime_digest: &'a str,
    pub channel: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedUpdateV2 {
    signed: runne_api::VerifiedSignedUpdateMetadataV2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum UpdateV2VerificationError {
    #[error("update metadata is invalid")]
    InvalidMetadata,
    #[error("root signature quorum is insufficient")]
    RootQuorum,
    #[error("targets signature quorum is insufficient")]
    TargetsQuorum,
    #[error("timestamp signature is invalid")]
    TimestampSignature,
    #[error("snapshot signature is invalid")]
    SnapshotSignature,
    #[error("update target does not match this desktop")]
    TargetMismatch,
    #[error("update metadata is expired")]
    Expired,
    #[error("update is below the rollback floor")]
    Rollback,
}

#[path = "updater_metadata/verify_v2.rs"]
mod verify_v2;
pub use verify_v2::verify_update_v2;
#[cfg(all(feature = "dev-loopback-updater", debug_assertions))]
pub use verify_v2::verify_update_v2_dev_loopback;

fn target_matches(target: &UpdateTargetV2, binding: &UpdateTargetV2Binding<'_>) -> bool {
    target.product_id == binding.product_id
        && target.platform == binding.platform
        && target.arch == binding.arch
        && target.min_os == binding.min_os
        && target.profile_id == binding.profile_id
        && target.bundle_sha256 == binding.bundle_sha256
        && target.runtime_version == binding.runtime_version
        && target.runtime_digest == binding.runtime_digest
        && target.channel == binding.channel
}
