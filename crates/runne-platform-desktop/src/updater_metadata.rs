//! Desktop policy adapter for threshold-signed release metadata.

#![allow(clippy::missing_errors_doc)]

use thiserror::Error;

const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;

pub use runne_api::{
    MacOsCodeIdentityExpectationV1, NativeEnrollmentQualificationRowV1, NativeEnrollmentTupleError,
    NativeEnrollmentTupleV2, NativeEnrollmentTupleV3, NativeEnrollmentTupleV3CodeIdentities,
    NativeEnrollmentTupleV3Deployment, NativeEnrollmentTupleV3Digests,
    NativeEnrollmentTupleV3ProtocolCompatibility, NativeEnrollmentTupleV3ProtocolVersions,
    UpdateMetadataSigningError, UpdateMetadataV2, UpdateRootRoleV2, UpdateSignatureV2,
    UpdateSnapshotRoleV2, UpdateTargetV2, UpdateTargetsRoleV2, UpdateTimestampRoleV2,
    UpdateTrustRootV2, VerifiedSignedNativeEnrollmentTupleV2,
    VerifiedSignedNativeEnrollmentTupleV3, update_metadata_signing_bytes,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeEnrollmentTupleV3EffectState {
    Reconciled,
    Armed,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeEnrollmentTupleV3UpdateDisposition {
    Ready,
    ReconciliationRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum NativeEnrollmentTupleV3UpdateError {
    #[error("credential-service application-ID group change is unsupported")]
    UnsupportedApplicationIdGroupChange,
    #[error("credential-service XPC protocol versions do not overlap")]
    UnsupportedProtocolTransition,
}

pub fn evaluate_native_enrollment_tuple_v3_update(
    current: &VerifiedSignedNativeEnrollmentTupleV3,
    next: &VerifiedSignedNativeEnrollmentTupleV3,
    effects: NativeEnrollmentTupleV3EffectState,
) -> Result<NativeEnrollmentTupleV3UpdateDisposition, NativeEnrollmentTupleV3UpdateError> {
    if current.service_application_id_group() != next.service_application_id_group() {
        return Err(NativeEnrollmentTupleV3UpdateError::UnsupportedApplicationIdGroupChange);
    }
    let compatible = current.protocol_compatibility_bundles().any(|bundle| {
        next.protocol_compatibility_bundles()
            .any(|next| next == bundle)
    });
    if !compatible {
        return Err(NativeEnrollmentTupleV3UpdateError::UnsupportedProtocolTransition);
    }
    Ok(match effects {
        NativeEnrollmentTupleV3EffectState::Reconciled => {
            NativeEnrollmentTupleV3UpdateDisposition::Ready
        }
        NativeEnrollmentTupleV3EffectState::Armed
        | NativeEnrollmentTupleV3EffectState::Uncertain => {
            NativeEnrollmentTupleV3UpdateDisposition::ReconciliationRequired
        }
    })
}

#[path = "updater_metadata/enrollment_tuple/macos_identity.rs"]
mod macos_identity;
pub use macos_identity::VerifiedMacOsWriterLaunch;
#[path = "updater_metadata/enrollment_tuple/qualification.rs"]
mod enrollment_qualification;
pub use enrollment_desktop_peer_claim::EnrollmentTransitionFacts;
pub use enrollment_qualification::{
    NativeEnrollmentQualification, NativeEnrollmentQualificationBinding,
};
#[path = "updater_metadata/enrollment_tuple/bootstrap_client_pins.rs"]
mod bootstrap_client_pins;
#[path = "updater_metadata/enrollment_tuple/admission.rs"]
mod enrollment_admission;
pub use bootstrap_client_pins::VerifiedQualificationBootstrapClientPins;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "updater_metadata/enrollment_tuple/bootstrap_desktop.rs"]
mod bootstrap_desktop;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use bootstrap_desktop::VerifiedInstalledQualificationBootstrapDesktop;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "updater_metadata/enrollment_tuple/bootstrap_gui_executor.rs"]
mod bootstrap_gui_executor;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use bootstrap_gui_executor::VerifiedInstalledQualificationGuiExecutor;
pub use enrollment_admission::NativeEnrollmentTupleAdmission;
#[cfg(any(target_os = "macos", all(test, unix)))]
#[path = "updater_metadata/enrollment_tuple/tuple_v3_producer.rs"]
mod enrollment_tuple_v3_producer;
#[cfg(target_os = "macos")]
pub use enrollment_tuple_v3_producer::produce_staged_native_enrollment_tuple_v3;

#[cfg(all(test, unix))]
#[path = "updater_metadata/enrollment_tuple/tuple_v3_producer_tests.rs"]
mod enrollment_tuple_v3_producer_tests;

#[cfg(all(feature = "test-support", target_os = "macos", target_arch = "aarch64"))]
#[path = "updater_metadata/local_enrollment_fixture.rs"]
mod local_enrollment_fixture;
#[cfg(all(feature = "test-support", target_os = "macos", target_arch = "aarch64"))]
pub use local_enrollment_fixture::prepare_local_native_enrollment;

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
