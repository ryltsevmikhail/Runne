//! Desktop implementations of native capability ports.
#![cfg_attr(
    not(feature = "test-support"),
    doc = r#"
Test-only enrollment fixtures are absent from the production feature graph:
```compile_fail
use runne_platform_desktop::test_only_ready_v3_enrollment_supervisor;
```
"#
)]

#[cfg(all(feature = "dev-loopback-updater", not(debug_assertions)))]
compile_error!("dev-loopback-updater cannot be compiled without debug assertions");

mod protected_runtime;
/// Platform-validated writer-process handoff for protected credential enrollment.
pub mod provider_credential_broker;
mod provider_credential_prompt;
mod root_handle_broker;
mod updater;
#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    feature = "protected-channel-integration",
    feature = "test-support"
))]
pub use protected_runtime::test_only_crossed_broker_offer;
#[cfg(all(feature = "test-support", target_os = "macos", target_arch = "aarch64"))]
pub use protected_runtime::{
    test_only_crossed_discovery, test_only_crossed_renewal, test_only_crossed_round,
    test_only_crossed_shutdown, test_only_pair_terminal,
};
mod updater_artifact;
#[cfg(all(target_os = "macos", feature = "test-support"))]
pub use protected_runtime::test_only_failed_writer_handoff;
mod updater_coordinator;
mod updater_feed;
mod updater_install;
mod updater_installed_metadata;
mod updater_journal;
mod updater_metadata;
mod updater_trust;

#[cfg(feature = "test-support")]
pub use protected_runtime::FirstActivationFaultPoint;
#[cfg(target_os = "macos")]
pub use protected_runtime::{
    CredentialWriterHandoff, CredentialWriterHandoffError, CredentialWriterHandoffMode,
    NativeProtectedCredentialEnrollmentBegin, PreparedCredentialServiceRejoin,
    PreparedCredentialServiceSessionRegistration, PreparedProtectedCredentialEnrollment,
    PreparedProtectedCredentialRecovery, RegisteredCredentialServiceSession,
};
pub use protected_runtime::{
    DevelopmentBundledRuntimeLauncher, ProtectedBundledRuntimeError,
    ProtectedBundledRuntimeLaunchSpec, ProtectedBundledRuntimeProcess,
    ProtectedBundledRuntimeSupervisor, discover_bundled_runtime,
};
#[cfg(all(feature = "test-support", unix))]
#[doc(hidden)]
pub use protected_runtime::{
    TestOnlyConnectedReadyV3EnrollmentSupervisor, TestOnlyReadyV3EnrollmentSupervisor,
    test_only_absent_enrollment_supervisor, test_only_connected_ready_v3_enrollment_supervisor,
    test_only_ready_v3_enrollment_supervisor,
};
#[cfg(target_os = "linux")]
pub use provider_credential_prompt::LinuxPinentryPrompt;
#[cfg(all(any(unix, windows), feature = "protected-channel-integration"))]
pub use root_handle_broker::ProtectedRootHandleEndpoint;
#[cfg(feature = "test-support")]
pub use root_handle_broker::test_transfer_pair;
pub use root_handle_broker::{
    NativeProcessFiles, RootHandleBrokerError, RootHandleTransferBinding,
    RootHandleTransferReceiver, RootHandleTransferSender, VerifiedRootHandle,
};
pub use root_handle_broker::{RootFileEntry, RootFileKind};
#[cfg(all(unix, feature = "test-support"))]
pub use root_handle_broker::{test_transfer_receiver, test_transfer_sender};
pub use runne_api::CompiledUpdateTrustRootV2;
pub use runne_api::WorkspaceId;
pub use runne_api::{PROTECTED_BUNDLED_SESSION_RENEW_AFTER, ProtectedRootHandleAdmission};
#[cfg(target_os = "macos")]
pub use runne_macos_process_identity::{MacOsContinuousClock, MacOsContinuousClockError};
pub use runne_platform_ports::provider_credential_broker::{
    VerifiedWriterArtifact, VerifiedWriterArtifactError, VerifiedWriterArtifactPort,
};
pub use runne_platform_ports::provider_credential_prompt::{
    CredentialPipeBytes, CredentialPromptAction, CredentialPromptProvider, MAX_CREDENTIAL_BYTES,
    SecureCredentialMaterial, SecureCredentialPromptDisposition, SecureCredentialPromptError,
    SecureCredentialPromptPort, SecureCredentialPromptRequest,
};
pub use updater::{
    StagedUpdate, UpdateInstallError, UpdateInstallPlan, UpdateInstallState, UpdateMetadataV1,
    UpdatePayloadV1, UpdateTarget, UpdateVerificationError, VerifiedUpdate,
    stage_verified_artifact, verify_update,
};
pub use updater_artifact::{UpdateArtifactKind, UpdateArtifactKindError};
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub use updater_coordinator::{
    TestOnlyEnrollmentRevalidation, TestOnlyEnrollmentUpdaterFixture,
    test_only_current_enrollment_updater_fixture, test_only_expired_enrollment_updater_fixture,
};
pub use updater_coordinator::{
    UpdateCoordinator, UpdateCoordinatorError, UpdateTargetBindingConfig,
};
pub use updater_feed::{UpdateFeedClient, UpdateFeedError};
pub use updater_install::{NativeUpdateInstallError, install_staged_update};
pub use updater_installed_metadata::InstalledUpdateMetadataError;
pub use updater_journal::{UpdateInstallRecord, UpdateJournal, UpdateJournalError};
#[cfg(all(feature = "test-support", target_os = "macos", target_arch = "aarch64"))]
#[doc(hidden)]
pub use updater_metadata::prepare_local_native_enrollment;
#[cfg(target_os = "macos")]
pub use updater_metadata::produce_staged_native_enrollment_tuple_v3;
#[cfg(all(feature = "dev-loopback-updater", debug_assertions))]
pub use updater_metadata::verify_update_v2_dev_loopback;
pub use updater_metadata::{
    ConfirmedInstalledNativeEnrollment, EnrollmentTransitionFacts, MacOsCodeIdentityExpectationV1,
    MeasuredNativeEnrollmentArtifactsV1, NativeEnrollmentQualification,
    NativeEnrollmentQualificationBinding, NativeEnrollmentQualificationRowV1,
    NativeEnrollmentTupleAdmission, NativeEnrollmentTupleError, NativeEnrollmentTupleV2,
    NativeEnrollmentTupleV3, NativeEnrollmentTupleV3CodeIdentities,
    NativeEnrollmentTupleV3Deployment, NativeEnrollmentTupleV3Digests,
    NativeEnrollmentTupleV3EffectState, NativeEnrollmentTupleV3ProtocolCompatibility,
    NativeEnrollmentTupleV3ProtocolVersions, NativeEnrollmentTupleV3UpdateDisposition,
    NativeEnrollmentTupleV3UpdateError, PreparedInstalledNativeEnrollment,
    QualificationAdmissionError, UpdateMetadataSigningError, UpdateMetadataV2, UpdateRootRoleV2,
    UpdateSignatureV2, UpdateSnapshotRoleV2, UpdateTargetV2, UpdateTargetV2Binding,
    UpdateTargetsRoleV2, UpdateTimestampRoleV2, UpdateTrustRootV2, UpdateV2VerificationError,
    VerifiedDaemonNativeEnrollmentPrepare, VerifiedInstalledEnrollmentMeasurementFacts,
    VerifiedMacOsWriterLaunch, VerifiedQualificationAdmission,
    VerifiedSignedNativeEnrollmentTupleV3, VerifiedUpdateV2,
    evaluate_native_enrollment_tuple_v3_update, update_metadata_signing_bytes, verify_update_v2,
};
pub use updater_trust::{UpdateTrustError, UpdateTrustJournal, UpdateTrustState};

use std::collections::VecDeque;
use std::fmt;
use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use thiserror::Error;

const MINIMUM_WINDOW_WIDTH: i32 = 960;
const MINIMUM_WINDOW_HEIGHT: i32 = 600;
const DEFAULT_WINDOW_WIDTH: i32 = 1_440;
const DEFAULT_WINDOW_HEIGHT: i32 = 900;
const BACKOFF_DELAYS: [Duration; 5] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(10),
    Duration::from_secs(30),
];
const UNEXPECTED_EXIT_WINDOW: Duration = Duration::from_mins(10);

include!("desktop_types.rs");
include!("desktop_supervisor.rs");
include!("desktop_support.rs");

#[cfg(test)]
mod tests {
    include!("tests/support.rs");
    include!("tests/capability_tuple.rs");
    include!("tests/supervisor.rs");
    include!("tests/recovery.rs");
    include!("tests/backoff_and_geometry.rs");
    include!("tests/updater_artifact.rs");
    include!("tests/updater.rs");
    #[cfg(unix)]
    mod root_files {
        include!("tests/root_files.rs");
    }
}
