//! Desktop implementations of native capability ports.

mod protected_runtime;
/// Platform-validated writer-process handoff for protected credential enrollment.
pub mod provider_credential_broker;
mod provider_credential_prompt;
mod root_handle_broker;
mod updater;
mod updater_artifact;
mod updater_coordinator;
mod updater_feed;
mod updater_install;
mod updater_journal;
mod updater_metadata;
mod updater_trust;

#[cfg(feature = "test-support")]
pub use protected_runtime::FirstActivationFaultPoint;
pub use protected_runtime::{
    DevelopmentBundledRuntimeLauncher, ProtectedBundledRuntimeError,
    ProtectedBundledRuntimeLaunchSpec, ProtectedBundledRuntimeProcess,
    ProtectedBundledRuntimeSupervisor, discover_bundled_runtime,
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
pub use runne_api::WorkspaceId;
pub use runne_api::{PROTECTED_BUNDLED_SESSION_RENEW_AFTER, ProtectedRootHandleAdmission};
pub use runne_platform_ports::provider_credential_broker::{
    VerifiedWriterArtifact, VerifiedWriterArtifactError, VerifiedWriterArtifactPort,
};
pub use runne_platform_ports::provider_credential_prompt::{
    CredentialPipeBytes, CredentialPromptAction, CredentialPromptProvider,
    SecureCredentialMaterial, SecureCredentialPromptDisposition, SecureCredentialPromptError,
    SecureCredentialPromptPort, SecureCredentialPromptRequest,
};
pub use updater::{
    StagedUpdate, UpdateInstallError, UpdateInstallPlan, UpdateInstallState, UpdateMetadataV1,
    UpdatePayloadV1, UpdateTarget, UpdateVerificationError, VerifiedUpdate,
    stage_verified_artifact, verify_update,
};
pub use updater_artifact::{UpdateArtifactKind, UpdateArtifactKindError};
pub use updater_coordinator::{
    UpdateCoordinator, UpdateCoordinatorError, UpdateTargetBindingConfig,
};
pub use updater_feed::{UpdateFeedClient, UpdateFeedError};
pub use updater_install::{NativeUpdateInstallError, install_staged_update};
pub use updater_journal::{UpdateInstallRecord, UpdateJournal, UpdateJournalError};
pub use updater_metadata::{
    MeasuredNativeEnrollmentArtifactsV1, NativeEnrollmentQualification,
    NativeEnrollmentTupleAdmission, NativeEnrollmentTupleError, NativeEnrollmentTupleV1,
    UpdateMetadataV2, UpdateRootRoleV2, UpdateSignatureV2, UpdateSnapshotRoleV2, UpdateTargetV2,
    UpdateTargetV2Binding, UpdateTargetsRoleV2, UpdateTimestampRoleV2, UpdateTrustRootV2,
    UpdateV2VerificationError, VerifiedMacOsWriterLaunch, VerifiedUpdateV2, verify_update_v2,
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
