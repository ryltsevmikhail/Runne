// Development/ad-hoc protected bundled-runtime launch and supervision.
//
// This module deliberately makes no production signing or notarization claim.
// The Unix backend is usable for local macOS development/ad-hoc execution and
// for Linux contract testing. Unsupported native backends fail closed.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::UnixStream;

use gocode_api::{
    ActivationDispositionV1, ExecutableIdentityV1, LaunchAuthorityError, LaunchSecret,
    PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID, PendingFirstActivationV1, ProtectedActivationKeys,
    ProtectedFirstActivationCommitV1, ProtectedFirstActivationPreparedV1, ProtectedLaunchRequestV1,
    ProtectedLaunchRequestV2, ProtectedOwnedLaunchV1, ProtectedOwnedLaunchV2, ProtectedReadyV1,
    ProtectedReadyV2, ProtectedRenewRequestV1, ProtectedRenewRequestV2, ProtectedRenewTicketV1,
    ProtectedRenewTicketV2, ProtectedRuntimeProfileV1, ProtectedShutdownAckV1,
    ProtectedShutdownAckV2, ProtectedShutdownV1, ProtectedShutdownV2, ProviderActivationBindingV1,
    StableRuntimeBindingV1,
};
use gocode_runtime_client::{
    AuthenticatedRuntimeClient, GOLDEN_BUNDLE_HASH, ProtectedBundledRuntimeProfile,
    REQUIRED_RUNTIME_CAPABILITIES, RuntimeTransportKind,
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    BUNDLED_RUNTIME_GRACEFUL_STOP_TIMEOUT, BundledRuntimeBackoff, BundledRuntimeLifecycleState,
    BundledRuntimeProcessStatus, BundledRuntimeRestartDisposition, BundledRuntimeStopDisposition,
};

const MAX_FRAME_PAYLOAD_BYTES: usize = 65_536;
const MAX_STATE_BYTES: u64 = 64 * 1024;
const LAUNCH_TIMEOUT: Duration = Duration::from_secs(30);
const LOCAL_PRINCIPAL: &str = "local-owner";
const STATE_SCHEMA_VERSION: u32 = 1;
const ACTIVATION_STATE_DIRECTORY: &str = ".desktop-protected-activation";
const STAGED_EXECUTABLE_DIRECTORY: &str = "executables-v1";
const STABLE_RECORD_FILE: &str = "stable-binding-v1.json";
const PENDING_RECORD_FILE: &str = "pending-first-activation-v1.json";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActivationCheckpoint {
    BeforePreparePersistence,
    AfterPrepareFileSync,
    AfterPreparePersistence,
    BeforeCommit,
    AfterCommit,
    AfterEventLogCreation,
    BeforeFinalPin,
    AfterFinalPinFileSync,
    AfterFinalPin,
}

/// Test-only crash/durable-write boundary for first-activation recovery.
#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirstActivationFaultPoint {
    BeforePreparePersistence,
    AfterPrepareFileSync,
    AfterPreparePersistence,
    BeforeCommit,
    AfterCommit,
    AfterEventLogCreation,
    BeforeFinalPin,
    AfterFinalPinFileSync,
    AfterFinalPin,
}

#[cfg(feature = "test-support")]
impl From<FirstActivationFaultPoint> for ActivationCheckpoint {
    fn from(value: FirstActivationFaultPoint) -> Self {
        match value {
            FirstActivationFaultPoint::BeforePreparePersistence => Self::BeforePreparePersistence,
            FirstActivationFaultPoint::AfterPrepareFileSync => Self::AfterPrepareFileSync,
            FirstActivationFaultPoint::AfterPreparePersistence => Self::AfterPreparePersistence,
            FirstActivationFaultPoint::BeforeCommit => Self::BeforeCommit,
            FirstActivationFaultPoint::AfterCommit => Self::AfterCommit,
            FirstActivationFaultPoint::AfterEventLogCreation => Self::AfterEventLogCreation,
            FirstActivationFaultPoint::BeforeFinalPin => Self::BeforeFinalPin,
            FirstActivationFaultPoint::AfterFinalPinFileSync => Self::AfterFinalPinFileSync,
            FirstActivationFaultPoint::AfterFinalPin => Self::AfterFinalPin,
        }
    }
}

struct LaunchTestControls {
    secret_override: Option<Zeroizing<[u8; 32]>>,
    capture_output: bool,
    fail_at: Option<ActivationCheckpoint>,
    fault_triggered: bool,
}

impl LaunchTestControls {
    const fn production() -> Self {
        Self {
            secret_override: None,
            capture_output: false,
            fail_at: None,
            fault_triggered: false,
        }
    }

    fn checkpoint(
        &mut self,
        point: ActivationCheckpoint,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        if self.fail_at == Some(point) && !self.fault_triggered {
            self.fault_triggered = true;
            return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
        }
        Ok(())
    }
}

/// Closed, renderer-safe failure vocabulary for protected bundled activation.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ProtectedBundledRuntimeError {
    #[error("unsupported_platform_backend")]
    UnsupportedPlatformBackend,
    #[error("bundled_executable_unavailable")]
    ExecutableUnavailable,
    #[error("bundled_executable_identity_mismatch")]
    ExecutableIdentityMismatch,
    #[error("protected_runtime_root_unavailable")]
    RuntimeRootUnavailable,
    #[error("protected_activation_state_unavailable")]
    ActivationStateUnavailable,
    #[error("protected_channel_unavailable")]
    ProtectedChannelUnavailable,
    #[error("bundled_spawn_failed")]
    SpawnFailed,
    #[error("bundled_readiness_timeout")]
    ReadinessTimeout,
    #[error("bundled_runtime_not_owned")]
    OwnershipMismatch,
    #[error("bundled_runtime_invalid_state")]
    InvalidState,
    #[error("bundled_runtime_restart_exhausted")]
    RestartExhausted,
    #[error("bundled_runtime_shutdown_incomplete")]
    ShutdownIncomplete,
    #[error("{0}")]
    LaunchAuthority(#[from] LaunchAuthorityError),
}

/// Canonical executable and owner-private runtime root for one local profile.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedBundledRuntimeLaunchSpec {
    executable: PathBuf,
    runtime_root: PathBuf,
    trusted_source_identity: ExecutableIdentityV1,
    provider_activation: Option<ProviderActivationBindingV1>,
}

impl fmt::Debug for ProtectedBundledRuntimeLaunchSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedBundledRuntimeLaunchSpec")
            .field("executable", &"<measured>")
            .field("runtime_root", &"<owner-private>")
            .field("provider_activation", &self.provider_activation)
            .finish_non_exhaustive()
    }
}

impl ProtectedBundledRuntimeLaunchSpec {
    /// Validates one direct, absolute executable and owner-private runtime root.
    ///
    /// # Errors
    ///
    /// Returns a closed platform, executable, or runtime-root failure.
    pub fn new(
        executable: &Path,
        runtime_root: &Path,
    ) -> Result<Self, ProtectedBundledRuntimeError> {
        #[cfg(not(unix))]
        {
            let _ = (executable, runtime_root);
            return Err(ProtectedBundledRuntimeError::UnsupportedPlatformBackend);
        }
        #[cfg(unix)]
        {
            let executable = validate_executable_path(executable)?;
            let trusted_source_identity = ExecutableIdentityV1::measure(&executable)
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            let runtime_root = ensure_owner_private_directory(runtime_root)?;
            Ok(Self {
                executable,
                runtime_root,
                trusted_source_identity,
                provider_activation: None,
            })
        }
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    #[must_use]
    pub fn runtime_root(&self) -> &Path {
        &self.runtime_root
    }

    const fn trusted_source_identity(&self) -> &ExecutableIdentityV1 {
        &self.trusted_source_identity
    }

    /// Selects provider-bound protected protocol V2 for this in-memory launch.
    #[must_use]
    pub fn with_provider_activation(
        mut self,
        provider_activation: ProviderActivationBindingV1,
    ) -> Self {
        self.provider_activation = Some(provider_activation);
        self
    }

    /// Selects the released native `OpenAI` Responses text provider for V2.
    ///
    /// The native desktop host calls this convenience method rather than
    /// constructing a provider binding from renderer-controlled input.
    #[must_use]
    pub fn with_openai_provider_activation(self) -> Self {
        self.with_provider_activation(ProviderActivationBindingV1::openai_responses_text_v1())
    }

    /// Returns the exact non-secret provider binding selected for V2.
    #[must_use]
    pub const fn provider_activation(&self) -> Option<&ProviderActivationBindingV1> {
        self.provider_activation.as_ref()
    }
}
