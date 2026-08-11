//! Protected inherited-channel admission for bundled daemon launches.

#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::{Arc, Mutex};
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use gocode_api::{
    ActivationDispositionV1, ExecutableIdentityV1, LOCAL_RUNTIME_SESSION_TTL, LaunchAuthorityError,
    LaunchAuthorityValidationV1, PendingFirstActivationV1, ProtectedActivationKeys,
    ProtectedFirstActivationCommitV1, ProtectedFirstActivationPreparedV1, ProtectedLaunchRequestV1,
    ProtectedLaunchRequestV2, ProtectedOwnedLaunchV1, ProtectedOwnedLaunchV2,
    ProtectedRenewRequestV1, ProtectedRenewRequestV2, ProtectedRenewTicketV1,
    ProtectedRenewTicketV2, ProtectedRuntimeProfileV1, ProtectedShutdownAckV1,
    ProtectedShutdownAckV2, ProtectedShutdownV1, ProtectedShutdownV2, ProviderActivationModeV1,
    RuntimeSessionBinding, StableRuntimeBindingV1,
};
#[cfg(all(unix, feature = "desktop-protected"))]
use gocode_api::{
    RootHandleControlFrame, RootHandleTransferAuthenticator, RootHandleTransferReady,
};
#[cfg(unix)]
use gocode_application::local_session::LocalSessionService;
#[cfg(unix)]
use gocode_store::schema;
#[cfg(unix)]
use rand::{RngCore, rngs::OsRng};
#[cfg(unix)]
use sha2::{Digest, Sha256};
#[cfg(unix)]
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "desktop-protected")]
use crate::application::root_handle_admission::RootHandleAdmissionAuthority;
#[cfg(unix)]
use crate::bootstrap::{
    BootstrapOutcome, bootstrap_protected, preflight_recoverable_first_activation_sidecars,
};
#[cfg(unix)]
use crate::config::{BuiltInDefaults, ConfigurationSnapshot};
#[cfg(unix)]
use crate::provider_activation::ProviderActivation;

#[cfg(unix)]
const MAX_FRAME_PAYLOAD_BYTES: usize = 65_536;
#[cfg(unix)]
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(unix)]
const CONTROL_IDLE_TIMEOUT: Duration =
    Duration::from_secs(LOCAL_RUNTIME_SESSION_TTL.as_secs() + CHANNEL_TIMEOUT.as_secs());
#[cfg(unix)]
const LOCAL_PRINCIPAL: &str = "local-owner";

/// Opaque daemon-owned capability for protected root-control dispatch.
#[cfg(feature = "desktop-protected")]
#[doc(hidden)]
pub struct ProtectedRootControl(Arc<RootHandleAdmissionAuthority>);

#[cfg(feature = "desktop-protected")]
impl ProtectedRootControl {
    pub(crate) fn new(authority: Arc<RootHandleAdmissionAuthority>) -> Arc<Self> {
        Arc::new(Self(authority))
    }

    pub(crate) fn admit_verified_offer(
        &self,
        offer: &gocode_api::RootHandleTransferOffer,
        root: gocode_platform_desktop::VerifiedRootHandle,
        now: u64,
    ) -> Result<
        gocode_api::RootHandleAdmission,
        gocode_application::ports::RootAdmissionVerifierError,
    > {
        self.0.admit(offer, root, now)
    }

    pub(crate) fn fence(
        &self,
    ) -> Result<(), gocode_application::ports::RootAdmissionVerifierError> {
        self.0.fence()
    }

    pub(crate) fn shutdown(&self) {
        self.0.shutdown();
    }
}

#[cfg(unix)]
mod channel;
#[cfg(unix)]
mod control;
#[cfg(unix)]
mod first_activation;
#[cfg(unix)]
mod launch;
#[cfg(unix)]
mod request;
#[cfg(all(unix, feature = "desktop-protected"))]
mod root_handle_control;

#[cfg(unix)]
pub use channel::ProtectedActivationChannel;
#[cfg(unix)]
pub use control::{run_control_loop, run_control_loop_v2};
#[cfg(unix)]
pub use first_activation::random_control_secret;
#[cfg(unix)]
pub use launch::{
    ProtectedDaemonLaunch, VerifiedProtectedApplicationStart, VerifiedProtectedRuntimeStart,
};
#[cfg(all(unix, feature = "desktop-protected"))]
pub use root_handle_control::{dispatch_root_handle_control_frame, receive_root_handle_offer};

#[cfg(unix)]
pub(crate) fn validate_protected_bootstrap_connection(
    config: &ConfigurationSnapshot,
    connection: &rusqlite::Connection,
    expected: &StableRuntimeBindingV1,
    pending: Option<&PendingFirstActivationV1>,
) -> Result<(), LaunchAuthorityError> {
    match pending {
        Some(pending) => first_activation::validate_resume_first_activation_connection(
            config, connection, pending,
        ),
        None => first_activation::validate_existing_connection(config, connection, expected, None),
    }
}

#[cfg(not(unix))]
pub struct ProtectedActivationChannel;

#[cfg(not(unix))]
impl ProtectedActivationChannel {
    pub fn from_inherited_stdin() -> Result<Option<Self>, gocode_api::LaunchAuthorityError> {
        Ok(None)
    }
}
