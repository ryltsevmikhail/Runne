//! Protected inherited-channel admission for bundled daemon launches.

#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(all(unix, any(feature = "desktop-protected", feature = "test-support")))]
use std::sync::{Arc, Mutex};
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use gocode_api::{
    ActivationDispositionV1, ExecutableIdentityV1, LaunchAuthorityError,
    LaunchAuthorityValidationV1, PendingFirstActivationV1, ProtectedActivationKeys,
    ProtectedFirstActivationCommitV1, ProtectedFirstActivationPreparedV1, ProtectedLaunchRequestV1,
    ProtectedLaunchRequestV2, ProtectedRuntimeProfileV1, ProviderActivationModeV1,
    StableRuntimeBindingV1,
};
#[cfg(all(unix, any(feature = "desktop-protected", feature = "test-support")))]
use gocode_api::{
    LOCAL_RUNTIME_SESSION_TTL, ProtectedOwnedLaunchV1, ProtectedRenewRequestV1,
    ProtectedRenewTicketV1, ProtectedShutdownAckV1, ProtectedShutdownV1, RuntimeSessionBinding,
};
#[cfg(all(unix, feature = "desktop-protected"))]
use gocode_api::{
    ProtectedOwnedLaunchV2, ProtectedRenewRequestV2, ProtectedRenewTicketV2,
    ProtectedShutdownAckV2, ProtectedShutdownV2,
};
#[cfg(all(unix, feature = "desktop-protected"))]
use gocode_api::{
    RootHandleControlFrame, RootHandleTransferAuthenticator, RootHandleTransferReady,
};
#[cfg(all(unix, any(feature = "desktop-protected", feature = "test-support")))]
use gocode_application::local_session::LocalSessionService;
#[cfg(unix)]
use gocode_store::schema;
#[cfg(unix)]
use rand::{RngCore, rngs::OsRng};
#[cfg(unix)]
use sha2::{Digest, Sha256};
#[cfg(all(unix, any(feature = "desktop-protected", feature = "test-support")))]
use zeroize::Zeroize;
#[cfg(unix)]
use zeroize::Zeroizing;

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
#[cfg(all(unix, any(feature = "desktop-protected", feature = "test-support")))]
const CONTROL_IDLE_TIMEOUT: Duration =
    Duration::from_secs(LOCAL_RUNTIME_SESSION_TTL.as_secs() + CHANNEL_TIMEOUT.as_secs());
#[cfg(unix)]
const LOCAL_PRINCIPAL: &str = "local-owner";

#[cfg(feature = "desktop-protected")]
pub(crate) struct ProtectedRootControl(Arc<RootHandleAdmissionAuthority>);

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
#[cfg(all(unix, any(feature = "desktop-protected", feature = "test-support")))]
mod control;
#[cfg(unix)]
mod first_activation;
#[cfg(unix)]
mod host;
#[cfg(unix)]
mod launch;
#[cfg(all(unix, feature = "test-support", feature = "desktop-protected"))]
mod loopback_fixture;
#[cfg(unix)]
mod request;
#[cfg(all(unix, feature = "desktop-protected"))]
mod root_handle_control;

#[cfg(unix)]
pub use channel::ProtectedActivationChannel;
#[cfg(all(unix, feature = "test-support", not(feature = "desktop-protected")))]
pub(crate) use control::run_control_loop;
#[cfg(all(unix, feature = "desktop-protected"))]
pub(crate) use control::{run_control_loop, run_control_loop_v2};
#[cfg(unix)]
pub use first_activation::random_control_secret;
#[cfg(unix)]
pub use host::run_verified_protected_channel;
#[cfg(all(unix, feature = "desktop-protected"))]
pub(crate) use launch::{VerifiedProtectedApplicationStart, VerifiedProtectedRuntimeStart};
#[cfg(all(unix, feature = "desktop-protected"))]
pub(crate) use root_handle_control::dispatch_root_handle_control_frame;
#[cfg(all(test, unix, feature = "test-support"))]
mod launch_channel_tests;
#[cfg(all(test, unix, feature = "desktop-protected", feature = "test-support"))]
mod root_handle_control_tests;
#[cfg(all(unix, feature = "test-support", feature = "desktop-protected"))]
mod test_root_admission_fixture;
#[cfg(all(unix, feature = "test-support"))]
pub mod test_support;

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
