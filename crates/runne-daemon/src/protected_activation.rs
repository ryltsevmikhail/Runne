#![cfg_attr(not(feature = "desktop-protected"), allow(dead_code, unused_imports))]

#[cfg(feature = "desktop-protected")]
use crate::application::root_handle_admission::RootHandleAdmissionAuthority;
#[cfg(any(unix, windows))]
use crate::bootstrap::{BootstrapOutcome, preflight_recoverable_first_activation_sidecars};
#[cfg(any(unix, windows))]
use crate::config::{BuiltInDefaults, ConfigurationSnapshot};
#[cfg(any(unix, windows))]
use crate::provider_activation::ProviderActivation;
#[cfg(any(unix, windows))]
use rand::{RngCore, rngs::OsRng};
#[cfg(all(unix, any(feature = "desktop-protected", feature = "test-support")))]
use runne_api::LOCAL_RUNTIME_SESSION_TTL;
#[cfg(any(unix, windows))]
use runne_api::{
    ActivationDispositionV1, ExecutableIdentityV1, LaunchAuthorityError,
    LaunchAuthorityValidationV1, PendingFirstActivationV1, ProtectedActivationKeys,
    ProtectedFirstActivationCommitV1, ProtectedFirstActivationPreparedV1, ProtectedLaunchRequestV1,
    ProtectedLaunchRequestV2, ProtectedRuntimeProfileV1, ProviderActivationBindingV1,
    ProviderActivationModeV1, StableRuntimeBindingV1,
};
#[cfg(any(unix, windows))]
use runne_api::{
    ProtectedCredentialEnrollmentLaunchBindingV1, ProtectedCredentialEnrollmentLaunchRequestV3,
};
#[cfg(all(unix, feature = "desktop-protected"))]
use runne_api::{
    ProtectedCredentialEnrollmentOwnedLaunchV3, ProtectedCredentialEnrollmentRenewRequestV3,
    ProtectedCredentialEnrollmentRenewTicketV3, ProtectedCredentialEnrollmentShutdownAckV3,
    ProtectedCredentialEnrollmentShutdownV3,
};
#[cfg(all(
    any(unix, windows),
    any(feature = "desktop-protected", feature = "test-support")
))]
use runne_api::{
    ProtectedOwnedLaunchV1, ProtectedRenewRequestV1, ProtectedRenewTicketV1,
    ProtectedShutdownAckV1, ProtectedShutdownV1, RuntimeSessionBinding,
};
#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
use runne_api::{
    ProtectedOwnedLaunchV2, ProtectedRenewRequestV2, ProtectedRenewTicketV2,
    ProtectedShutdownAckV2, ProtectedShutdownV2,
};
#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
use runne_api::{RootHandleControlFrame, RootHandleTransferAuthenticator, RootHandleTransferReady};
#[cfg(all(
    any(unix, windows),
    any(feature = "desktop-protected", feature = "test-support")
))]
use runne_application::local_session::LocalSessionService;
#[cfg(any(unix, windows))]
use runne_store::schema;
#[cfg(any(unix, windows))]
use sha2::{Digest, Sha256};
#[cfg(any(unix, windows))]
use std::io::{Read, Write};
#[cfg(any(unix, windows))]
use std::path::{Path, PathBuf};
#[cfg(all(
    any(unix, windows),
    any(feature = "desktop-protected", feature = "test-support")
))]
use std::sync::{Arc, Mutex};
#[cfg(any(unix, windows))]
use std::time::Duration;
#[cfg(all(
    any(unix, windows),
    any(feature = "desktop-protected", feature = "test-support")
))]
use zeroize::Zeroize;
#[cfg(any(unix, windows))]
use zeroize::Zeroizing;
#[cfg(unix)]
mod installation_anchor;
#[cfg(unix)]
pub(crate) use installation_anchor::{VerifiedNativeEnrollmentInstallation, load_read_only};
#[cfg(all(unix, feature = "desktop-protected"))]
mod enrollment_control_exchange;
#[cfg(all(
    test,
    unix,
    feature = "desktop-protected",
    target_os = "macos",
    target_arch = "aarch64"
))]
#[path = "protected_activation/enrollment_control_exchange_negative_tests.rs"]
mod enrollment_control_exchange_negative_tests;
#[cfg(all(unix, feature = "desktop-protected"))]
mod enrollment_control_transition;
#[cfg(all(
    test,
    unix,
    feature = "desktop-protected",
    target_os = "macos",
    target_arch = "aarch64"
))]
#[path = "protected_activation/enrollment_control_transition_fixture.rs"]
mod enrollment_control_transition_fixture;
#[cfg(all(
    test,
    unix,
    feature = "desktop-protected",
    target_os = "macos",
    target_arch = "aarch64"
))]
#[path = "protected_activation/enrollment_control_transition_tests.rs"]
mod enrollment_control_transition_tests;
#[cfg(all(unix, feature = "desktop-protected"))]
#[path = "protected_activation/enrollment_exchange_platform.rs"]
mod enrollment_exchange_platform;
#[cfg(all(test, target_os = "macos"))]
#[path = "protected_activation/installation_anchor_tests.rs"]
mod installation_anchor_tests;

#[cfg(any(unix, windows))]
const MAX_FRAME_PAYLOAD_BYTES: usize = 65_536;
#[cfg(unix)]
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(all(unix, any(feature = "desktop-protected", feature = "test-support")))]
const CONTROL_IDLE_TIMEOUT: Duration =
    Duration::from_secs(LOCAL_RUNTIME_SESSION_TTL.as_secs() + CHANNEL_TIMEOUT.as_secs());
#[cfg(any(unix, windows))]
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
        offer: &runne_api::RootHandleTransferOffer,
        root: runne_platform_desktop::VerifiedRootHandle,
        now: u64,
    ) -> Result<
        crate::application::root_handle_admission::IssuedRootAdmission,
        runne_application::ports::RootAdmissionVerifierError,
    > {
        self.0.admit(offer, root, now)
    }

    pub(crate) fn fence(&self) -> Result<(), runne_application::ports::RootAdmissionVerifierError> {
        self.0.fence()
    }

    pub(crate) fn shutdown(&self) {
        self.0.shutdown();
    }
}

#[cfg(feature = "desktop-protected")]
#[cfg(any(all(test, unix), all(target_os = "macos", target_arch = "aarch64")))]
mod broker_handoff;
#[cfg(any(unix, windows))]
mod channel;
#[cfg(all(
    any(unix, windows),
    any(feature = "desktop-protected", feature = "test-support")
))]
mod control;
#[cfg(feature = "desktop-protected")]
#[cfg(all(unix, feature = "desktop-protected"))]
#[cfg(any(test, unix, all(target_os = "macos", target_arch = "aarch64")))]
pub(crate) mod control_v3;
#[cfg(all(target_os = "macos", feature = "desktop-protected"))]
mod credential_service_gateway;
#[cfg(all(target_os = "macos", feature = "desktop-protected"))]
mod credential_service_registration;
#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    feature = "desktop-protected"
))]
mod startup_discovery;
#[cfg(all(target_os = "macos", feature = "desktop-protected"))]
pub(crate) use credential_service_gateway::CredentialServiceRuntimeGateway;
#[cfg(all(target_os = "macos", feature = "desktop-protected"))]
pub(crate) use credential_service_registration::CredentialServiceRuntimeSession;
#[cfg(all(test, target_os = "macos", feature = "desktop-protected"))]
#[path = "protected_activation/credential_service_gateway_tests.rs"]
mod credential_service_gateway_tests;
#[cfg(all(test, target_os = "macos", feature = "desktop-protected"))]
#[path = "protected_activation/credential_service_registration_read_tests.rs"]
mod credential_service_registration_read_tests;
#[cfg(all(test, target_os = "macos", feature = "desktop-protected"))]
#[path = "protected_activation/credential_service_registration_tests.rs"]
mod credential_service_registration_tests;
#[cfg(all(test, target_os = "macos", feature = "desktop-protected"))]
#[path = "protected_activation/credential_service_rejoin_registration_tests.rs"]
mod credential_service_rejoin_registration_tests;
#[cfg(any(unix, windows))]
mod first_activation;
#[cfg(any(unix, windows))]
mod host;
#[cfg(any(unix, windows))]
mod launch;
#[cfg(all(unix, feature = "test-support", feature = "desktop-protected"))]
mod loopback_fixture;
#[cfg(any(unix, windows))]
mod request;
#[cfg(all(unix, feature = "desktop-protected"))]
use request::{
    DaemonLaunchProtocolExpectation, DaemonLaunchRequest, VerifiedDaemonEnrollmentLaunchAuthority,
};
#[cfg(all(unix, feature = "desktop-protected"))]
mod enrollment_transition_v2_v3;
#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
mod root_handle_control;
#[cfg(windows)]
mod windows_acl;
#[cfg(windows)]
mod windows_channel;

#[cfg(any(unix, windows))]
pub use channel::ProtectedActivationChannel;
#[cfg(all(
    any(unix, windows),
    feature = "test-support",
    not(feature = "desktop-protected")
))]
pub(crate) use control::run_control_loop;
#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
pub(crate) use control::{run_control_loop, run_control_loop_v2};
#[cfg(any(unix, windows))]
pub use first_activation::random_control_secret;
#[cfg(any(unix, windows))]
pub use host::run_verified_protected_channel;
#[cfg(any(unix, windows))]
pub(crate) use launch::VerifiedProtectedEnrollmentCapability;
#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
pub(crate) use launch::{VerifiedProtectedApplicationStart, VerifiedProtectedRuntimeStart};
#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
pub(crate) use root_handle_control::dispatch_root_handle_control_frame;
#[cfg(all(unix, feature = "desktop-protected"))]
pub(crate) use root_handle_control::dispatch_root_handle_control_frame_for_ids;
#[cfg(all(test, target_os = "macos", feature = "desktop-protected"))]
#[path = "protected_activation/enrollment_v3_broker_happy_tests.rs"]
mod enrollment_v3_broker_happy_tests;
#[cfg(all(
    test,
    unix,
    feature = "desktop-protected",
    target_os = "macos",
    target_arch = "aarch64"
))]
#[path = "protected_activation/enrollment_v3_broker_rejection_tests.rs"]
mod enrollment_v3_broker_rejection_tests;
#[cfg(all(
    test,
    unix,
    feature = "desktop-protected",
    target_os = "macos",
    target_arch = "aarch64"
))]
#[path = "protected_activation/enrollment_v3_broker_tests.rs"]
mod enrollment_v3_broker_tests;
#[cfg(all(test, unix, feature = "desktop-protected"))]
mod enrollment_v3_tests;
#[cfg(all(test, target_os = "linux", feature = "desktop-protected"))]
pub(crate) use enrollment_v3_tests::owned_and_sessions as test_enrollment_owned_and_sessions;
#[cfg(all(test, unix, feature = "test-support"))]
mod launch_channel_tests;
#[cfg(all(test, unix, feature = "desktop-protected", feature = "test-support"))]
mod root_handle_control_tests;
#[cfg(all(unix, feature = "test-support", feature = "desktop-protected"))]
mod test_root_admission_fixture;
#[cfg(all(unix, feature = "test-support"))]
pub mod test_support;

include!("protected_activation/bootstrap_validation.rs");
