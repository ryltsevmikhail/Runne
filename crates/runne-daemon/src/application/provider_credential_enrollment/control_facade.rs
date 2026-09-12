use std::sync::Arc;

use super::{
    broker::pending::PendingBrokerRendezvousRegistry,
    operation_handle::ProviderCredentialOperationHandleIssuer,
};
use runne_api::ProviderCredentialEnrollmentHostError;
#[cfg(any(
    all(test, unix),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialCommandContext,
    ProviderCredentialIntentConsumptionProof,
};
#[cfg(any(
    all(test, unix),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use runne_api::{ProviderCredentialBaseRequestAuthority, ProviderCredentialOperationSnapshotV2};
#[cfg(any(
    all(test, unix),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use runne_api::{
    ProviderCredentialRequestAuthorityPair, ProviderCredentialRequestAuthorityVerifier,
};
use runne_provider::{
    CredentialEnrollmentMeasurementAuthority, CredentialEnrollmentStoreAuthority,
};
use runne_secure_store::ProviderCredentialReadback;
use runne_store::provider::SqliteProviderCredentialLifecycleStore;

mod http;

#[cfg(any(
    all(test, unix),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use super::{ProviderCredentialAdmission, begin::ProviderCredentialEnrollmentBegin};

#[cfg(any(
    all(test, unix),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
mod protected_session;
#[cfg(all(
    feature = "desktop-protected",
    target_os = "macos",
    target_arch = "aarch64"
))]
pub(crate) use protected_session::PostcommitAdmissionPermit;
#[cfg(any(
    all(test, unix),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
pub(crate) use protected_session::ProtectedEnrollmentSessionFacts;
#[cfg(any(
    all(test, unix),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
pub(crate) use protected_session::{
    DaemonProtectedCredentialEnrollmentSession, InitialCredentialExchange,
};

/// Daemon-owned online-enrollment authorities paired to the canonical store.
#[cfg_attr(
    not(any(
        all(test, unix),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    )),
    expect(
        dead_code,
        reason = "canonical composition retains the portable lifecycle control for its authenticated host boundary"
    )
)]
pub(crate) struct DaemonProviderCredentialEnrollmentControl {
    store: Arc<SqliteProviderCredentialLifecycleStore>,
    readback: Arc<dyn ProviderCredentialReadback>,
    measurements: CredentialEnrollmentMeasurementAuthority,
    enrollment_store_authority: CredentialEnrollmentStoreAuthority,
    handles: ProviderCredentialOperationHandleIssuer,
    rendezvous: PendingBrokerRendezvousRegistry,
    #[cfg(any(
        all(test, unix),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    http_authority_issuer: runne_api::ProviderCredentialRequestAuthorityIssuer,
    #[cfg(any(
        all(test, unix),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    http_authority_verifier: ProviderCredentialRequestAuthorityVerifier,
    #[cfg(any(
        all(test, unix),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    http_facts: super::http_admission_resolver::LiveCredentialHttpFacts,
    #[cfg(all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    ))]
    runtime_authority: [u8; 16],
    #[cfg(all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    ))]
    database_generation: u64,
    #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
    credential_service: Option<Arc<crate::protected_activation::CredentialServiceRuntimeGateway>>,
}

include!("control_facade/construct.rs");

#[cfg(test)]
mod tests {
    use super::http::generate_handle_key;

    #[test]
    fn control_handle_keys_are_nonzero_and_process_local() {
        let first = generate_handle_key().unwrap();
        let second = generate_handle_key().unwrap();
        assert_ne!(first, [0; 32]);
        assert_ne!(first, second);
    }

    #[test]
    fn control_constructor_has_one_unconditional_portable_implementation() {
        let source = include_str!("control_facade/construct.rs");
        let production = source;
        let signature = "pub(crate) fn new(";
        assert_eq!(production.matches(signature).count(), 1);
        assert!(production.contains(concat!(
            "impl DaemonProviderCredentialEnrollmentControl {\n",
            "    pub(crate) fn new("
        )));
        let constructor = production.split_once(signature).unwrap().1;
        let constructor = constructor.split_once("pub(crate) fn install_").unwrap().0;
        assert!(!constructor.contains("ProviderCredentialEnrollmentHostError::Unsupported"));
    }
}

#[cfg(all(test, unix))]
#[path = "control_facade_tests/http_admission.rs"]
mod http_admission_tests;
#[cfg(all(test, unix))]
#[path = "control_facade_tests/protected_session.rs"]
mod protected_session_tests;
#[cfg(all(test, unix))]
pub(crate) use protected_session_tests::control as test_control;
