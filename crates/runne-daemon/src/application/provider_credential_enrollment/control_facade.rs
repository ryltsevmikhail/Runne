use std::sync::Arc;
use std::sync::OnceLock;

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
    ProviderCredentialIntentConsumptionProof, VerifyProviderCredential,
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
    verification: OnceLock<Arc<dyn super::ProviderCredentialVerificationHost>>,
    #[cfg(any(
        all(test, unix),
        all(target_os = "macos", feature = "desktop-protected")
    ))]
    #[cfg_attr(
        not(all(target_os = "macos", feature = "desktop-protected")),
        expect(
            dead_code,
            reason = "the only reader is the protected macOS credential-service session, which does not exist in this configuration"
        )
    )]
    local_readback: OnceLock<Arc<dyn runne_secure_store::ProviderCredentialVerificationReadback>>,
    #[cfg(any(
        all(test, unix),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    http_authority_issuer: runne_api::ProviderCredentialRequestAuthorityIssuer,
    #[cfg(all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
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

#[cfg(any(test, all(target_os = "macos", feature = "desktop-protected")))]
fn install_local_readback_once(
    slot: &OnceLock<Arc<dyn runne_secure_store::ProviderCredentialVerificationReadback>>,
    readback: Arc<dyn runne_secure_store::ProviderCredentialVerificationReadback>,
) -> Result<(), ProviderCredentialEnrollmentHostError> {
    if let Some(existing) = slot.get() {
        return if Arc::ptr_eq(existing, &readback) {
            Ok(())
        } else {
            Err(ProviderCredentialEnrollmentHostError::InvariantViolation)
        };
    }
    slot.set(readback)
        .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
}

#[cfg(test)]
mod tests {
    use super::http::generate_handle_key;
    use super::install_local_readback_once;
    use runne_provider::{CredentialVerificationLease, CredentialVerificationResult};
    use runne_secure_store::{ProviderCredentialVerificationReadback, SecureStoreError};
    use std::sync::{Arc, OnceLock};

    struct Reader;

    impl ProviderCredentialVerificationReadback for Reader {
        fn verify_local(
            &self,
            _: &CredentialVerificationLease,
        ) -> Result<CredentialVerificationResult, SecureStoreError> {
            Ok(CredentialVerificationResult::Verified)
        }
    }

    #[test]
    fn local_readback_mount_is_idempotent_only_for_same_arc() {
        let slot = OnceLock::new();
        let first: Arc<dyn ProviderCredentialVerificationReadback> = Arc::new(Reader);
        let different: Arc<dyn ProviderCredentialVerificationReadback> = Arc::new(Reader);

        assert!(install_local_readback_once(&slot, Arc::clone(&first)).is_ok());
        assert!(install_local_readback_once(&slot, Arc::clone(&first)).is_ok());
        assert!(install_local_readback_once(&slot, different).is_err());
    }

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

#[cfg(any(
    all(test, unix),
    all(
        test,
        target_os = "macos",
        target_arch = "aarch64",
        feature = "desktop-protected"
    )
))]
#[path = "control_facade_tests/http_admission.rs"]
mod http_admission_tests;
#[cfg(any(
    all(test, unix),
    all(
        test,
        target_os = "macos",
        target_arch = "aarch64",
        feature = "desktop-protected"
    )
))]
#[path = "control_facade_tests/protected_session.rs"]
mod protected_session_tests;
#[cfg(any(
    all(test, unix),
    all(
        test,
        target_os = "macos",
        target_arch = "aarch64",
        feature = "desktop-protected"
    )
))]
#[path = "control_facade_tests/verify.rs"]
mod verify_tests;
#[cfg(all(
    test,
    feature = "desktop-protected",
    target_os = "macos",
    target_arch = "aarch64"
))]
pub(crate) use protected_session_tests::control as test_control;
