use std::sync::Arc;
#[cfg(any(
    test,
    all(feature = "desktop-protected", target_os = "linux"),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use std::sync::OnceLock;

use super::{
    broker::pending::PendingBrokerRendezvousRegistry,
    operation_handle::ProviderCredentialOperationHandleIssuer,
};
use runne_api::ProviderCredentialEnrollmentHostError;
#[cfg(any(
    all(test, unix),
    all(feature = "desktop-protected", target_os = "linux"),
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
    all(feature = "desktop-protected", target_os = "linux"),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use runne_api::{ProviderCredentialBaseRequestAuthority, ProviderCredentialOperationSnapshotV2};
#[cfg(any(
    all(test, unix),
    all(feature = "desktop-protected", target_os = "linux"),
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
#[cfg(target_os = "linux")]
mod linux_activation;

#[cfg(any(
    all(test, unix),
    all(feature = "desktop-protected", target_os = "linux"),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use super::{ProviderCredentialAdmission, begin::ProviderCredentialEnrollmentBegin};

#[cfg(any(
    all(test, unix),
    all(feature = "desktop-protected", target_os = "linux"),
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
    all(feature = "desktop-protected", target_os = "linux"),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
pub(crate) use protected_session::ProtectedEnrollmentSessionFacts;
#[cfg(any(
    all(test, unix),
    all(feature = "desktop-protected", target_os = "linux"),
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
        all(feature = "desktop-protected", target_os = "linux"),
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
        all(feature = "desktop-protected", target_os = "linux"),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    verification: OnceLock<Arc<dyn super::ProviderCredentialVerificationHost>>,
    #[cfg(any(
        all(test, unix),
        all(feature = "desktop-protected", target_os = "linux"),
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
        all(feature = "desktop-protected", target_os = "linux"),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    #[cfg_attr(
        not(any(
            test,
            all(
                target_os = "macos",
                target_arch = "aarch64",
                feature = "desktop-protected"
            )
        )),
        expect(
            dead_code,
            reason = "the D1 Linux composition slice consumes the HTTP authority issuer; the macOS flow and tests drive it today"
        )
    )]
    http_authority_issuer: runne_api::ProviderCredentialRequestAuthorityIssuer,
    #[cfg(any(
        all(feature = "desktop-protected", target_os = "linux"),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    #[cfg_attr(
        not(all(target_os = "macos", feature = "desktop-protected")),
        expect(
            dead_code,
            reason = "the only reader is the protected macOS admission flow; Linux D1 composition consumes it in a later slice"
        )
    )]
    http_authority_verifier: ProviderCredentialRequestAuthorityVerifier,
    #[cfg(any(
        all(test, unix),
        all(feature = "desktop-protected", target_os = "linux"),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    http_facts: super::http_admission_resolver::LiveCredentialHttpFacts,
    #[cfg(any(
        target_os = "linux",
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    runtime_authority: [u8; 16],
    #[cfg(target_os = "linux")]
    linux_preadmission: std::sync::Mutex<Option<linux_activation::SessionGate>>,
    #[cfg(any(
        all(feature = "desktop-protected", target_os = "linux"),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    database_generation: u64,
    #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
    credential_service: Option<Arc<crate::protected_activation::CredentialServiceRuntimeGateway>>,
}

include!("control_facade/construct.rs");
#[cfg(all(test, unix))]
include!("control_facade/test_construct.rs");

#[path = "control_facade/local_readback.rs"]
mod local_readback;

#[cfg(test)]
mod tests;

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
