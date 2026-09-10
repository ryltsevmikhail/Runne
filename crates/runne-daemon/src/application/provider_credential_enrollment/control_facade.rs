use std::sync::Arc;

use super::{
    broker::pending::PendingBrokerRendezvousRegistry,
    operation_handle::ProviderCredentialOperationHandleIssuer,
};
use rand::{RngCore as _, rngs::OsRng};
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
    BeginProviderCredentialEnrollment, ProviderCredentialBaseRequestAuthority,
    ProviderCredentialCommandContext, ProviderCredentialIntentConsumptionProof,
    ProviderCredentialOperationSnapshotV2, ProviderCredentialRequestAuthorityVerifier,
};
use runne_provider::{
    CredentialEnrollmentMeasurementAuthority, CredentialEnrollmentStoreAuthority,
};
use runne_secure_store::ProviderCredentialReadback;
use runne_store::provider::SqliteProviderCredentialLifecycleStore;

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

impl DaemonProviderCredentialEnrollmentControl {
    pub(crate) fn new(
        store: Arc<SqliteProviderCredentialLifecycleStore>,
        readback: Arc<dyn ProviderCredentialReadback>,
        measurements: CredentialEnrollmentMeasurementAuthority,
        enrollment_store_authority: CredentialEnrollmentStoreAuthority,
        runtime_authority: [u8; 16],
        database_generation: u64,
        #[cfg(all(target_os = "macos", feature = "desktop-protected"))] credential_service: Option<
            Arc<crate::protected_activation::CredentialServiceRuntimeGateway>,
        >,
    ) -> Result<Self, ProviderCredentialEnrollmentHostError> {
        if runtime_authority == [0; 16] || database_generation == 0 {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let handles = ProviderCredentialOperationHandleIssuer::new(generate_handle_key()?);
        let rendezvous = PendingBrokerRendezvousRegistry::new(handles.duplicate());
        Ok(Self {
            store,
            readback,
            measurements,
            enrollment_store_authority,
            handles,
            rendezvous,
            #[cfg(all(
                feature = "desktop-protected",
                target_os = "macos",
                target_arch = "aarch64"
            ))]
            runtime_authority,
            #[cfg(all(
                feature = "desktop-protected",
                target_os = "macos",
                target_arch = "aarch64"
            ))]
            database_generation,
            #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
            credential_service,
        })
    }

    #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
    pub(crate) fn install_credential_service_session(
        &self,
        session: crate::protected_activation::CredentialServiceRuntimeSession,
    ) -> Result<
        Arc<crate::protected_activation::CredentialServiceRuntimeGateway>,
        ProviderCredentialEnrollmentHostError,
    > {
        let gateway = self
            .credential_service
            .as_ref()
            .ok_or(ProviderCredentialEnrollmentHostError::Unsupported)?;
        gateway.install(session)?;
        super::CredentialEnrollmentRecoveryGateway::new(self.store.as_ref(), gateway.as_ref())
            .reconcile_online(chrono::Utc::now().timestamp())?;
        Ok(Arc::clone(gateway))
    }

    #[cfg(any(
        all(test, unix),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    #[allow(clippy::too_many_arguments)]
    fn begin_admitted(
        &self,
        verifier: ProviderCredentialRequestAuthorityVerifier,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
        context: &ProviderCredentialCommandContext,
        command: &BeginProviderCredentialEnrollment,
        now_high_water: i64,
    ) -> Result<ProviderCredentialOperationSnapshotV2, ProviderCredentialEnrollmentHostError> {
        ProviderCredentialEnrollmentBegin::new(
            ProviderCredentialAdmission::with_legacy_import_authority(
                verifier,
                self.measurements.clone(),
                self.enrollment_store_authority.clone(),
            ),
            self.handles.duplicate(),
            self.store.as_ref(),
            self.readback.as_ref(),
            self.rendezvous.clone(),
        )
        .admit(authority, proof, context, command, now_high_water)
    }

    #[cfg(all(
        target_os = "macos",
        target_arch = "aarch64",
        feature = "desktop-protected"
    ))]
    pub(crate) fn start_protected_session(
        self: &Arc<Self>,
        keys: &runne_api::ProtectedActivationKeys,
        owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
        rendezvous: super::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous,
        installed_facts: runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
    ) -> Result<DaemonProtectedCredentialEnrollmentSession, ProviderCredentialEnrollmentHostError>
    {
        let facts = ProtectedEnrollmentSessionFacts::from_owned(
            owned,
            self.runtime_authority,
            self.database_generation,
        )?;
        DaemonProtectedCredentialEnrollmentSession::new(
            Arc::clone(self),
            keys,
            facts,
            rendezvous,
            Some(installed_facts),
        )
    }

    #[cfg(all(test, unix))]
    fn start_test_protected_session(
        self: &Arc<Self>,
        keys: &runne_api::ProtectedActivationKeys,
        facts: ProtectedEnrollmentSessionFacts,
        rendezvous: super::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous,
    ) -> Result<DaemonProtectedCredentialEnrollmentSession, ProviderCredentialEnrollmentHostError>
    {
        DaemonProtectedCredentialEnrollmentSession::new(
            Arc::clone(self),
            keys,
            facts,
            rendezvous,
            #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
            None,
        )
    }
}

fn generate_handle_key() -> Result<[u8; 32], ProviderCredentialEnrollmentHostError> {
    let mut key = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut key)
        .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
    if key == [0; 32] {
        return Err(ProviderCredentialEnrollmentHostError::Unavailable);
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::generate_handle_key;

    #[test]
    fn control_handle_keys_are_nonzero_and_process_local() {
        let first = generate_handle_key().unwrap();
        let second = generate_handle_key().unwrap();
        assert_ne!(first, [0; 32]);
        assert_ne!(first, second);
    }

    #[test]
    fn control_constructor_has_one_unconditional_portable_implementation() {
        let source = include_str!("control_facade.rs");
        let production = source.split_once("#[cfg(test)]\nmod tests").unwrap().0;
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
#[path = "control_facade_tests/protected_session.rs"]
mod protected_session_tests;
