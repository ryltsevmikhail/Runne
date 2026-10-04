use std::sync::Arc;

use super::DaemonProviderCredentialEnrollmentControl;
use crate::application::provider_credential_enrollment::{
    admission_registry::PendingCredentialAdmissions,
    broker::rendezvous::DaemonOwnedUnixBrokerRendezvous,
};
use runne_api::{
    BeginProviderCredentialEnrollment, ProtectedActivationKeys,
    ProtectedCredentialEnrollmentAdmissionBinding, ProtectedCredentialEnrollmentAuthenticator,
    ProtectedCredentialEnrollmentControlFrame, ProtectedCredentialEnrollmentLifecycleCodec,
    ProviderCredentialEnrollmentHostError, ProviderCredentialOperationSnapshotV2,
    ProviderCredentialRequestAuthorityPair, ProviderCredentialRequestAuthorityVerifier,
    VerifiedProtectedCredentialEnrollmentAdmission, VerifiedProtectedCredentialEnrollmentRequest,
    VerifyProviderCredential,
};

#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    feature = "desktop-protected"
))]
mod claim_measurements;
#[cfg(all(
    any(all(target_os = "macos", target_arch = "aarch64"), target_os = "linux"),
    feature = "desktop-protected"
))]
mod claim_runtime;
mod claim_selection;
mod discovery;
mod initial_request;
mod intent_exchange;
#[cfg(target_os = "linux")]
mod linux_claim_measurements;
#[cfg(all(test, target_os = "linux"))]
mod linux_fixture;
pub(crate) use initial_request::InitialCredentialExchange;
#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    feature = "desktop-protected"
))]
mod qualification;
#[cfg(all(
    test,
    target_os = "macos",
    target_arch = "aarch64",
    feature = "desktop-protected"
))]
use claim_runtime::{QualifiedWriterService, claim_fenced_writer_on};
#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    feature = "desktop-protected"
))]
pub(crate) use qualification::PostcommitAdmissionPermit;
mod helpers;
mod recovery;
pub(crate) use super::ProtectedEnrollmentSessionFacts;
use super::session_facts::{daemon_binding, session_binding};

struct VerifiedAdmission {
    request: VerifiedProtectedCredentialEnrollmentRequest,
    admission: VerifiedProtectedCredentialEnrollmentAdmission,
}

/// One protected-channel enrollment lifecycle; neither cloneable nor serializable.
pub(crate) struct DaemonProtectedCredentialEnrollmentSession {
    control: Arc<DaemonProviderCredentialEnrollmentControl>,
    http_controls: Vec<Arc<DaemonProviderCredentialEnrollmentControl>>,
    authenticator: ProtectedCredentialEnrollmentAuthenticator,
    lifecycle: ProtectedCredentialEnrollmentLifecycleCodec,
    recovery: recovery::RecoveryExchange,
    facts: ProtectedEnrollmentSessionFacts,
    http_session: [u8; 16],
    broker_evidence: [u8; 32],
    admissions: PendingCredentialAdmissions,
    verifier: ProviderCredentialRequestAuthorityVerifier,
    rendezvous: Option<DaemonOwnedUnixBrokerRendezvous>,
    pending: Option<VerifiedAdmission>,
    begun: Option<(BeginProviderCredentialEnrollment, ProviderCredentialOperationSnapshotV2)>,
    verified: Option<(VerifyProviderCredential, ProviderCredentialOperationSnapshotV2)>,
    handoff: Option<crate::application::provider_credential_enrollment::broker::pending::PendingBrokerEndpointHandoff>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64", feature = "desktop-protected"))]
    installed_facts: Option<runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64", feature = "desktop-protected"))]
    qualification: Option<crate::protected_activation::control_v3::initial_exchange::VerifiedQualificationAdmission>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64", feature = "desktop-protected"))]
    qualification_snapshot: Option<ProtectedEnrollmentSessionFacts>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64", feature = "desktop-protected"))]
    qualification_fenced: Option<qualification::FencedQualificationAdmission>,
    desktop_sequence: u64,
    daemon_sequence: u64,
}

impl DaemonProtectedCredentialEnrollmentSession {
    pub(super) fn set_http_controls(
        &mut self,
        controls: Vec<Arc<DaemonProviderCredentialEnrollmentControl>>,
    ) {
        self.http_controls = if controls.is_empty() {
            vec![Arc::clone(&self.control)]
        } else {
            controls
        };
    }

    pub(crate) fn http_controls(&self) -> Vec<Arc<DaemonProviderCredentialEnrollmentControl>> {
        self.http_controls.clone()
    }

    pub(super) fn new(
        control: Arc<DaemonProviderCredentialEnrollmentControl>,
        keys: &ProtectedActivationKeys,
        facts: ProtectedEnrollmentSessionFacts,
        rendezvous: DaemonOwnedUnixBrokerRendezvous,
        #[cfg(all(
            target_os = "macos",
            target_arch = "aarch64",
            feature = "desktop-protected"
        ))]
        installed_facts: Option<
            runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
        >,
    ) -> Result<Self, ProviderCredentialEnrollmentHostError> {
        let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
        let broker_evidence = runne_api::protected_credential_broker_evidence_binding(
            facts.release,
            rendezvous.channel_binding(),
            rendezvous.publication_public_key(),
        );
        let recovery = recovery::RecoveryExchange::new(keys, &facts, broker_evidence, &issuer)?;
        let http_session = facts.session;
        let admissions = PendingCredentialAdmissions::new_with_broker_transfer(issuer, keys);
        #[cfg(target_os = "linux")]
        let admissions = admissions.with_linux_preadmission(
            control.linux_preadmission_for(facts.session, facts.runtime_authority)?,
        );
        Ok(Self {
            http_controls: vec![Arc::clone(&control)],
            control,
            authenticator: ProtectedCredentialEnrollmentAuthenticator::from_protected_activation(
                keys,
            ),
            lifecycle: ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(keys),
            recovery,
            facts,
            http_session,
            broker_evidence,
            admissions,
            verifier,
            rendezvous: Some(rendezvous),
            pending: None,
            begun: None,
            verified: None,
            handoff: None,
            #[cfg(all(
                target_os = "macos",
                target_arch = "aarch64",
                feature = "desktop-protected"
            ))]
            installed_facts,
            #[cfg(all(
                target_os = "macos",
                target_arch = "aarch64",
                feature = "desktop-protected"
            ))]
            qualification: None,
            #[cfg(all(
                target_os = "macos",
                target_arch = "aarch64",
                feature = "desktop-protected"
            ))]
            qualification_snapshot: None,
            #[cfg(all(
                target_os = "macos",
                target_arch = "aarch64",
                feature = "desktop-protected"
            ))]
            qualification_fenced: None,
            desktop_sequence: 0,
            daemon_sequence: 0,
        })
    }

    #[cfg_attr(target_os = "linux", allow(dead_code))]
    pub(crate) fn begun_is_terminal(&self) -> bool {
        self.begun
            .as_ref()
            .is_some_and(|(_, snapshot)| snapshot.state().terminal())
            || self
                .verified
                .as_ref()
                .is_some_and(|(_, snapshot)| snapshot.state().terminal())
    }

    #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
    pub(crate) fn begun_action(
        &self,
    ) -> Result<
        runne_api::ProviderCredentialEnrollmentActionV2,
        ProviderCredentialEnrollmentHostError,
    > {
        self.begun
            .as_ref()
            .map(|(request, _)| request.action())
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    #[cfg(all(
        any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")),
        feature = "desktop-protected"
    ))]
    pub(crate) fn refresh_http_facts(
        &mut self,
        owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let facts = ProtectedEnrollmentSessionFacts::from_owned(
            owned,
            self.control.runtime_authority,
            self.control.database_generation,
        )?;
        #[cfg(target_os = "linux")]
        crate::protected_activation::enrollment_control_fanout::refresh_linux_session(
            &self.http_controls,
            self.http_session,
            *owned.session_id(),
            &facts,
        )?;
        #[cfg(not(target_os = "linux"))]
        {
            crate::protected_activation::enrollment_control_fanout::clear(
                &self.http_controls,
                self.http_session,
            );
            crate::protected_activation::enrollment_control_fanout::publish(
                &self.http_controls,
                &facts,
            )?;
        }
        self.http_session = *owned.session_id();
        Ok(())
    }

    #[cfg(any(
        all(test, unix),
        all(target_os = "linux", feature = "desktop-protected"),
        all(
            target_os = "macos",
            target_arch = "aarch64",
            feature = "desktop-protected"
        )
    ))]
    pub(crate) fn clear_http_facts(&self) {
        crate::protected_activation::enrollment_control_fanout::clear(
            &self.http_controls,
            self.http_session,
        );
    }

    #[cfg(all(test, unix))]
    pub(in crate::application::provider_credential_enrollment::control_facade) fn refresh_test_http_facts(
        &mut self,
        facts: ProtectedEnrollmentSessionFacts,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        crate::protected_activation::enrollment_control_fanout::publish(
            &self.http_controls,
            &facts,
        )?;
        self.http_session = facts.session;
        Ok(())
    }
}
