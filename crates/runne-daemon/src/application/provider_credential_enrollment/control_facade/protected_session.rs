use std::sync::Arc;

use super::DaemonProviderCredentialEnrollmentControl;
use crate::application::provider_credential_enrollment::{
    admission_registry::PendingCredentialAdmissions,
    broker::rendezvous::DaemonOwnedUnixBrokerRendezvous,
};
use runne_api::{
    ApiActor, ApiPrincipalId, BeginProviderCredentialEnrollment, ProtectedActivationKeys,
    ProtectedCredentialEnrollmentAdmissionBinding, ProtectedCredentialEnrollmentAuthenticator,
    ProtectedCredentialEnrollmentControlFrame, ProtectedCredentialEnrollmentLifecycleCodec,
    ProviderCredentialCommandContext, ProviderCredentialEnrollmentHostError,
    ProviderCredentialOperationSnapshotV2, ProviderCredentialRequestAuthorityPair,
    ProviderCredentialRequestAuthorityVerifier, VerifiedProtectedCredentialEnrollmentAdmission,
    VerifiedProtectedCredentialEnrollmentRequest,
};
use runne_domain::id::{CommandId, IdempotencyKey};

#[cfg(target_os = "macos")]
mod claim_measurements;
#[cfg(target_os = "macos")]
mod claim_runtime;
mod facts;
pub(crate) use facts::ProtectedEnrollmentSessionFacts;
use facts::{daemon_binding, session_binding};

struct VerifiedAdmission {
    request: VerifiedProtectedCredentialEnrollmentRequest,
    admission: VerifiedProtectedCredentialEnrollmentAdmission,
}

/// One protected-channel enrollment lifecycle; neither cloneable nor serializable.
pub(crate) struct DaemonProtectedCredentialEnrollmentSession {
    control: Arc<DaemonProviderCredentialEnrollmentControl>,
    authenticator: ProtectedCredentialEnrollmentAuthenticator,
    lifecycle: ProtectedCredentialEnrollmentLifecycleCodec,
    facts: ProtectedEnrollmentSessionFacts,
    broker_evidence: [u8; 32],
    admissions: PendingCredentialAdmissions,
    verifier: ProviderCredentialRequestAuthorityVerifier,
    rendezvous: Option<DaemonOwnedUnixBrokerRendezvous>,
    pending: Option<VerifiedAdmission>,
    begun: Option<(BeginProviderCredentialEnrollment, ProviderCredentialOperationSnapshotV2)>,
    handoff: Option<crate::application::provider_credential_enrollment::broker::pending::PendingBrokerEndpointHandoff>,
    installed_facts: Option<runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts>,
    desktop_sequence: u64,
    daemon_sequence: u64,
}

impl DaemonProtectedCredentialEnrollmentSession {
    pub(super) fn new(
        control: Arc<DaemonProviderCredentialEnrollmentControl>,
        keys: &ProtectedActivationKeys,
        facts: ProtectedEnrollmentSessionFacts,
        rendezvous: DaemonOwnedUnixBrokerRendezvous,
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
        Ok(Self {
            control,
            authenticator: ProtectedCredentialEnrollmentAuthenticator::from_protected_activation(
                keys,
            ),
            lifecycle: ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(keys),
            facts,
            broker_evidence,
            admissions: PendingCredentialAdmissions::new_with_broker_transfer(issuer, keys),
            verifier,
            rendezvous: Some(rendezvous),
            pending: None,
            begun: None,
            handoff: None,
            installed_facts,
            desktop_sequence: 0,
            daemon_sequence: 0,
        })
    }

    /// Authenticates one exact native request and returns its daemon admission proof.
    pub(crate) fn accept_request(
        &mut self,
        frame: &[u8],
        now_unix_millis: u64,
    ) -> Result<Vec<u8>, ProviderCredentialEnrollmentHostError> {
        if self.pending.is_some() || self.begun.is_some() {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let request = self
            .authenticator
            .decode_authenticated_request(frame, 0, now_unix_millis)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        self.require_request(&request)?;
        let binding = self.admission_binding(&request)?;
        let admission = self
            .authenticator
            .issue_admission(&request, binding.clone(), request.sequence() + 1)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let encoded =
            ProtectedCredentialEnrollmentControlFrame::Admission(admission).encode_frame();
        let verified = self
            .authenticator
            .decode_admission(
                &encoded,
                &request,
                &binding,
                request.sequence(),
                now_unix_millis,
            )
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        self.pending = Some(VerifiedAdmission {
            request,
            admission: verified,
        });
        Ok(encoded)
    }

    /// Consumes a verified admission and returns only the safe operation projection.
    pub(crate) fn begin(
        &mut self,
        frame: &[u8],
        now_unix_millis: u64,
    ) -> Result<Vec<u8>, ProviderCredentialEnrollmentHostError> {
        let command = self
            .lifecycle
            .decode_desktop_begin(frame, self.desktop_sequence)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        self.desktop_sequence = self
            .desktop_sequence
            .checked_add(1)
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        if let Some((prior, snapshot)) = &self.begun {
            if prior != &command {
                return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
            }
            return self.encode_snapshot(snapshot.clone());
        }
        let pending = self
            .pending
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let context = command_context(&command)?;
        self.admissions
            .register(pending.request, pending.admission, context, now_unix_millis)?;
        let (authority, proof, context, broker_transfer) = self
            .admissions
            .resolve_begin_with_broker_transfer(&command, self.facts.session, now_unix_millis)?;
        let rendezvous = self
            .rendezvous
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        self.control
            .rendezvous
            .reserve_transition_rendezvous_with_transfer(
                rendezvous,
                &authority,
                &proof,
                broker_transfer,
            )?;
        let now_high_water = i64::try_from(now_unix_millis / 1_000)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let snapshot = self.control.begin_admitted(
            self.verifier.clone(),
            &authority,
            &proof,
            &context,
            &command,
            now_high_water,
        )?;
        let operation_id = self.control.handles.resolve(snapshot.operation_handle())?;
        let operation = runne_provider::ProviderCredentialEnrollmentStore::load_operation(
            self.control.store.as_ref(),
            operation_id,
        )
        .map_err(super::super::effect_authority::map_store)?;
        self.handoff = Some(
            self.control.rendezvous.begin_endpoint_handoff(
                snapshot
                    .broker_rendezvous_id()
                    .ok_or(ProviderCredentialEnrollmentHostError::InvariantViolation)?,
                &operation,
                &authority,
                &proof,
                now_high_water,
            )?,
        );
        self.begun = Some((command, snapshot.clone()));
        self.encode_snapshot(snapshot)
    }

    pub(crate) fn take_bound_broker_handoff(
        &mut self,
    ) -> Result<
        crate::application::provider_credential_enrollment::broker::pending::PendingBrokerEndpointHandoff,
        ProviderCredentialEnrollmentHostError,
    >{
        self.handoff
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    fn encode_snapshot(
        &mut self,
        snapshot: ProviderCredentialOperationSnapshotV2,
    ) -> Result<Vec<u8>, ProviderCredentialEnrollmentHostError> {
        self.daemon_sequence = self
            .daemon_sequence
            .checked_add(1)
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        self.lifecycle
            .encode_daemon_snapshot(&snapshot, self.daemon_sequence)
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
    }

    fn require_request(
        &self,
        request: &VerifiedProtectedCredentialEnrollmentRequest,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let facts = &self.facts;
        if request.protected_launch_authority_id() != facts.launch_authority
            || request.protected_session_id() != facts.session
            || request.daemon_instance_id() != facts.daemon
            || request.daemon_launch_generation() != facts.launch_generation
            || request.desktop_supervisor_generation() != facts.supervisor_generation
            || request.release_tuple_digest() != facts.release
            || request.tauri_peer_process_evidence_digest() != facts.tauri_peer
            || request.broker_process_evidence_digest() != self.broker_evidence
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok(())
    }

    fn admission_binding(
        &self,
        request: &VerifiedProtectedCredentialEnrollmentRequest,
    ) -> Result<ProtectedCredentialEnrollmentAdmissionBinding, ProviderCredentialEnrollmentHostError>
    {
        ProtectedCredentialEnrollmentAdmissionBinding::new(
            self.facts.installation,
            self.facts.release,
            session_binding(&self.facts),
            self.facts.supervisor_generation,
            daemon_binding(&self.facts),
            self.facts.database_generation,
            self.facts.tauri_peer,
            request.native_confirmation_digest(),
            request.broker_process_evidence_digest(),
            *uuid::Uuid::now_v7().as_bytes(),
            request.expires_at_unix_millis(),
        )
        .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
    }
}

fn command_context(
    command: &BeginProviderCredentialEnrollment,
) -> Result<ProviderCredentialCommandContext, ProviderCredentialEnrollmentHostError> {
    Ok(ProviderCredentialCommandContext {
        command_id: CommandId::parse(command.command_identity())
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvalidRequest)?,
        idempotency_key: IdempotencyKey::new(command.idempotency_key())
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvalidRequest)?,
        principal: ApiPrincipalId::new("protected-desktop-owner")
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
        actor: ApiActor::new("runne-tauri-native-host")
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
    })
}
