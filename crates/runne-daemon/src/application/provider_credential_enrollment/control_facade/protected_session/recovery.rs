use super::*;
use crate::application::provider_credential_enrollment::{
    broker::pending::recovery::{PendingCleanupBrokerHandoff, PendingCleanupBrokerReservation},
    effect_authority::map_store,
};
use runne_api::{
    ProtectedCredentialRecoveryCodec, ProtectedCredentialRecoveryContext,
    ProtectedCredentialRecoveryOffer, ProviderCredentialBaseRequestAuthority,
    ProviderCredentialBrokerTransferAuthority, ProviderCredentialRequestAuthorityIssuer,
};
use runne_provider::{
    AcceptedCredentialCleanupRecovery, CredentialCleanupRecoveryRequest,
    CredentialInstallationOwnerId, CredentialOperationId, ProviderCredentialEnrollmentStore,
};

// The lease starts before the mandatory three-part native writer handoff and
// credential-service rejoin. Keep it short-lived, but leave a full claim-ticket
// window after that bounded platform work.
const CLEANUP_RECOVERY_TTL_SECONDS: u64 = 120;

pub(super) struct RecoveryExchange {
    pub(super) codec: ProtectedCredentialRecoveryCodec,
    context: ProtectedCredentialRecoveryContext,
    authority: ProviderCredentialBaseRequestAuthority,
    transfer: Option<ProviderCredentialBrokerTransferAuthority>,
    pending: Option<(
        ProtectedCredentialRecoveryOffer,
        AcceptedCredentialCleanupRecovery,
    )>,
    pub(super) ready: Option<AcceptedCredentialCleanupRecovery>,
    pub(super) operation: Option<CredentialOperationId>,
    pub(super) started: bool,
}

impl DaemonProtectedCredentialEnrollmentSession {
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
            reason = "the D1 Linux composition slice encodes terminal snapshots; the macOS flow and tests drive it today"
        )
    )]
    pub(crate) fn encode_terminal_snapshot(
        &mut self,
        snapshot: ProviderCredentialOperationSnapshotV2,
    ) -> Result<Vec<u8>, ProviderCredentialEnrollmentHostError> {
        if !snapshot.state().terminal() {
            return Err(ProviderCredentialEnrollmentHostError::InvariantViolation);
        }
        if self.recovery.started {
            self.recovery
                .codec
                .encode_daemon_terminal(&snapshot)
                .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
        } else {
            self.encode_snapshot(snapshot)
        }
    }
}

impl RecoveryExchange {
    pub(super) fn new(
        keys: &ProtectedActivationKeys,
        facts: &ProtectedEnrollmentSessionFacts,
        broker: [u8; 32],
        issuer: &ProviderCredentialRequestAuthorityIssuer,
    ) -> Result<Self, ProviderCredentialEnrollmentHostError> {
        let session = session_binding(facts);
        let daemon = daemon_binding(facts);
        let context = ProtectedCredentialRecoveryContext::new(
            facts.installation,
            facts.release,
            session,
            daemon,
            facts.tauri_peer,
            broker,
            facts.database_generation,
            facts.supervisor_generation,
        )
        .map_err(denied)?;
        let authority = issuer.issue_base(
            facts.installation,
            facts.release,
            session,
            facts.supervisor_generation,
            daemon,
            facts.database_generation,
            facts.tauri_peer,
        )?;
        let transfer = issuer.issue_recovery_broker_transfer(keys, &authority)?;
        Ok(Self {
            codec: ProtectedCredentialRecoveryCodec::new(keys, context.clone()),
            context,
            authority,
            transfer: Some(transfer),
            pending: None,
            ready: None,
            operation: None,
            started: false,
        })
    }
}

impl DaemonProtectedCredentialEnrollmentSession {
    /// The control loop must hold its live-session admission guard around this call.
    pub(crate) fn offer_cleanup_recovery(
        &mut self,
        frame: &[u8],
        now: u64,
    ) -> Result<Vec<u8>, ProviderCredentialEnrollmentHostError> {
        #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
        if self.qualification_snapshot.is_some() {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        if self.pending.is_some()
            || self.begun.is_some()
            || self.verified.is_some()
            || self.recovery.started
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let id = self
            .recovery
            .codec
            .decode_desktop_request(frame)
            .map_err(denied)?;
        self.recovery.started = true;
        let operation = CredentialOperationId::from_bytes(id).map_err(denied)?;
        let snapshot = self
            .control
            .store
            .load_operation(operation)
            .map_err(map_store)?;
        let head = self
            .control
            .store
            .lifecycle_snapshot(snapshot.provider())
            .map_err(map_store)?;
        let measurements = &self.control.measurements;
        let request = CredentialCleanupRecoveryRequest::new(
            operation,
            CredentialInstallationOwnerId::from_bytes(self.facts.installation).map_err(denied)?,
            measurements
                .release_manifest_digest(self.facts.release)
                .map_err(denied)?,
            measurements
                .protected_session_id(session_binding(&self.facts))
                .map_err(denied)?,
            measurements
                .desktop_supervisor_generation(self.facts.supervisor_generation)
                .map_err(denied)?,
            self.facts.database_generation,
            head.lifecycle_revision(),
            head.fence(),
            measurements.fresh_cleanup_continuation().map_err(denied)?,
            CLEANUP_RECOVERY_TTL_SECONDS,
        );
        let expired_attempt = self
            .control
            .store
            .expired_cleanup_recovery_attempt(request.owner(), operation)
            .map_err(map_store)?;
        // Metadata selects an explicit CAS, never a retry after a failed admission.
        // A concurrent claim or supersession is rechecked by the store transaction.
        let accepted = match expired_attempt {
            Some(expected) => self
                .control
                .store
                .supersede_cleanup_recovery(request, expected),
            None => self.control.store.accept_cleanup_recovery(request),
        }
        .map_err(map_store)?;
        let request = accepted.request();
        let offer = ProtectedCredentialRecoveryOffer::new(
            self.recovery.context.clone(),
            id,
            request.continuation_digest().as_bytes(),
            accepted.attempt(),
            request.lifecycle_revision().get(),
            request.credential_fence().get(),
            u64::try_from(accepted.issued_at()).map_err(denied)?,
            u64::try_from(accepted.expires_at()).map_err(denied)?,
        )
        .map_err(denied)?;
        let frame = self
            .recovery
            .codec
            .encode_daemon_offer(&offer, now)
            .map_err(denied)?;
        self.recovery.pending = Some((offer, accepted));
        Ok(frame)
    }

    /// Revalidates the stored snapshot before publishing a one-use endpoint.
    /// Caller must keep the live-session guard held through this method.
    pub(crate) fn accept_cleanup_recovery(
        &mut self,
        frame: &[u8],
        now: u64,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let (offer, accepted) = self
            .recovery
            .pending
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        self.recovery
            .codec
            .decode_desktop_accept(frame, &offer, now)
            .map_err(denied)?;
        let operation = self
            .control
            .store
            .load_operation(accepted.operation().operation_id())
            .map_err(map_store)?;
        let reserved = PendingCleanupBrokerHandoff::try_from(PendingCleanupBrokerReservation {
            accepted,
            authority: &self.recovery.authority,
            verifier: &self.verifier,
            measurements: &self.control.measurements,
            operation: &operation,
            rendezvous: self
                .rendezvous
                .take()
                .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?,
            transfer: self
                .recovery
                .transfer
                .take()
                .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?,
            expected_broker_evidence: self.broker_evidence,
            now: i64::try_from(now).map_err(denied)?,
        })?;
        let (endpoint, accepted) = reserved.into();
        self.recovery.operation = Some(accepted.operation().operation_id());
        self.handoff = Some(endpoint);
        self.recovery.ready = Some(accepted);
        Ok(())
    }
}

fn denied<T>(_: T) -> ProviderCredentialEnrollmentHostError {
    ProviderCredentialEnrollmentHostError::AccessDenied
}

#[cfg(test)]
mod tests;

impl DaemonProtectedCredentialEnrollmentSession {
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
            reason = "the D1 Linux composition slice takes the bound broker handoff; the macOS flow and tests drive it today"
        )
    )]
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
}
