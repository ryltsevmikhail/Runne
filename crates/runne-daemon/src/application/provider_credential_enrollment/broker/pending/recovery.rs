use super::*;
use runne_api::ProviderCredentialRequestAuthorityVerifier;
use runne_provider::{AcceptedCredentialCleanupRecovery, CredentialEnrollmentMeasurementAuthority};

/// Inputs owned by the admitted host; metadata alone cannot construct the witness.
pub(crate) struct PendingCleanupBrokerReservation<'a> {
    pub(crate) accepted: AcceptedCredentialCleanupRecovery,
    pub(crate) authority: &'a ProviderCredentialBaseRequestAuthority,
    pub(crate) verifier: &'a ProviderCredentialRequestAuthorityVerifier,
    pub(crate) measurements: &'a CredentialEnrollmentMeasurementAuthority,
    pub(crate) operation: &'a CredentialOperationSnapshot,
    pub(crate) rendezvous: DaemonOwnedUnixBrokerRendezvous,
    pub(crate) transfer: ProviderCredentialBrokerTransferAuthority,
    pub(crate) expected_broker_evidence: [u8; 32],
    pub(crate) now: i64,
}

/// Retains the exact store witness beside its move-only endpoint handoff.
pub(crate) struct PendingCleanupBrokerHandoff {
    endpoint: PendingBrokerEndpointHandoff,
    accepted: AcceptedCredentialCleanupRecovery,
}

impl TryFrom<PendingCleanupBrokerReservation<'_>> for PendingCleanupBrokerHandoff {
    type Error = ProviderCredentialEnrollmentHostError;
    fn try_from(value: PendingCleanupBrokerReservation<'_>) -> Result<Self, Self::Error> {
        value.verifier.verify_base(value.authority)?;
        value
            .measurements
            .validate_cleanup_recovery(&value.accepted)
            .map_err(|_| Self::Error::AccessDenied)?;
        let request = value.accepted.request();
        let operation = value.operation;
        let authority = value.authority;
        let witness = authority.credential_broker_handoff_witness();
        if value.now < value.accepted.issued_at()
            || value.now >= value.accepted.expires_at()
            || operation != value.accepted.operation()
            || operation.state() != CredentialOperationState::Prepared
            || !matches!(
                operation.action(),
                runne_provider::CredentialOperationAction::Revoke
                    | runne_provider::CredentialOperationAction::RetiredVersionCleanup
                    | runne_provider::CredentialOperationAction::LegacySourceCleanup
            )
            || request.owner().as_bytes() != *authority.installation_identity()
            || request.release_digest().as_bytes() != *authority.release_tuple_digest()
            || request.session_digest().as_bytes() != *authority.protected_session_id()
            || request.database_generation() != authority.database_generation()
            || request.supervisor_generation() != authority.desktop_supervisor_generation()
            || value.expected_broker_evidence
                != runne_api::protected_credential_broker_evidence_binding(
                    *authority.release_tuple_digest(),
                    value.rendezvous.channel_binding(),
                    value.rendezvous.publication_public_key(),
                )
            || !value
                .transfer
                .matches_handoff(&witness, authority.protected_session_id())
        {
            return Err(Self::Error::AccessDenied);
        }
        let binding = PendingBrokerRendezvousBinding {
            operation_id: operation.operation_id(),
            begin_proof: operation.begin_proof_digest(),
            owner: request.owner(),
            protected_session: *authority.protected_session_id(),
            tauri_peer: *authority.authenticated_tauri_peer_process(),
            daemon_authority: *authority.daemon_authority_id(),
            database_generation: authority.database_generation(),
            supervisor_generation: authority.desktop_supervisor_generation(),
            release_tuple: request.release_digest(),
            expires_at_high_water: value.accepted.expires_at(),
        };
        Ok(Self {
            endpoint: PendingBrokerEndpointHandoff {
                binding,
                authority_witness: witness,
                broker_transfer: Some(value.transfer),
                rendezvous: value.rendezvous,
            },
            accepted: value.accepted,
        })
    }
}

impl From<PendingCleanupBrokerHandoff>
    for (
        PendingBrokerEndpointHandoff,
        AcceptedCredentialCleanupRecovery,
    )
{
    fn from(value: PendingCleanupBrokerHandoff) -> Self {
        (value.endpoint, value.accepted)
    }
}
