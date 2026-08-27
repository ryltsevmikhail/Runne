use std::sync::Arc;

use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{
    ClaimCredentialOperation, CredentialBindingDigest, CredentialBrokerFrame,
    CredentialBrokerFrameCodec, CredentialEnrollmentError,
    CredentialEnrollmentMeasurementAuthority, CredentialMeasurementSnapshot,
    CredentialOperationSnapshot, IssueCredentialTicketDigest, IssuedCredentialTicketAttempt,
    ProviderCredentialEnrollmentStore, RawCredentialTicket,
};
use zeroize::Zeroizing;

use super::effect_authority::map_store;

/// Authenticated inherited control channel; Task 11 owns its platform adapters.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the Task 11 authenticated inherited-channel adapter instantiates this broker boundary"
    )
)]
pub(super) trait CredentialBrokerChannel {
    /// Sends exactly one canonical broker frame to the authenticated writer endpoint.
    fn send(
        &mut self,
        frame: Zeroizing<Vec<u8>>,
    ) -> Result<(), ProviderCredentialEnrollmentHostError>;
}

/// Daemon coordinator for digest-first credential-ticket issuance.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the Task 11 authenticated inherited-channel adapter constructs the broker after handoff"
    )
)]
pub(super) struct ProviderCredentialBroker {
    measurements: Arc<CredentialEnrollmentMeasurementAuthority>,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the Task 11 authenticated inherited-channel adapter invokes issue and claim after handoff"
    )
)]
impl ProviderCredentialBroker {
    /// Retains the measurement authority paired with the durable lifecycle store.
    pub(super) const fn new(measurements: Arc<CredentialEnrollmentMeasurementAuthority>) -> Self {
        Self { measurements }
    }

    /// Commits the digest-only ticket attempt before its raw value enters the broker codec.
    pub(super) fn issue_ticket<S: ProviderCredentialEnrollmentStore, C: CredentialBrokerChannel>(
        &self,
        operation: CredentialOperationSnapshot,
        continuation: CredentialBindingDigest,
        ttl_seconds: i64,
        store: &S,
        channel: &mut C,
    ) -> Result<IssuedCredentialTicketAttempt, ProviderCredentialEnrollmentHostError> {
        self.issue_ticket_with_raw(
            RawCredentialTicket::generate(),
            operation,
            continuation,
            ttl_seconds,
            store,
            channel,
        )
    }

    #[cfg(test)]
    pub(super) fn issue_ticket_with_test_entropy<
        S: ProviderCredentialEnrollmentStore,
        C: CredentialBrokerChannel,
    >(
        &self,
        operation: CredentialOperationSnapshot,
        continuation: CredentialBindingDigest,
        ttl_seconds: i64,
        store: &S,
        channel: &mut C,
        fill: impl FnOnce(&mut [u8; 32]) -> Result<(), ()>,
    ) -> Result<IssuedCredentialTicketAttempt, ProviderCredentialEnrollmentHostError> {
        self.issue_ticket_with_raw(
            RawCredentialTicket::generate_with_test_entropy(fill),
            operation,
            continuation,
            ttl_seconds,
            store,
            channel,
        )
    }

    fn issue_ticket_with_raw<S: ProviderCredentialEnrollmentStore, C: CredentialBrokerChannel>(
        &self,
        ticket: Result<RawCredentialTicket, CredentialEnrollmentError>,
        operation: CredentialOperationSnapshot,
        continuation: CredentialBindingDigest,
        ttl_seconds: i64,
        store: &S,
        channel: &mut C,
    ) -> Result<IssuedCredentialTicketAttempt, ProviderCredentialEnrollmentHostError> {
        let ticket = ticket.map_err(map_ticket_generation)?;
        let receipt = store
            .issue_ticket_attempt(
                IssueCredentialTicketDigest::new(
                    operation.operation_id(),
                    ticket.binding_digest(),
                    continuation,
                    ttl_seconds,
                )
                .map_err(|_| ProviderCredentialEnrollmentHostError::InvalidRequest)?,
            )
            .map_err(map_store)?;
        let frame = Zeroizing::new(
            CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::IssueTicket {
                operation_id: receipt.operation().operation_id(),
                attempt: receipt.ticket_attempt(),
                ticket,
            })
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
        );
        channel.send(frame)?;
        Ok(receipt)
    }

    /// Validates a returned one-shot ticket and advances only the sealed durable claim CAS.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn claim_ticket<S: ProviderCredentialEnrollmentStore>(
        &self,
        receipt: IssuedCredentialTicketAttempt,
        continuation: CredentialBindingDigest,
        database_generation: u64,
        desktop_supervisor_generation: u64,
        evidence: CredentialMeasurementSnapshot,
        frame: Zeroizing<Vec<u8>>,
        store: &S,
    ) -> Result<Vec<u8>, ProviderCredentialEnrollmentHostError> {
        let expected_operation = receipt.operation().operation_id();
        let expected_attempt = receipt.ticket_attempt();
        let CredentialBrokerFrame::Claim {
            operation_id,
            attempt,
            ticket,
            binding,
        } = CredentialBrokerFrameCodec::decode(&frame)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?
        else {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        };
        if operation_id != expected_operation || attempt != expected_attempt {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let draft = ClaimCredentialOperation::new(
            receipt,
            ticket.binding_digest(),
            continuation,
            binding,
            database_generation,
            desktop_supervisor_generation,
        )
        .map_err(|_| ProviderCredentialEnrollmentHostError::InvalidRequest)?;
        let claim = self
            .measurements
            .seal_claim_operation(evidence, draft)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        store.claim(claim).map_err(map_store)?;
        CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::ClaimAccepted {
            operation_id: expected_operation,
            attempt: expected_attempt,
        })
        .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
    }
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the Task 11 broker issue path reaches this only after authenticated channel handoff"
    )
)]
fn map_ticket_generation(
    error: CredentialEnrollmentError,
) -> ProviderCredentialEnrollmentHostError {
    match error {
        CredentialEnrollmentError::EntropyUnavailable => {
            ProviderCredentialEnrollmentHostError::Unavailable
        }
        _ => ProviderCredentialEnrollmentHostError::InvariantViolation,
    }
}
