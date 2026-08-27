use std::sync::Arc;

use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{
    AttachCredentialProcess, ClaimCredentialOperation, CredentialBindingDigest,
    CredentialBrokerFrame, CredentialBrokerFrameCodec, CredentialEnrollmentError,
    CredentialEnrollmentMeasurementAuthority, CredentialMeasurementSnapshot,
    CredentialNativeEffectDisposition, CredentialOperationId, CredentialOperationSnapshot,
    IssueCredentialTicketDigest, IssuedCredentialTicketAttempt, ObserveNativeEffect,
    ProviderCredentialEnrollmentStore, RawCredentialTicket,
};
use zeroize::Zeroizing;

use super::effect_authority::map_store;

#[cfg(all(unix, feature = "desktop-protected"))]
mod unix;

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

    /// Receives the one writer response admitted by the surrounding exchange.
    fn receive(&mut self) -> Result<Zeroizing<Vec<u8>>, ProviderCredentialEnrollmentHostError>;
}

/// Move-only authority for the one post-claim possible-effect diagnostic.
#[must_use = "the writer effect diagnostic must be consumed or reconciled after a claim"]
pub(super) struct ClaimedBrokerEffect {
    operation_id: CredentialOperationId,
    binding: CredentialBindingDigest,
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
        store
            .attach_process(
                AttachCredentialProcess::new(operation.operation_id(), continuation)
                    .map_err(|_| ProviderCredentialEnrollmentHostError::InvalidRequest)?,
            )
            .map_err(map_store)?;
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

    /// Receives one claim, commits its durable CAS, then returns only its acknowledgement.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn claim_ticket_from_channel<
        S: ProviderCredentialEnrollmentStore,
        C: CredentialBrokerChannel,
    >(
        &self,
        receipt: IssuedCredentialTicketAttempt,
        continuation: CredentialBindingDigest,
        database_generation: u64,
        desktop_supervisor_generation: u64,
        evidence: CredentialMeasurementSnapshot,
        store: &S,
        channel: &mut C,
    ) -> Result<ClaimedBrokerEffect, ProviderCredentialEnrollmentHostError> {
        let operation_id = receipt.operation().operation_id();
        let claim = channel.receive()?;
        let accepted = self.claim_ticket(
            receipt,
            continuation,
            database_generation,
            desktop_supervisor_generation,
            evidence,
            claim,
            store,
        )?;
        let operation = store.load_operation(operation_id).map_err(map_store)?;
        let binding = operation
            .process_release_binding_digest()
            .ok_or(ProviderCredentialEnrollmentHostError::InvariantViolation)?;
        channel.send(Zeroizing::new(accepted))?;
        Ok(ClaimedBrokerEffect {
            operation_id,
            binding,
        })
    }

    /// Accepts only the exact bound possible-effect diagnostic after a claim.
    pub(super) fn observe_effect_from_channel<
        S: ProviderCredentialEnrollmentStore,
        C: CredentialBrokerChannel,
    >(
        &self,
        claimed: ClaimedBrokerEffect,
        store: &S,
        channel: &mut C,
    ) -> Result<CredentialOperationSnapshot, ProviderCredentialEnrollmentHostError> {
        let frame = channel.receive()?;
        let CredentialBrokerFrame::NativeEffectObserved {
            operation_id,
            binding,
        } = CredentialBrokerFrameCodec::decode(&frame)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?
        else {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        };
        if operation_id != claimed.operation_id || binding != claimed.binding {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        store
            .mark_native_effect_observed(ObserveNativeEffect::new(
                operation_id,
                CredentialNativeEffectDisposition::PossibleEffect,
            ))
            .map_err(map_store)
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
