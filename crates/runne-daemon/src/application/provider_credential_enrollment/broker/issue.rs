use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{
    AttachCredentialProcess, ClaimCredentialOperation, CredentialBindingDigest,
    CredentialBrokerCommand, CredentialBrokerFrame, CredentialBrokerFrameCodec,
    CredentialEnrollmentError, CredentialMeasurementSnapshot, CredentialOperationSnapshot,
    IssueCredentialTicketDigest, IssuedCredentialTicketAttempt, ProviderCredentialEnrollmentStore,
    RawCredentialTicket,
};
use zeroize::Zeroizing;

use super::{CredentialBrokerChannel, ProviderCredentialBroker};
use crate::application::provider_credential_enrollment::effect_authority::map_store;

/// Complete, authority-issued measurement context required before ticket issuance.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the Task 11 authenticated handoff creates this same-authority issue context"
    )
)]
pub(crate) struct ClaimIssueContext {
    measurements: CredentialMeasurementSnapshot,
    database_generation: u64,
    desktop_supervisor_generation: u64,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the Task 11 authenticated handoff supplies the private issue context"
    )
)]
impl ClaimIssueContext {
    /// Rejects zero generation values before a ticket attempt can be persisted.
    fn new(
        measurements: CredentialMeasurementSnapshot,
        database_generation: u64,
        desktop_supervisor_generation: u64,
    ) -> Result<Self, ProviderCredentialEnrollmentHostError> {
        if database_generation == 0 || desktop_supervisor_generation == 0 {
            return Err(ProviderCredentialEnrollmentHostError::InvalidRequest);
        }
        Ok(Self {
            measurements,
            database_generation,
            desktop_supervisor_generation,
        })
    }
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the Task 11 authenticated handoff invokes the ticket issue seam"
    )
)]
impl ProviderCredentialBroker {
    /// Admits one same-authority measurement context before ticket persistence.
    pub(crate) fn claim_issue_context(
        &self,
        measurements: CredentialMeasurementSnapshot,
        continuation: CredentialBindingDigest,
        database_generation: u64,
        desktop_supervisor_generation: u64,
    ) -> Result<ClaimIssueContext, ProviderCredentialEnrollmentHostError> {
        if measurements.continuation_binding_digest() != continuation {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        self.measurements
            .validate_measurement_snapshot(&measurements)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        ClaimIssueContext::new(
            measurements,
            database_generation,
            desktop_supervisor_generation,
        )
    }

    /// Commits a ticket only with the complete claim context that its writer must echo.
    pub(crate) fn issue_ticket<S: ProviderCredentialEnrollmentStore, C: CredentialBrokerChannel>(
        &self,
        operation: CredentialOperationSnapshot,
        continuation: CredentialBindingDigest,
        context: &ClaimIssueContext,
        ttl_seconds: i64,
        store: &S,
        channel: &mut C,
    ) -> Result<IssuedCredentialTicketAttempt, ProviderCredentialEnrollmentHostError> {
        self.issue_ticket_with_raw(
            RawCredentialTicket::generate(),
            operation,
            continuation,
            context,
            ttl_seconds,
            store,
            channel,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn issue_ticket_with_test_entropy<
        S: ProviderCredentialEnrollmentStore,
        C: CredentialBrokerChannel,
    >(
        &self,
        operation: CredentialOperationSnapshot,
        continuation: CredentialBindingDigest,
        context: &ClaimIssueContext,
        ttl_seconds: i64,
        store: &S,
        channel: &mut C,
        fill: impl FnOnce(&mut [u8; 32]) -> Result<(), ()>,
    ) -> Result<IssuedCredentialTicketAttempt, ProviderCredentialEnrollmentHostError> {
        self.issue_ticket_with_raw(
            RawCredentialTicket::generate_with_test_entropy(fill),
            operation,
            continuation,
            context,
            ttl_seconds,
            store,
            channel,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_ticket_with_raw<S: ProviderCredentialEnrollmentStore, C: CredentialBrokerChannel>(
        &self,
        ticket: Result<RawCredentialTicket, CredentialEnrollmentError>,
        operation: CredentialOperationSnapshot,
        continuation: CredentialBindingDigest,
        context: &ClaimIssueContext,
        ttl_seconds: i64,
        store: &S,
        channel: &mut C,
    ) -> Result<IssuedCredentialTicketAttempt, ProviderCredentialEnrollmentHostError> {
        if context.measurements.continuation_binding_digest() != continuation {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        self.measurements
            .validate_measurement_snapshot(&context.measurements)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
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
        let draft = ClaimCredentialOperation::new(
            receipt.clone(),
            ticket.binding_digest(),
            continuation,
            ticket.binding_digest(),
            context.database_generation,
            context.desktop_supervisor_generation,
        )
        .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?;
        let binding = self
            .measurements
            .measure_claim_operation(&context.measurements, &draft)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let command =
            CredentialBrokerCommand::from_operation(receipt.operation(), receipt.ticket_attempt())
                .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?;
        let frame = Zeroizing::new(
            CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::IssueTicket {
                operation_id: receipt.operation().operation_id(),
                attempt: receipt.ticket_attempt(),
                ticket,
                binding,
                command,
            })
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
        );
        channel.send(frame)?;
        Ok(receipt)
    }
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the Task 11 authenticated handoff reaches entropy mapping through issue_ticket"
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
