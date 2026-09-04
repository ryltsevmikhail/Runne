use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{
    AttachCredentialProcess, ClaimCredentialOperation, CredentialBindingDigest,
    CredentialBrokerCommand, CredentialBrokerFrame, CredentialEnrollmentError,
    CredentialMeasurementSnapshot, CredentialOperationSnapshot, IssueCredentialTicketDigest,
    IssuedCredentialTicketAttempt, ProviderCredentialEnrollmentStore, RawCredentialTicket,
};

use super::{CredentialBrokerChannel, ProviderCredentialBroker};
use crate::application::provider_credential_enrollment::effect_authority::map_store;

/// Recovery requires the move-only store witness, never a metadata snapshot.
pub(crate) enum CredentialTicketAuthority {
    Intent(Box<CredentialOperationSnapshot>),
    Recovery(Box<runne_provider::AcceptedCredentialCleanupRecovery>),
}

impl From<CredentialOperationSnapshot> for CredentialTicketAuthority {
    fn from(value: CredentialOperationSnapshot) -> Self {
        Self::Intent(Box::new(value))
    }
}

impl From<runne_provider::AcceptedCredentialCleanupRecovery> for CredentialTicketAuthority {
    fn from(value: runne_provider::AcceptedCredentialCleanupRecovery) -> Self {
        Self::Recovery(Box::new(value))
    }
}

/// Complete, authority-issued measurement context required before ticket issuance.
pub(crate) struct ClaimIssueContext {
    measurements: CredentialMeasurementSnapshot,
    channel_binding: [u8; 32],
    database_generation: u64,
    desktop_supervisor_generation: u64,
}

impl ClaimIssueContext {
    /// Rejects zero generation values before a ticket attempt can be persisted.
    fn new(
        measurements: CredentialMeasurementSnapshot,
        channel_binding: [u8; 32],
        database_generation: u64,
        desktop_supervisor_generation: u64,
    ) -> Result<Self, ProviderCredentialEnrollmentHostError> {
        if channel_binding == [0; 32]
            || database_generation == 0
            || desktop_supervisor_generation == 0
        {
            return Err(ProviderCredentialEnrollmentHostError::InvalidRequest);
        }
        Ok(Self {
            measurements,
            channel_binding,
            database_generation,
            desktop_supervisor_generation,
        })
    }
}

impl ProviderCredentialBroker {
    /// Admits one same-authority measurement context before ticket persistence.
    pub(crate) fn claim_issue_context(
        &self,
        measurements: CredentialMeasurementSnapshot,
        channel_binding: [u8; 32],
        continuation: CredentialBindingDigest,
        database_generation: u64,
        desktop_supervisor_generation: u64,
    ) -> Result<ClaimIssueContext, ProviderCredentialEnrollmentHostError> {
        if measurements.continuation_binding_digest() != continuation
            || CredentialBindingDigest::from_measured(channel_binding)
                .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?
                != measurements.broker_channel_binding_digest()
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        self.measurements
            .validate_measurement_snapshot(&measurements)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        ClaimIssueContext::new(
            measurements,
            channel_binding,
            database_generation,
            desktop_supervisor_generation,
        )
    }

    /// Commits a ticket only with the complete claim context that its writer must echo.
    pub(crate) fn issue_ticket<S: ProviderCredentialEnrollmentStore, C: CredentialBrokerChannel>(
        &self,
        operation: impl Into<CredentialTicketAuthority>,
        continuation: CredentialBindingDigest,
        context: &ClaimIssueContext,
        ttl_seconds: i64,
        store: &S,
        channel: &mut C,
    ) -> Result<IssuedCredentialTicketAttempt, ProviderCredentialEnrollmentHostError> {
        self.issue_ticket_with_raw(
            generate_ticket(),
            operation.into(),
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
            operation.into(),
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
        authority: CredentialTicketAuthority,
        continuation: CredentialBindingDigest,
        context: &ClaimIssueContext,
        ttl_seconds: i64,
        store: &S,
        channel: &mut C,
    ) -> Result<IssuedCredentialTicketAttempt, ProviderCredentialEnrollmentHostError> {
        if context.measurements.continuation_binding_digest() != continuation
            || channel.binding_digest() != context.measurements.broker_channel_binding_digest()
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        self.measurements
            .validate_measurement_snapshot(&context.measurements)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let ticket = ticket.map_err(map_ticket_generation)?;
        let operation = match authority {
            CredentialTicketAuthority::Intent(operation) => store
                .attach_process(
                    AttachCredentialProcess::new(operation.operation_id(), continuation)
                        .map_err(|_| ProviderCredentialEnrollmentHostError::InvalidRequest)?,
                )
                .map_err(map_store)?,
            CredentialTicketAuthority::Recovery(accepted) => {
                self.measurements
                    .validate_cleanup_recovery_measurements(
                        &accepted,
                        &context.measurements,
                        context.database_generation,
                        context.desktop_supervisor_generation,
                    )
                    .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
                store
                    .attach_cleanup_recovery(*accepted)
                    .map_err(map_store)?
            }
        };
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
        let frame = CredentialBrokerFrame::IssueTicket {
            operation_id: receipt.operation().operation_id(),
            attempt: receipt.ticket_attempt(),
            ticket,
            channel_binding: context.channel_binding,
            binding,
            command,
        };
        channel.send_issue(&receipt, frame)?;
        Ok(receipt)
    }
}

fn generate_ticket() -> Result<RawCredentialTicket, CredentialEnrollmentError> {
    #[cfg(feature = "test-support")]
    if runne_api::test_support::local_native_enrollment_case()
        == Some(runne_api::test_support::LocalNativeEnrollmentCase::Leakage)
    {
        return RawCredentialTicket::generate_with_test_entropy(|bytes| {
            bytes.fill(0xa7);
            Ok(())
        });
    }
    RawCredentialTicket::generate()
}

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
