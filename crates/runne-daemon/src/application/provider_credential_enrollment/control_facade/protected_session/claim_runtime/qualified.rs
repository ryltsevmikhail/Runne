use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{CredentialBindingDigest, CredentialMeasurementSnapshot};

use super::{DaemonProtectedCredentialEnrollmentSession, PendingProtectedBrokerClaim};
use crate::application::provider_credential_enrollment::broker::{
    self, ProviderCredentialBroker,
};
use crate::application::provider_credential_enrollment::broker::issue::ClaimIssueContext;
use crate::application::provider_credential_enrollment::control_facade::protected_session::qualification::FencedWriterDelivery;

pub(in crate::application::provider_credential_enrollment::control_facade::protected_session) trait QualifiedWriterService<
    C,
>
{
    fn arm_and_handoff(
        &self,
        command: runne_provider::CredentialBrokerCommand,
        channel: &mut C,
    ) -> Result<(), ProviderCredentialEnrollmentHostError>;
}

impl QualifiedWriterService<broker::MacOsCredentialBrokerChannel>
    for crate::protected_activation::CredentialServiceRuntimeGateway
{
    fn arm_and_handoff(
        &self,
        command: runne_provider::CredentialBrokerCommand,
        channel: &mut broker::MacOsCredentialBrokerChannel,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        channel.send_service_handoff(self.arm_mutation(command)?)
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the protected session owns the exact claim inputs"
)]
pub(super) fn claim_fenced_writer(
    session: &mut DaemonProtectedCredentialEnrollmentSession,
    delivery: FencedWriterDelivery,
    coordinator: ProviderCredentialBroker,
    context: ClaimIssueContext,
    measurements: CredentialMeasurementSnapshot,
    continuation: CredentialBindingDigest,
    channel: &mut broker::MacOsCredentialBrokerChannel,
    service: Option<&crate::protected_activation::CredentialServiceRuntimeGateway>,
) -> Result<PendingProtectedBrokerClaim, ProviderCredentialEnrollmentHostError> {
    claim_fenced_writer_on(
        session,
        delivery,
        coordinator,
        context,
        measurements,
        continuation,
        channel,
        service,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the protected session owns the exact claim inputs"
)]
pub(in crate::application::provider_credential_enrollment::control_facade::protected_session) fn claim_fenced_writer_on<
    C,
    S,
>(
    session: &mut DaemonProtectedCredentialEnrollmentSession,
    delivery: FencedWriterDelivery,
    coordinator: ProviderCredentialBroker,
    context: ClaimIssueContext,
    measurements: CredentialMeasurementSnapshot,
    continuation: CredentialBindingDigest,
    channel: &mut C,
    service: Option<&S>,
) -> Result<PendingProtectedBrokerClaim, ProviderCredentialEnrollmentHostError>
where
    C: broker::CredentialBrokerChannel + broker::QualifiedCredentialBrokerChannel,
    S: QualifiedWriterService<C>,
{
    let qualified = delivery.into_writer_exchange()?;
    let service_command = service
        .filter(|_| super::requires_service_arm(qualified.receipt().operation().action()))
        .map(|_| {
            runne_provider::CredentialBrokerCommand::from_operation(
                qualified.receipt().operation(),
                qualified.receipt().ticket_attempt(),
            )
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
        })
        .transpose()?;
    let delivery = qualified.issue_to_writer(
        &coordinator,
        continuation,
        &context,
        session.facts.launch_generation,
        channel,
    )?;
    let mut claimed = delivery.claim(
        &coordinator,
        continuation,
        session.facts.database_generation,
        session.facts.supervisor_generation,
        measurements,
        session.control.store.as_ref(),
        channel,
    )?;
    if let (Some(service), Some(service_command)) = (service, service_command) {
        service.arm_and_handoff(service_command, channel)?;
    }
    let relay = claimed.take_secret_relay()?;
    Ok(PendingProtectedBrokerClaim { claimed, relay })
}
