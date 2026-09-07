use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{
    CredentialBindingDigest, CredentialBrokerFrame, CredentialMeasurementSnapshot,
    CredentialOperationId, IssuedCredentialTicketAttempt, ProviderCredentialEnrollmentStore,
    RawCredentialTicket,
};
use zeroize::Zeroizing;

use super::{ClaimedBrokerEffect, CredentialBrokerChannel, ProviderCredentialBroker};
use crate::application::provider_credential_enrollment::effect_authority::map_store;
use crate::protected_activation::control_v3::initial_exchange::qualification_fence::WriterAdmissionBundle;

#[cfg(test)]
mod source_boundary_tests;

/// Private post-fence owner of the one original ticket and durable receipt.
pub(crate) struct QualifiedIssuedTicket {
    ticket: RawCredentialTicket,
    issued: IssuedCredentialTicketAttempt,
}

/// Sole post-fence owner retained until the channel begins exact V2 signing.
pub(crate) struct FencedWriterExchange {
    qualified: QualifiedIssuedTicket,
    admission: WriterAdmissionBundle,
}

/// Unforgeable input consumed only by a qualified channel implementation.
pub(crate) struct QualifiedIssueTransmission {
    issued: IssuedCredentialTicketAttempt,
    frame: CredentialBrokerFrame,
    launch_generation: u64,
    admission: WriterAdmissionBundle,
}

/// Post-signing claim authority; constructed only after channel issue succeeds.
pub(in crate::application::provider_credential_enrollment) struct QualifiedWriterDelivery {
    issued: IssuedCredentialTicketAttempt,
}

impl QualifiedIssuedTicket {
    pub(in crate::application::provider_credential_enrollment::broker) const fn new(
        ticket: RawCredentialTicket,
        issued: IssuedCredentialTicketAttempt,
    ) -> Self {
        Self { ticket, issued }
    }

    pub(crate) const fn receipt(&self) -> &IssuedCredentialTicketAttempt {
        &self.issued
    }

    pub(super) fn into_qualified_issue_members(
        self,
    ) -> (RawCredentialTicket, IssuedCredentialTicketAttempt) {
        (self.ticket, self.issued)
    }
}

impl FencedWriterExchange {
    pub(crate) const fn from_postcommit(
        qualified: QualifiedIssuedTicket,
        admission: WriterAdmissionBundle,
    ) -> Self {
        Self {
            qualified,
            admission,
        }
    }

    pub(in crate::application::provider_credential_enrollment) const fn receipt(
        &self,
    ) -> &IssuedCredentialTicketAttempt {
        self.qualified.receipt()
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::application::provider_credential_enrollment) fn issue_to_writer<C>(
        self,
        broker: &ProviderCredentialBroker,
        continuation: CredentialBindingDigest,
        context: &crate::application::provider_credential_enrollment::broker::issue::ClaimIssueContext,
        launch_generation: u64,
        channel: &mut C,
    ) -> Result<QualifiedWriterDelivery, ProviderCredentialEnrollmentHostError>
    where
        C: CredentialBrokerChannel + QualifiedCredentialBrokerChannel,
    {
        let (issued, frame) = broker
            .issue_frame_for_qualified(self.qualified, continuation, context)?
            .into_qualified_frame_members();
        let delivery = QualifiedWriterDelivery {
            issued: issued.clone(),
        };
        channel.send_qualified_issue(QualifiedIssueTransmission::new(
            issued,
            frame,
            launch_generation,
            self.admission,
        ))?;
        Ok(delivery)
    }
}

impl QualifiedIssueTransmission {
    fn new(
        issued: IssuedCredentialTicketAttempt,
        frame: CredentialBrokerFrame,
        launch_generation: u64,
        admission: WriterAdmissionBundle,
    ) -> Self {
        Self {
            issued,
            frame,
            launch_generation,
            admission,
        }
    }

    pub(in crate::application::provider_credential_enrollment) fn into_signing_parts(
        self,
    ) -> (
        IssuedCredentialTicketAttempt,
        CredentialBrokerFrame,
        u64,
        WriterAdmissionBundle,
    ) {
        (
            self.issued,
            self.frame,
            self.launch_generation,
            self.admission,
        )
    }
}

pub(crate) trait QualifiedCredentialBrokerChannel {
    fn send_qualified_issue(
        &mut self,
        _issue: QualifiedIssueTransmission,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    fn send_qualified_prelude(&mut self) -> Result<(), ProviderCredentialEnrollmentHostError> {
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    fn receive_qualified_ack(&mut self) -> Result<(), ProviderCredentialEnrollmentHostError> {
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    fn qualified_exchange_check(&mut self) -> Result<(), ProviderCredentialEnrollmentHostError> {
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    }
}

impl ProviderCredentialBroker {
    /// Claims one original qualified ticket through prelude, ACK, and acceptance.
    #[allow(clippy::too_many_arguments)]
    fn claim_ticket_from_qualified_channel<
        S: ProviderCredentialEnrollmentStore,
        C: CredentialBrokerChannel + QualifiedCredentialBrokerChannel,
    >(
        &self,
        delivery: QualifiedWriterDelivery,
        continuation: CredentialBindingDigest,
        database_generation: u64,
        desktop_supervisor_generation: u64,
        evidence: CredentialMeasurementSnapshot,
        store: &S,
        channel: &mut C,
    ) -> Result<ClaimedBrokerEffect, ProviderCredentialEnrollmentHostError> {
        let issued = delivery.issued;
        if channel.binding_digest() != evidence.broker_channel_binding_digest() {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        channel.qualified_exchange_check()?;
        let operation_id: CredentialOperationId = issued.operation().operation_id();
        let attempt = issued.ticket_attempt();
        let claim = channel.receive()?;
        channel.qualified_exchange_check()?;
        let accepted = self.claim_ticket(
            issued,
            continuation,
            database_generation,
            desktop_supervisor_generation,
            evidence,
            claim,
            store,
        )?;
        channel.qualified_exchange_check()?;
        let operation = store.load_operation(operation_id).map_err(map_store)?;
        let binding = operation
            .process_release_binding_digest()
            .ok_or(ProviderCredentialEnrollmentHostError::InvariantViolation)?;
        channel.qualified_exchange_check()?;
        channel.send_qualified_prelude()?;
        channel.qualified_exchange_check()?;
        channel.receive_qualified_ack()?;
        channel.qualified_exchange_check()?;
        channel.send(Zeroizing::new(accepted.acknowledgement))?;
        let offer = accepted
            .pending_publication
            .as_ref()
            .map(runne_provider::CredentialSecretOfferCodec::encode);
        let publication = accepted
            .pending_publication
            .map(|offer| channel.sign_publication(offer))
            .transpose()?;
        Ok(ClaimedBrokerEffect {
            operation_id,
            attempt,
            binding,
            publication,
            offer,
            publication_taken: false,
        })
    }
}

impl QualifiedWriterDelivery {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::application::provider_credential_enrollment) fn claim<
        S: ProviderCredentialEnrollmentStore,
        C: CredentialBrokerChannel + QualifiedCredentialBrokerChannel,
    >(
        self,
        broker: &ProviderCredentialBroker,
        continuation: CredentialBindingDigest,
        database_generation: u64,
        desktop_supervisor_generation: u64,
        evidence: CredentialMeasurementSnapshot,
        store: &S,
        channel: &mut C,
    ) -> Result<ClaimedBrokerEffect, ProviderCredentialEnrollmentHostError> {
        broker.claim_ticket_from_qualified_channel(
            self,
            continuation,
            database_generation,
            desktop_supervisor_generation,
            evidence,
            store,
            channel,
        )
    }
}
