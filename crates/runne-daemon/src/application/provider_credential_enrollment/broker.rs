use std::sync::Arc;

use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{
    ClaimCredentialOperation, CredentialBindingDigest, CredentialBrokerFrame,
    CredentialBrokerFrameCodec, CredentialEnrollmentMeasurementAuthority,
    CredentialMeasurementSnapshot, CredentialNativeEffectDisposition, CredentialOperationSnapshot,
    CredentialSecretClaimOffer, CredentialSecretPublication, IssuedCredentialTicketAttempt,
    ObserveNativeEffect, ProviderCredentialEnrollmentStore,
};
use zeroize::Zeroizing;

use super::effect_authority::map_store;
mod claimed_effect;
mod effect_release;
pub(super) use claimed_effect::{AcceptedBrokerClaim, ClaimedBrokerEffect};
pub(crate) mod issue;
pub(super) mod pending;
#[cfg(all(unix, feature = "desktop-protected"))]
mod pending_writer;
#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    feature = "desktop-protected"
))]
mod qualified_exchange;
#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    feature = "desktop-protected"
))]
pub(crate) use qualified_exchange::{FencedWriterExchange, QualifiedIssuedTicket};
#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    feature = "desktop-protected"
))]
pub(super) use qualified_exchange::{QualifiedCredentialBrokerChannel, QualifiedIssueTransmission};
#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    feature = "desktop-protected"
))]
mod qualified_issue;
#[cfg(unix)]
pub(crate) mod rendezvous;
#[cfg(all(unix, feature = "desktop-protected"))]
pub(super) mod unix;
#[cfg(all(target_os = "macos", feature = "desktop-protected"))]
pub(crate) use unix::MacOsCredentialBrokerChannel;
#[cfg(test)]
pub(crate) mod writer_session_test_support;

#[cfg(all(unix, feature = "desktop-protected"))]
pub(crate) use pending::{AwaitingVerifiedWriter, PendingBrokerEndpointHandoff};
#[cfg(all(unix, target_os = "macos", feature = "desktop-protected"))]
pub(crate) use pending_writer::VerifiedMacOsWriterWithDaemonKillCapability;
#[cfg(all(unix, feature = "desktop-protected"))]
pub(crate) use pending_writer::VerifiedWriterAwaitingDaemonKillCapability;

/// Authenticated inherited control channel; Task 11 owns its platform adapters.
pub(crate) trait CredentialBrokerChannel {
    /// Exact measured binding for the authenticated, daemon-owned control channel.
    fn binding_digest(&self) -> CredentialBindingDigest;

    /// Sends the first ticket only after binding its session attestation.
    fn send_issue(
        &mut self,
        receipt: &IssuedCredentialTicketAttempt,
        frame: CredentialBrokerFrame,
    ) -> Result<(), ProviderCredentialEnrollmentHostError>;

    /// Sends exactly one canonical broker frame to the authenticated writer endpoint.
    fn send(
        &mut self,
        frame: Zeroizing<Vec<u8>>,
    ) -> Result<(), ProviderCredentialEnrollmentHostError>;

    /// Receives the one writer response admitted by the surrounding exchange.
    fn receive(&mut self) -> Result<Zeroizing<Vec<u8>>, ProviderCredentialEnrollmentHostError>;

    /// Consumes the channel-owned signer for exactly one inert publication.
    fn sign_publication(
        &mut self,
        offer: CredentialSecretClaimOffer,
    ) -> Result<CredentialSecretPublication, ProviderCredentialEnrollmentHostError>;
}

/// Daemon coordinator for digest-first credential-ticket issuance.
pub(super) struct ProviderCredentialBroker {
    measurements: Arc<CredentialEnrollmentMeasurementAuthority>,
}

impl ProviderCredentialBroker {
    /// Retains the measurement authority paired with the durable lifecycle store.
    pub(super) const fn new(measurements: Arc<CredentialEnrollmentMeasurementAuthority>) -> Self {
        Self { measurements }
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
    ) -> Result<AcceptedBrokerClaim, ProviderCredentialEnrollmentHostError> {
        let expected_operation = receipt.operation().operation_id();
        let expected_attempt = receipt.ticket_attempt();
        let CredentialBrokerFrame::Claim {
            operation_id,
            attempt,
            ticket,
            binding,
            secret_offer,
        } = CredentialBrokerFrameCodec::decode(&frame)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?
        else {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        };
        if operation_id != expected_operation || attempt != expected_attempt {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        if !secret_offer_matches_action(
            receipt.operation().action(),
            receipt.operation().allocated_credential_version().is_some(),
            secret_offer.is_some(),
        ) {
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
        let acknowledgement =
            CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::ClaimAccepted {
                operation_id: expected_operation,
                attempt: expected_attempt,
            })
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?;
        Ok(AcceptedBrokerClaim {
            acknowledgement,
            pending_publication: secret_offer,
        })
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
        if channel.binding_digest() != evidence.broker_channel_binding_digest() {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let operation_id = receipt.operation().operation_id();
        let attempt = receipt.ticket_attempt();
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

pub(super) fn secret_offer_matches_action(
    action: runne_provider::CredentialOperationAction,
    has_allocated_version: bool,
    has_offer: bool,
) -> bool {
    match action {
        runne_provider::CredentialOperationAction::Pair => has_allocated_version && has_offer,
        _ => !has_offer,
    }
}
