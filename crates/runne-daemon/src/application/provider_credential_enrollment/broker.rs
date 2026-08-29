use std::sync::Arc;

use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{
    ClaimCredentialOperation, CredentialBindingDigest, CredentialBrokerFrame,
    CredentialBrokerFrameCodec, CredentialEnrollmentMeasurementAuthority,
    CredentialMeasurementSnapshot, CredentialNativeEffectDisposition, CredentialOperationId,
    CredentialOperationSnapshot, CredentialSecretClaimOffer, CredentialSecretPublication,
    IssuedCredentialTicketAttempt, ObserveNativeEffect, ProviderCredentialEnrollmentStore,
};
use zeroize::Zeroizing;

use super::effect_authority::map_store;

pub(crate) mod issue;
pub(super) mod pending;
#[cfg(all(unix, feature = "desktop-protected"))]
mod pending_writer;
#[cfg(unix)]
mod rendezvous;
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
    /// Exact measured binding for the authenticated, daemon-owned control channel.
    fn binding_digest(&self) -> CredentialBindingDigest;

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

/// Move-only authority for the one post-claim possible-effect diagnostic.
#[must_use = "the writer effect diagnostic must be consumed or reconciled after a claim"]
pub(super) struct ClaimedBrokerEffect {
    operation_id: CredentialOperationId,
    binding: CredentialBindingDigest,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "publication handoff follows in the next sealed-relay slice"
        )
    )]
    publication: Option<CredentialSecretPublication>,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "publication handoff follows in the next sealed-relay slice"
        )
    )]
    publication_taken: bool,
}

pub(super) struct AcceptedBrokerClaim {
    acknowledgement: Vec<u8>,
    pending_publication: Option<CredentialSecretClaimOffer>,
}

impl AcceptedBrokerClaim {
    #[cfg(test)]
    pub(super) fn acknowledgement(&self) -> &[u8] {
        &self.acknowledgement
    }
}

impl ClaimedBrokerEffect {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "publication handoff follows in the next sealed-relay slice"
        )
    )]
    pub(super) fn take_secret_publication(
        &mut self,
    ) -> Result<Option<CredentialSecretPublication>, ProviderCredentialEnrollmentHostError> {
        if self.publication_taken {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        self.publication_taken = true;
        Ok(self.publication.take())
    }
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
        let publication = accepted
            .pending_publication
            .map(|offer| channel.sign_publication(offer))
            .transpose()?;
        Ok(ClaimedBrokerEffect {
            operation_id,
            binding,
            publication,
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
