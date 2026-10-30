use std::sync::Arc;

use runne_api::{ProviderCredentialEnrollmentHostError, ProviderCredentialOperationSnapshotV2};
use runne_provider::ProviderCredentialEnrollmentStore;

use super::DaemonProtectedCredentialEnrollmentSession;
#[cfg(target_os = "macos")]
use crate::application::provider_credential_enrollment::broker::CredentialBrokerChannel as _;
use crate::application::provider_credential_enrollment::{
    CredentialEnrollmentRecoveryGateway, broker, effect_authority::map_store, operation_projection,
};
use crate::protected_activation::linux_pair_diagnostics::record as pair_diag;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod qualified;
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(super) use qualified::{QualifiedWriterService, claim_fenced_writer_on};

pub(crate) struct PendingProtectedBrokerClaim {
    claimed: broker::ClaimedBrokerEffect,
    relay: Option<[u8; runne_provider::CredentialSecretRelayFrameCodec::BYTES]>,
}

pub(crate) struct ReleasedProtectedBrokerClaim {
    claimed: broker::ClaimedBrokerEffect,
}

impl PendingProtectedBrokerClaim {
    pub(crate) const fn relay(&self) -> Option<&[u8]> {
        match &self.relay {
            Some(value) => Some(value),
            None => None,
        }
    }
}

impl DaemonProtectedCredentialEnrollmentSession {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn take_installed_facts(
        &mut self,
    ) -> Result<
        runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
        ProviderCredentialEnrollmentHostError,
    > {
        self.installed_facts
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    pub(crate) fn claim_writer(
        &mut self,
        measurements: runne_provider::CredentialMeasurementSnapshot,
        continuation: runne_provider::CredentialBindingDigest,
        #[cfg(target_os = "macos")] channel: &mut broker::MacOsCredentialBrokerChannel,
        #[cfg(not(target_os = "macos"))] channel: &mut impl broker::CredentialBrokerChannel,
    ) -> Result<PendingProtectedBrokerClaim, ProviderCredentialEnrollmentHostError> {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        return self.claim_writer_inner(measurements, continuation, channel, None);
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        self.claim_writer_inner(measurements, continuation, channel)
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn claim_writer_with_service(
        &mut self,
        measurements: runne_provider::CredentialMeasurementSnapshot,
        continuation: runne_provider::CredentialBindingDigest,
        channel: &mut broker::MacOsCredentialBrokerChannel,
        service: &crate::protected_activation::CredentialServiceRuntimeGateway,
    ) -> Result<PendingProtectedBrokerClaim, ProviderCredentialEnrollmentHostError> {
        self.claim_writer_inner(measurements, continuation, channel, Some(service))
    }

    fn claim_writer_inner(
        &mut self,
        measurements: runne_provider::CredentialMeasurementSnapshot,
        continuation: runne_provider::CredentialBindingDigest,
        #[cfg(target_os = "macos")] channel: &mut broker::MacOsCredentialBrokerChannel,
        #[cfg(not(target_os = "macos"))] channel: &mut impl broker::CredentialBrokerChannel,
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))] service: Option<
            &crate::protected_activation::CredentialServiceRuntimeGateway,
        >,
    ) -> Result<PendingProtectedBrokerClaim, ProviderCredentialEnrollmentHostError> {
        let coordinator =
            broker::ProviderCredentialBroker::new(Arc::new(self.control.measurements.clone()));
        let context = coordinator.claim_issue_context(
            measurements.clone(),
            channel.binding_digest().as_bytes(),
            continuation,
            self.facts.database_generation,
            self.facts.supervisor_generation,
        );
        pair_diag("claim_issue_context", context.is_ok());
        let context = context?;
        #[cfg(all(
            target_os = "macos",
            target_arch = "aarch64",
            feature = "desktop-protected"
        ))]
        if let Some(fenced) = self.qualification_fenced.take() {
            return qualified::claim_fenced_writer(
                self,
                fenced.into_writer_delivery()?,
                coordinator,
                context,
                measurements,
                continuation,
                channel,
                service,
            );
        }
        let authority = self.take_ticket_authority();
        pair_diag("claim_ticket_authority", authority.is_ok());
        let authority = authority?;
        let receipt = coordinator.issue_ticket(
            authority,
            continuation,
            &context,
            claim_ticket_ttl_seconds(),
            self.control.store.as_ref(),
            channel,
        );
        pair_diag("claim_issue_ticket", receipt.is_ok());
        let receipt = receipt?;
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let service_command = service
            .as_ref()
            .filter(|_| requires_service_arm(receipt.operation().action()))
            .map(|_| {
                runne_provider::CredentialBrokerCommand::from_operation(
                    receipt.operation(),
                    receipt.ticket_attempt(),
                )
                .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
            })
            .transpose()?;
        let claimed = coordinator.claim_ticket_from_channel(
            receipt,
            continuation,
            self.facts.database_generation,
            self.facts.supervisor_generation,
            measurements,
            self.control.store.as_ref(),
            channel,
        );
        pair_diag("claim_ticket_accept", claimed.is_ok());
        let mut claimed = claimed?;
        self.control
            .rendezvous
            .release_detached_after_claim(claimed.operation_id());
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        if let (Some(service), Some(service_command)) = (service, service_command) {
            let handoff = service.arm_mutation(service_command)?;
            channel.send_service_handoff(handoff)?;
        }
        let relay = claimed.take_secret_relay()?;
        Ok(PendingProtectedBrokerClaim { claimed, relay })
    }

    pub(crate) fn encode_relay(
        &mut self,
        relay: &[u8],
    ) -> Result<Vec<u8>, ProviderCredentialEnrollmentHostError> {
        self.daemon_sequence = self
            .daemon_sequence
            .checked_add(1)
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        self.lifecycle
            .encode_daemon_relay(relay, self.daemon_sequence)
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
    }

    /// Secretless release for one claimed control-only effect of this exact
    /// session: a fresh begun operation or the accepted recovery operation.
    /// The claimed operation id must resolve through the same session identity,
    /// and no relay may exist for a control-only claim.
    pub(crate) fn release_control_only(
        &self,
        pending: PendingProtectedBrokerClaim,
        channel: &mut impl broker::CredentialBrokerChannel,
    ) -> Result<ReleasedProtectedBrokerClaim, ProviderCredentialEnrollmentHostError> {
        if pending.relay.is_some() {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let operation_id = self.operation_id()?;
        if pending.claimed.operation_id() != operation_id {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let coordinator =
            broker::ProviderCredentialBroker::new(Arc::new(self.control.measurements.clone()));
        coordinator.release_control_only_effect(
            &pending.claimed,
            operation_id,
            self.control.store.as_ref(),
            channel,
        )?;
        Ok(ReleasedProtectedBrokerClaim {
            claimed: pending.claimed,
        })
    }

    pub(crate) fn accept_relay_ack(
        &mut self,
        frame: &[u8],
        relay: &[u8],
        pending: PendingProtectedBrokerClaim,
        channel: &mut impl broker::CredentialBrokerChannel,
    ) -> Result<ReleasedProtectedBrokerClaim, ProviderCredentialEnrollmentHostError> {
        self.lifecycle
            .decode_desktop_relay_ack(frame, self.desktop_sequence, relay)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        self.desktop_sequence = self
            .desktop_sequence
            .checked_add(1)
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let coordinator =
            broker::ProviderCredentialBroker::new(Arc::new(self.control.measurements.clone()));
        coordinator.release_claimed_effect_to_channel(&pending.claimed, channel)?;
        Ok(ReleasedProtectedBrokerClaim {
            claimed: pending.claimed,
        })
    }

    pub(crate) fn prepare_writer_readback(
        &mut self,
        released: ReleasedProtectedBrokerClaim,
        channel: &mut impl broker::CredentialBrokerChannel,
        now_high_water: i64,
    ) -> Result<
        Box<
            dyn FnOnce() -> Result<
                    ProviderCredentialOperationSnapshotV2,
                    ProviderCredentialEnrollmentHostError,
                > + Send
                + 'static,
        >,
        ProviderCredentialEnrollmentHostError,
    > {
        let coordinator =
            broker::ProviderCredentialBroker::new(Arc::new(self.control.measurements.clone()));
        coordinator.observe_effect_from_channel(
            released.claimed,
            self.control.store.as_ref(),
            channel,
        )?;
        #[cfg(feature = "test-support")]
        if runne_api::test_support::local_native_enrollment_case()
            == Some(runne_api::test_support::LocalNativeEnrollmentCase::DeathReadback)
        {
            std::process::exit(86);
        }
        let control = Arc::clone(&self.control);
        let operation_id = self.operation_id()?;
        Ok(Box::new(move || {
            CredentialEnrollmentRecoveryGateway::new(
                control.store.as_ref(),
                control.readback.as_ref(),
            )
            .reconcile_online(now_high_water)?;
            let operation = control
                .store
                .load_operation(operation_id)
                .map_err(map_store)?;
            let lifecycle = control
                .store
                .lifecycle_snapshot(operation.provider())
                .map_err(map_store)?;
            operation_projection::snapshot(
                operation,
                &control.handles,
                lifecycle.readiness_revision().get(),
                &control.rendezvous,
                now_high_water,
            )
        }))
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const fn requires_service_arm(action: runne_provider::CredentialOperationAction) -> bool {
    !matches!(
        action,
        runne_provider::CredentialOperationAction::LegacySourceCleanup
    )
}

const fn production_claim_ticket_ttl_seconds() -> i64 {
    60
}

fn claim_ticket_ttl_seconds() -> i64 {
    #[cfg(feature = "test-support")]
    if runne_api::test_support::validated_local_native_enrollment_case_name().is_some() {
        return 180;
    }
    production_claim_ticket_ttl_seconds()
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
#[path = "claim_runtime/tests.rs"]
mod tests;
