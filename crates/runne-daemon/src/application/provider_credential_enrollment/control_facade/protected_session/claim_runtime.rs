use std::sync::Arc;

use runne_api::{ProviderCredentialEnrollmentHostError, ProviderCredentialOperationSnapshotV2};
use runne_provider::ProviderCredentialEnrollmentStore;

use super::DaemonProtectedCredentialEnrollmentSession;
use crate::application::provider_credential_enrollment::{
    CredentialEnrollmentRecoveryGateway,
    broker::{self, CredentialBrokerChannel},
    effect_authority::map_store,
    operation_projection,
};

mod qualified;
#[cfg(test)]
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
        channel: &mut broker::MacOsCredentialBrokerChannel,
    ) -> Result<PendingProtectedBrokerClaim, ProviderCredentialEnrollmentHostError> {
        self.claim_writer_inner(measurements, continuation, channel, None)
    }

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
        channel: &mut broker::MacOsCredentialBrokerChannel,
        service: Option<&crate::protected_activation::CredentialServiceRuntimeGateway>,
    ) -> Result<PendingProtectedBrokerClaim, ProviderCredentialEnrollmentHostError> {
        let coordinator =
            broker::ProviderCredentialBroker::new(Arc::new(self.control.measurements.clone()));
        let context = coordinator.claim_issue_context(
            measurements.clone(),
            channel.binding_digest().as_bytes(),
            continuation,
            self.facts.database_generation,
            self.facts.supervisor_generation,
        )?;
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
        let authority = self.take_ticket_authority()?;
        let receipt = coordinator.issue_ticket(
            authority,
            continuation,
            &context,
            claim_ticket_ttl_seconds(),
            self.control.store.as_ref(),
            channel,
        )?;
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
        let mut claimed = coordinator.claim_ticket_from_channel(
            receipt,
            continuation,
            self.facts.database_generation,
            self.facts.supervisor_generation,
            measurements,
            self.control.store.as_ref(),
            channel,
        )?;
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
        channel: &mut broker::MacOsCredentialBrokerChannel,
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
        channel: &mut broker::MacOsCredentialBrokerChannel,
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
        channel: &mut broker::MacOsCredentialBrokerChannel,
        now_high_water: i64,
    ) -> Result<
        impl FnOnce() -> Result<
            ProviderCredentialOperationSnapshotV2,
            ProviderCredentialEnrollmentHostError,
        > + Send
        + use<>,
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
        Ok(move || {
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
        })
    }
}

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

#[cfg(test)]
mod tests {
    use runne_provider::CredentialOperationAction;

    #[test]
    fn only_legacy_source_cleanup_skips_the_credential_service_arm() {
        for action in [
            CredentialOperationAction::Pair,
            CredentialOperationAction::Revoke,
            CredentialOperationAction::MigrateLegacy,
            CredentialOperationAction::RetiredVersionCleanup,
            CredentialOperationAction::WriterIdentityMigrationEffect,
            CredentialOperationAction::WriterIdentityMigrationVerify,
        ] {
            assert!(super::requires_service_arm(action));
        }
        assert!(!super::requires_service_arm(
            CredentialOperationAction::LegacySourceCleanup
        ));
    }
}
