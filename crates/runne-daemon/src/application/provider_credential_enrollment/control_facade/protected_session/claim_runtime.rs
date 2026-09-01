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

pub(crate) struct PendingProtectedBrokerClaim {
    claimed: broker::ClaimedBrokerEffect,
    relay: Option<[u8; runne_provider::CredentialSecretRelayFrameCodec::BYTES]>,
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
        &self,
        measurements: runne_provider::CredentialMeasurementSnapshot,
        continuation: runne_provider::CredentialBindingDigest,
        channel: &mut broker::MacOsCredentialBrokerChannel,
    ) -> Result<PendingProtectedBrokerClaim, ProviderCredentialEnrollmentHostError> {
        let operation_id = self.operation_id()?;
        let operation = self
            .control
            .store
            .load_operation(operation_id)
            .map_err(map_store)?;
        let coordinator =
            broker::ProviderCredentialBroker::new(Arc::new(self.control.measurements.clone()));
        let context = coordinator.claim_issue_context(
            measurements.clone(),
            channel.binding_digest().as_bytes(),
            continuation,
            self.facts.database_generation,
            self.facts.supervisor_generation,
        )?;
        let receipt = coordinator.issue_ticket(
            operation,
            continuation,
            &context,
            60,
            self.control.store.as_ref(),
            channel,
        )?;
        let mut claimed = coordinator.claim_ticket_from_channel(
            receipt,
            continuation,
            self.facts.database_generation,
            self.facts.supervisor_generation,
            measurements,
            self.control.store.as_ref(),
            channel,
        )?;
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

    pub(crate) fn accept_relay_ack(
        &mut self,
        frame: &[u8],
        relay: &[u8],
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        self.lifecycle
            .decode_desktop_relay_ack(frame, self.desktop_sequence, relay)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        self.desktop_sequence = self
            .desktop_sequence
            .checked_add(1)
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        Ok(())
    }

    pub(crate) fn finish_writer(
        &mut self,
        pending: PendingProtectedBrokerClaim,
        channel: &mut broker::MacOsCredentialBrokerChannel,
        now_high_water: i64,
    ) -> Result<ProviderCredentialOperationSnapshotV2, ProviderCredentialEnrollmentHostError> {
        let coordinator =
            broker::ProviderCredentialBroker::new(Arc::new(self.control.measurements.clone()));
        coordinator.observe_effect_from_channel(
            pending.claimed,
            self.control.store.as_ref(),
            channel,
        )?;
        CredentialEnrollmentRecoveryGateway::new(
            self.control.store.as_ref(),
            self.control.readback.as_ref(),
        )
        .reconcile_online(now_high_water)?;
        let operation = self
            .control
            .store
            .load_operation(self.operation_id()?)
            .map_err(map_store)?;
        let lifecycle = self
            .control
            .store
            .lifecycle_snapshot(operation.provider())
            .map_err(map_store)?;
        operation_projection::snapshot(
            operation,
            &self.control.handles,
            lifecycle.readiness_revision().get(),
            &self.control.rendezvous,
            now_high_water,
        )
    }

    pub(crate) fn encode_terminal_snapshot(
        &mut self,
        snapshot: ProviderCredentialOperationSnapshotV2,
    ) -> Result<Vec<u8>, ProviderCredentialEnrollmentHostError> {
        self.encode_snapshot(snapshot)
    }

    fn operation_id(
        &self,
    ) -> Result<runne_provider::CredentialOperationId, ProviderCredentialEnrollmentHostError> {
        self.begun
            .as_ref()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)
            .and_then(|(_, snapshot)| self.control.handles.resolve(snapshot.operation_handle()))
    }
}
