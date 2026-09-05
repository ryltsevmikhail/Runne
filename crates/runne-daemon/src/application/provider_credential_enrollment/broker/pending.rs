use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

use runne_api::{
    ProviderCredentialBaseRequestAuthority, ProviderCredentialBrokerHandoffWitness,
    ProviderCredentialBrokerTransferAuthority, ProviderCredentialEnrollmentHostError,
    ProviderCredentialIntentConsumptionProof,
};
use runne_provider::{
    CredentialBindingDigest, CredentialInstallationOwnerId, CredentialOperationId,
    CredentialOperationSnapshot, CredentialOperationState,
};

use super::super::{
    ProviderCredentialEffectAuthority, operation_handle::ProviderCredentialOperationHandleIssuer,
};
#[cfg(unix)]
pub(crate) mod recovery;
mod reservation;
pub(in crate::application::provider_credential_enrollment) use reservation::PendingBrokerAdmissionGate;
pub(in crate::application::provider_credential_enrollment::broker) use reservation::PendingBrokerRendezvousBinding;
use reservation::ReservedTransitionRendezvous;

#[cfg(all(unix, feature = "desktop-protected"))]
use super::rendezvous::DaemonBrokerAuthority;
#[cfg(unix)]
use super::rendezvous::DaemonOwnedUnixBrokerRendezvous;

/// Process-local one-shot authority for fresh, durable prepared operations.
pub(crate) struct PendingBrokerRendezvousRegistry {
    entries: Arc<Mutex<BTreeMap<CredentialOperationId, PendingEntry>>>,
    #[cfg(unix)]
    detached: Arc<Mutex<BTreeSet<CredentialOperationId>>>,
    #[cfg(unix)]
    reserved: Arc<Mutex<Option<ReservedTransitionRendezvous>>>,
    handles: ProviderCredentialOperationHandleIssuer,
}

impl Clone for PendingBrokerRendezvousRegistry {
    fn clone(&self) -> Self {
        Self {
            entries: Arc::clone(&self.entries),
            #[cfg(unix)]
            detached: Arc::clone(&self.detached),
            #[cfg(unix)]
            reserved: Arc::clone(&self.reserved),
            handles: self.handles.duplicate(),
        }
    }
}

const MAX_PENDING: usize = 64;

struct PendingEntry {
    binding: PendingBrokerRendezvousBinding,
    authority_witness: ProviderCredentialBrokerHandoffWitness,
    broker_transfer: Option<ProviderCredentialBrokerTransferAuthority>,
    #[cfg(unix)]
    rendezvous: DaemonOwnedUnixBrokerRendezvous,
}

/// Move-only pending rendezvous removed before its current authority is validated.
#[cfg(unix)]
pub(crate) struct PendingBrokerEndpointHandoff {
    binding: PendingBrokerRendezvousBinding,
    authority_witness: ProviderCredentialBrokerHandoffWitness,
    broker_transfer: Option<ProviderCredentialBrokerTransferAuthority>,
    rendezvous: DaemonOwnedUnixBrokerRendezvous,
}

/// Opaque daemon control authority awaiting separate writer peer/release admission.
#[cfg(all(unix, feature = "desktop-protected"))]
pub(crate) struct AwaitingVerifiedWriter {
    pub(super) binding: PendingBrokerRendezvousBinding,
    pub(super) authority: DaemonBrokerAuthority,
    pub(super) transfer_authority: ProviderCredentialBrokerTransferAuthority,
    pub(super) handoff: runne_platform_desktop::provider_credential_broker::VerifiedDaemonWriterEndpointHandoffFacts,
}

impl PendingBrokerRendezvousRegistry {
    #[must_use]
    pub(crate) fn new(handles: ProviderCredentialOperationHandleIssuer) -> Self {
        Self {
            entries: Arc::new(Mutex::new(BTreeMap::new())),
            #[cfg(unix)]
            detached: Arc::new(Mutex::new(BTreeSet::new())),
            #[cfg(unix)]
            reserved: Arc::new(Mutex::new(None)),
            handles,
        }
    }

    /// Registers exactly one daemon-created rendezvous for a fresh durable operation.
    #[cfg(test)]
    pub(crate) fn register(
        &self,
        operation: &CredentialOperationSnapshot,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
        now_high_water: i64,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let binding =
            PendingBrokerRendezvousBinding::new(operation, authority, proof, now_high_water)?;
        let lease = self
            .begin_gate(now_high_water)?
            .preflight(authority, proof)?;
        if lease.entries.contains_key(&binding.operation_id) {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        #[cfg(not(unix))]
        return Err(ProviderCredentialEnrollmentHostError::Unsupported);
        lease.commit_snapshot(operation);
        Ok(())
    }

    /// Reports only an unexpired, process-local rendezvous entry.
    pub(crate) fn has_live(
        &self,
        operation_id: CredentialOperationId,
        now_high_water: i64,
    ) -> bool {
        if now_high_water <= 0 {
            return false;
        }
        let Ok(mut entries) = self.entries.lock() else {
            return false;
        };
        clean_expired(&mut entries, now_high_water);
        entries.contains_key(&operation_id)
    }

    /// Validates under lock before consuming the exact one-shot authority.
    #[cfg(unix)]
    pub(crate) fn begin_endpoint_handoff(
        &self,
        rendezvous_id: &str,
        operation: &CredentialOperationSnapshot,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
        now_high_water: i64,
    ) -> Result<PendingBrokerEndpointHandoff, ProviderCredentialEnrollmentHostError> {
        let operation_id = self.handles.resolve_broker_rendezvous_id(rendezvous_id)?;
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        if operation_id != operation.operation_id() {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let current = PendingBrokerRendezvousBinding::for_handoff(
            operation,
            authority,
            proof,
            now_high_water,
        )?;
        let entry = entries
            .get(&operation_id)
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        if entry.binding != current || !entry.authority_witness.matches_authority(authority) {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let mut detached = self
            .detached
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        if !detached.insert(operation_id) {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let entry = entries
            .remove(&operation_id)
            .ok_or(ProviderCredentialEnrollmentHostError::InvariantViolation)?;
        Ok(PendingBrokerEndpointHandoff {
            binding: entry.binding,
            authority_witness: entry.authority_witness,
            broker_transfer: entry.broker_transfer,
            rendezvous: entry.rendezvous,
        })
    }

    /// Clears the process-local handoff tombstone only after durable claim.
    #[cfg(unix)]
    pub(crate) fn release_detached_after_claim(&self, operation_id: CredentialOperationId) {
        if let Ok(mut detached) = self.detached.lock() {
            detached.remove(&operation_id);
        }
    }
}

fn clean_expired(entries: &mut BTreeMap<CredentialOperationId, PendingEntry>, now_high_water: i64) {
    entries.retain(|_, entry| !entry.binding.expired(now_high_water));
}

#[cfg(unix)]
impl PendingBrokerEndpointHandoff {
    pub(crate) const fn operation_id(&self) -> CredentialOperationId {
        self.binding.operation_id
    }

    pub(crate) fn rendezvous_facts(&self) -> ([u8; 32], [u8; 32]) {
        (
            self.rendezvous.channel_binding(),
            self.rendezvous.publication_public_key(),
        )
    }

    #[cfg(test)]
    pub(crate) fn matches_safe_operation_for_test(
        &self,
        snapshot: &runne_api::ProviderCredentialOperationSnapshotV2,
        handles: &ProviderCredentialOperationHandleIssuer,
    ) -> bool {
        handles.resolve(snapshot.operation_handle()).ok() == Some(self.binding.operation_id)
    }
}

#[cfg(all(unix, feature = "desktop-protected"))]
impl PendingBrokerEndpointHandoff {
    pub(crate) fn take_broker_transfer(
        &mut self,
    ) -> Option<ProviderCredentialBrokerTransferAuthority> {
        self.broker_transfer.take()
    }

    /// Sends the endpoint and keeps only opaque authority pending later native admission.
    pub(crate) fn send_endpoint(
        mut self,
        transport: std::os::unix::net::UnixStream,
        transfer_authority: ProviderCredentialBrokerTransferAuthority,
    ) -> Result<AwaitingVerifiedWriter, ProviderCredentialEnrollmentHostError> {
        if !transfer_authority
            .matches_handoff(&self.authority_witness, &self.binding.protected_session)
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let handoff = self
            .rendezvous
            .handoff_writer_endpoint(transport, &transfer_authority)?;
        let authority = self.rendezvous.take_daemon_authority()?;
        Ok(AwaitingVerifiedWriter {
            binding: self.binding,
            authority,
            transfer_authority,
            handoff,
        })
    }
}

#[cfg(test)]
#[path = "pending_tests.rs"]
mod tests;
