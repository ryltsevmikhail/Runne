use std::{
    collections::BTreeMap,
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

use super::super::operation_handle::ProviderCredentialOperationHandleIssuer;

#[cfg(all(unix, feature = "desktop-protected"))]
use super::rendezvous::DaemonBrokerAuthority;
#[cfg(unix)]
use super::rendezvous::DaemonOwnedUnixBrokerRendezvous;

/// Process-local one-shot authority for fresh, durable prepared operations.
pub(crate) struct PendingBrokerRendezvousRegistry {
    entries: Arc<Mutex<BTreeMap<CredentialOperationId, PendingEntry>>>,
    handles: ProviderCredentialOperationHandleIssuer,
}

impl Clone for PendingBrokerRendezvousRegistry {
    fn clone(&self) -> Self {
        Self {
            entries: Arc::clone(&self.entries),
            handles: self.handles.duplicate(),
        }
    }
}

const MAX_PENDING: usize = 64;

struct PendingEntry {
    binding: PendingBrokerRendezvousBinding,
    authority_witness: ProviderCredentialBrokerHandoffWitness,
    #[cfg(unix)]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the protected dispatcher consumes the pending endpoint"
        )
    )]
    rendezvous: DaemonOwnedUnixBrokerRendezvous,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct PendingBrokerRendezvousBinding {
    operation_id: CredentialOperationId,
    begin_proof: CredentialBindingDigest,
    owner: CredentialInstallationOwnerId,
    protected_session: [u8; 32],
    tauri_peer: [u8; 32],
    daemon_authority: [u8; 32],
    database_generation: u64,
    supervisor_generation: u64,
    pub(super) release_tuple: CredentialBindingDigest,
    expires_at_high_water: i64,
}

/// Move-only pending rendezvous removed before its current authority is validated.
#[cfg(unix)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the protected dispatcher owns the pending endpoint"
    )
)]
pub(crate) struct PendingBrokerEndpointHandoff {
    binding: PendingBrokerRendezvousBinding,
    authority_witness: ProviderCredentialBrokerHandoffWitness,
    rendezvous: DaemonOwnedUnixBrokerRendezvous,
}

/// Opaque daemon control authority awaiting separate writer peer/release admission.
#[cfg(all(unix, feature = "desktop-protected"))]
pub(crate) struct AwaitingVerifiedWriter {
    pub(super) binding: PendingBrokerRendezvousBinding,
    pub(super) authority: DaemonBrokerAuthority,
    pub(super) transfer_authority: ProviderCredentialBrokerTransferAuthority,
}

impl PendingBrokerRendezvousRegistry {
    #[must_use]
    pub(crate) fn new(handles: ProviderCredentialOperationHandleIssuer) -> Self {
        Self {
            entries: Arc::new(Mutex::new(BTreeMap::new())),
            handles,
        }
    }

    /// Registers exactly one daemon-created rendezvous for a fresh durable operation.
    pub(crate) fn register(
        &self,
        operation: &CredentialOperationSnapshot,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
        now_high_water: i64,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        clean_expired(&mut entries, now_high_water);
        let binding =
            PendingBrokerRendezvousBinding::new(operation, authority, proof, now_high_water)?;
        if entries.contains_key(&binding.operation_id) {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        if entries.len() >= MAX_PENDING {
            return Err(ProviderCredentialEnrollmentHostError::Unavailable);
        }
        #[cfg(unix)]
        let rendezvous = DaemonOwnedUnixBrokerRendezvous::create()?;
        #[cfg(not(unix))]
        return Err(ProviderCredentialEnrollmentHostError::Unsupported);
        entries.insert(
            binding.operation_id,
            PendingEntry {
                binding,
                authority_witness: authority.credential_broker_handoff_witness(),
                #[cfg(unix)]
                rendezvous,
            },
        );
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

    /// Removes before validation so failures cannot retain or replay writer authority.
    #[cfg(unix)]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the protected dispatcher begins the one-shot handoff"
        )
    )]
    pub(crate) fn begin_endpoint_handoff(
        &self,
        rendezvous_id: &str,
        operation: &CredentialOperationSnapshot,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
        now_high_water: i64,
    ) -> Result<PendingBrokerEndpointHandoff, ProviderCredentialEnrollmentHostError> {
        let operation_id = self.handles.resolve_broker_rendezvous_id(rendezvous_id)?;
        let entry = self
            .entries
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?
            .remove(&operation_id)
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        if operation_id != operation.operation_id() {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let current =
            PendingBrokerRendezvousBinding::new(operation, authority, proof, now_high_water)?;
        if entry.binding != current || !entry.authority_witness.matches_authority(authority) {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok(PendingBrokerEndpointHandoff {
            binding: entry.binding,
            authority_witness: entry.authority_witness,
            rendezvous: entry.rendezvous,
        })
    }
}

impl PendingBrokerRendezvousBinding {
    pub(super) fn new(
        operation: &CredentialOperationSnapshot,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
        now_high_water: i64,
    ) -> Result<Self, ProviderCredentialEnrollmentHostError> {
        let begin_proof = CredentialBindingDigest::from_measured(*proof.proof_digest())
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let release_tuple =
            CredentialBindingDigest::from_measured(*authority.release_tuple_digest())
                .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let owner = CredentialInstallationOwnerId::from_bytes(*authority.installation_identity())
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let expires_at_high_water = proof.expires_at_high_water();
        if now_high_water <= 0
            || operation.state() != CredentialOperationState::Prepared
            || operation.begin_proof_digest() != begin_proof
            || operation.installation_owner_id() != owner
            || operation.metadata().qualified_release_tuple_digest() != Some(release_tuple)
            || proof.protected_session_binding() != authority.protected_session_id()
            || authority.protected_session_id() == &[0; 32]
            || authority.authenticated_tauri_peer_process() == &[0; 32]
            || authority.daemon_authority_id() == &[0; 32]
            || authority.database_generation() == 0
            || authority.desktop_supervisor_generation() == 0
            || expires_at_high_water <= now_high_water
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok(Self {
            operation_id: operation.operation_id(),
            begin_proof,
            owner,
            protected_session: *authority.protected_session_id(),
            tauri_peer: *authority.authenticated_tauri_peer_process(),
            daemon_authority: *authority.daemon_authority_id(),
            database_generation: authority.database_generation(),
            supervisor_generation: authority.desktop_supervisor_generation(),
            release_tuple,
            expires_at_high_water,
        })
    }

    const fn expired(self, now_high_water: i64) -> bool {
        now_high_water >= self.expires_at_high_water
    }
}

fn clean_expired(entries: &mut BTreeMap<CredentialOperationId, PendingEntry>, now_high_water: i64) {
    entries.retain(|_, entry| !entry.binding.expired(now_high_water));
}

#[cfg(all(unix, feature = "desktop-protected"))]
impl PendingBrokerEndpointHandoff {
    /// Sends the endpoint and keeps only opaque authority pending later native admission.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "writer peer and release admission is deliberately not composed in this slice"
        )
    )]
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
        self.rendezvous
            .handoff_writer_endpoint(transport, &transfer_authority)?;
        let authority = self.rendezvous.take_daemon_authority()?;
        Ok(AwaitingVerifiedWriter {
            binding: self.binding,
            authority,
            transfer_authority,
        })
    }
}

#[cfg(test)]
#[path = "pending_tests.rs"]
mod tests;
