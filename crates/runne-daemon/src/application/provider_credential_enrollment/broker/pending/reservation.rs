use super::*;
mod binding;
pub(in crate::application::provider_credential_enrollment::broker) use binding::PendingBrokerRendezvousBinding;
use binding::{ReservedAuthorityBinding, validate_authority};

#[cfg(unix)]
pub(super) struct ReservedTransitionRendezvous {
    authority_witness: ProviderCredentialBrokerHandoffWitness,
    broker_transfer: Option<ProviderCredentialBrokerTransferAuthority>,
    binding: ReservedAuthorityBinding,
    rendezvous: DaemonOwnedUnixBrokerRendezvous,
}

#[cfg(unix)]
pub(crate) struct PendingBrokerRendezvousLease<'a> {
    pub(super) entries: std::sync::MutexGuard<'a, BTreeMap<CredentialOperationId, PendingEntry>>,
    reserved_slot: &'a std::sync::Mutex<Option<ReservedTransitionRendezvous>>,
    reserved: Option<ReservedTransitionRendezvous>,
    begin_proof: CredentialBindingDigest,
    owner: CredentialInstallationOwnerId,
    protected_session: [u8; 32],
    tauri_peer: [u8; 32],
    daemon_authority: [u8; 32],
    database_generation: u64,
    supervisor_generation: u64,
    release_tuple: CredentialBindingDigest,
    expires_at_high_water: i64,
}

/// Serializes the durable replay check with consumption of one transition reservation.
#[cfg(unix)]
pub(crate) struct PendingBrokerAdmissionGate<'a> {
    registry: &'a PendingBrokerRendezvousRegistry,
    entries: std::sync::MutexGuard<'a, BTreeMap<CredentialOperationId, PendingEntry>>,
    now_high_water: i64,
}

impl PendingBrokerRendezvousRegistry {
    /// Reserves the transition-created rendezvous for the exact admitted authority.
    #[cfg(all(test, unix))]
    pub(crate) fn reserve_transition_rendezvous(
        &self,
        rendezvous: DaemonOwnedUnixBrokerRendezvous,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        self.reserve_transition_rendezvous_inner(rendezvous, authority, proof, None)
    }

    pub(crate) fn reserve_transition_rendezvous_with_transfer(
        &self,
        rendezvous: DaemonOwnedUnixBrokerRendezvous,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
        transfer: ProviderCredentialBrokerTransferAuthority,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let witness = authority.credential_broker_handoff_witness();
        if !transfer.matches_handoff(&witness, authority.protected_session_id()) {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        self.reserve_transition_rendezvous_inner(rendezvous, authority, proof, Some(transfer))
    }

    fn reserve_transition_rendezvous_inner(
        &self,
        rendezvous: DaemonOwnedUnixBrokerRendezvous,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
        broker_transfer: Option<ProviderCredentialBrokerTransferAuthority>,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let mut reserved = self
            .reserved
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        if reserved.is_some() {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        *reserved = Some(ReservedTransitionRendezvous {
            authority_witness: authority.credential_broker_handoff_witness(),
            broker_transfer,
            binding: ReservedAuthorityBinding::new(authority, proof),
            rendezvous,
        });
        Ok(())
    }

    pub(crate) fn discard_transition_rendezvous(
        &self,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let mut reserved = self
            .reserved
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        let candidate = reserved
            .as_ref()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        if !candidate.authority_witness.matches_authority(authority)
            || candidate.binding != ReservedAuthorityBinding::new(authority, proof)
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        reserved.take();
        Ok(())
    }

    #[cfg(all(test, unix))]
    pub(crate) fn reserve_new_for_test(
        &self,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
    ) {
        self.reserve_transition_rendezvous(
            DaemonOwnedUnixBrokerRendezvous::create().unwrap(),
            authority,
            proof,
        )
        .unwrap();
    }

    /// Acquires the begin gate before the durable replay re-check.
    #[cfg(unix)]
    pub(crate) fn begin_gate(
        &self,
        now_high_water: i64,
    ) -> Result<PendingBrokerAdmissionGate<'_>, ProviderCredentialEnrollmentHostError> {
        if now_high_water <= 0 {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        clean_expired(&mut entries, now_high_water);
        Ok(PendingBrokerAdmissionGate {
            registry: self,
            entries,
            now_high_water,
        })
    }
}

#[cfg(unix)]
impl<'a> PendingBrokerAdmissionGate<'a> {
    /// Consumes only the exact reserved transition after durable replay was ruled out.
    pub(crate) fn preflight(
        self,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
    ) -> Result<PendingBrokerRendezvousLease<'a>, ProviderCredentialEnrollmentHostError> {
        let now_high_water = self.now_high_water;
        let begin_proof = CredentialBindingDigest::from_measured(*proof.proof_digest())
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let release_tuple =
            CredentialBindingDigest::from_measured(*authority.release_tuple_digest())
                .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let owner = CredentialInstallationOwnerId::from_bytes(*authority.installation_identity())
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        validate_authority(authority, proof, now_high_water)?;
        if self.entries.len() >= MAX_PENDING {
            return Err(ProviderCredentialEnrollmentHostError::Unavailable);
        }
        let mut reserved_slot = self
            .registry
            .reserved
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        let candidate = reserved_slot
            .as_ref()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        if !candidate.authority_witness.matches_authority(authority)
            || candidate.binding != ReservedAuthorityBinding::new(authority, proof)
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let reserved = reserved_slot
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        Ok(PendingBrokerRendezvousLease {
            entries: self.entries,
            reserved_slot: &self.registry.reserved,
            reserved: Some(reserved),
            begin_proof,
            owner,
            protected_session: *authority.protected_session_id(),
            tauri_peer: *authority.authenticated_tauri_peer_process(),
            daemon_authority: *authority.daemon_authority_id(),
            database_generation: authority.database_generation(),
            supervisor_generation: authority.desktop_supervisor_generation(),
            release_tuple,
            expires_at_high_water: proof.expires_at_high_water(),
        })
    }
}

#[cfg(unix)]
impl PendingBrokerRendezvousLease<'_> {
    pub(in crate::application::provider_credential_enrollment) fn commit_fresh(
        self,
        effect: ProviderCredentialEffectAuthority,
    ) -> CredentialOperationSnapshot {
        let operation = effect.consume();
        self.commit_snapshot(&operation);
        operation
    }

    pub(super) fn commit_snapshot(mut self, operation: &CredentialOperationSnapshot) {
        let reserved = self
            .reserved
            .take()
            .expect("a validated reservation remains owned by its move-only lease");
        let binding = PendingBrokerRendezvousBinding {
            operation_id: operation.operation_id(),
            begin_proof: self.begin_proof,
            owner: self.owner,
            protected_session: self.protected_session,
            tauri_peer: self.tauri_peer,
            daemon_authority: self.daemon_authority,
            database_generation: self.database_generation,
            supervisor_generation: self.supervisor_generation,
            release_tuple: self.release_tuple,
            expires_at_high_water: self.expires_at_high_water,
        };
        self.entries.insert(
            binding.operation_id,
            PendingEntry {
                binding,
                authority_witness: reserved.authority_witness,
                broker_transfer: reserved.broker_transfer,
                rendezvous: reserved.rendezvous,
            },
        );
    }
}

#[cfg(unix)]
impl Drop for PendingBrokerRendezvousLease<'_> {
    fn drop(&mut self) {
        let Some(reserved) = self.reserved.take() else {
            return;
        };
        let Ok(mut slot) = self.reserved_slot.lock() else {
            return;
        };
        if slot.is_none() {
            *slot = Some(reserved);
        }
    }
}
