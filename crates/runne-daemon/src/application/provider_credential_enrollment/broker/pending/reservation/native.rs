use super::*;

impl PendingBrokerRendezvousRegistry {
    /// Reserves the transition-created rendezvous for the exact admitted authority.
    #[cfg(test)]
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

    #[cfg(test)]
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
}
