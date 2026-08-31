use runne_secure_store::ProviderJournalKeyring;
use std::sync::MutexGuard;

impl SqliteProviderExecutionStore {
    /// Arms online effect authorization from the exact durable active journal key.
    pub fn install_online_effect_proof_capability(
        &self,
        keyring: &dyn ProviderJournalKeyring,
        binding: ProviderJournalKeyBinding,
    ) -> Result<(), ProviderAdmissionError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let capability = OnlineEffectProofCapabilitySet::load(&transaction, keyring, binding)?;
        capability.ensure_current_active(&transaction)?;
        let mut state = self.online_effect_proof.lock()?;
        if state.is_some() {
            return Err(ProviderAdmissionError::AuthorityDenied);
        }
        transaction
            .commit()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        *state = Some(capability);
        Ok(())
    }

    pub(super) fn online_effect_proof(
        &self,
        connection: &Connection,
    ) -> Result<MutexGuard<'_, Option<OnlineEffectProofCapabilitySet>>, ProviderAdmissionError> {
        let state = self.online_effect_proof.lock()?;
        state
            .as_ref()
            .ok_or(ProviderAdmissionError::AuthorityDenied)?
            .ensure_current_active(connection)?;
        Ok(state)
    }
}
