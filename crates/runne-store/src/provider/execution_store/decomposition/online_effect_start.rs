impl SqliteProviderExecutionStore {
    /// Atomically records the V26 online binding and the pre-effect audit.
    pub(crate) fn start_online_effect(
        &self,
        launch: &ProviderRuntimeLaunchCapability,
        claim: &ProviderDispatchClaim,
        binding: &OnlineEffectStartBinding,
    ) -> Result<ProviderOnlineEffectStartReceipt, ProviderAdmissionError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let mut receipt = start_online_effect(
            &mut connection,
            launch,
            claim,
            binding,
            &self.online_effect_proof,
            || self.now(),
            {
                #[cfg(test)]
                {
                    self.fail_effect_readback.swap(false, Ordering::SeqCst)
                }
                #[cfg(not(test))]
                {
                    false
                }
            },
        )?;
        let database = std::sync::Arc::clone(&self.connection);
        let proof = std::sync::Arc::clone(&self.online_effect_proof);
        let claim = claim.clone();
        let now = std::sync::Arc::clone(&self.now);
        let provider = binding.provider().clone();
        receipt.install_final_send_authority(crate::provider::ProviderFinalSendAuthority::new(
            move || {
                let mut connection = database
                    .lock()
                    .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
                let transaction = connection
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
                let observed = now();
                crate::store::taskrun_provider_start::verify_admitted_running_attempt(
                    &transaction,
                    claim.attempt_id.as_bytes(),
                )
                .map_err(|_| ProviderAdmissionError::AuthorityDenied)?;
                crate::provider::credential_lifecycle::advance_provider_clock(
                    &transaction,
                    &provider,
                    observed,
                )
                .map_err(|_| ProviderAdmissionError::AuthorityDenied)?;
                crate::provider::effect_start::verify_online_final_send(
                    &transaction,
                    &claim,
                    &proof,
                    observed,
                )?;
                transaction
                    .commit()
                    .map_err(|_| ProviderAdmissionError::RepositoryFailure)
            },
        ));
        Ok(receipt)
    }
}
