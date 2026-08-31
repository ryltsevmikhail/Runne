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
        start_online_effect(
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
        )
    }
}
