impl SqliteProviderExecutionStore {
    /// Installs or advances runtime-owned authority state.
    pub fn install_runtime_authority(
        &self,
        config: &ProviderRuntimeAuthorityConfig,
    ) -> Result<(), ProviderAdmissionError> {
        self.install_runtime_authority_inner(config, false)
    }

    /// Installs authority and advances its worker lease atomically.
    pub fn install_runtime_authority_and_advance_worker_lease(
        &self,
        config: &ProviderRuntimeAuthorityConfig,
    ) -> Result<(), ProviderAdmissionError> {
        self.install_runtime_authority_inner(config, true)
    }

    fn install_runtime_authority_inner(
        &self,
        config: &ProviderRuntimeAuthorityConfig,
        advance_lease: bool,
    ) -> Result<(), ProviderAdmissionError> {
        config.validate()?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        install_runtime_authority_in_transaction(
            &transaction,
            config,
            self.now(),
            advance_lease,
        )?;
        if advance_lease {
            advance_worker_lease_in_transaction(
                &transaction,
                config.generation,
                config.fencing_token,
            )?;
        }
        transaction
            .commit()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)
    }

    /// Atomically activates one exact runtime launch and returns its opaque proof.
    pub fn activate_runtime_launch(
        &self,
        config: &ProviderRuntimeAuthorityConfig,
    ) -> Result<ProviderRuntimeLaunchCapability, ProviderAdmissionError> {
        config.validate()?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        install_runtime_authority_in_transaction(&transaction, config, self.now(), true)?;
        advance_worker_lease_in_transaction(&transaction, config.generation, config.fencing_token)?;
        let state =
            load_runtime_authority(&transaction)?.ok_or(ProviderAdmissionError::AuthorityDenied)?;
        let capability = ProviderRuntimeLaunchCapability::from_state(&state)?;
        transaction
            .commit()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        Ok(capability)
    }

    /// Advances only the worker lease projection, used by supervisor recovery.
    pub fn advance_worker_lease(
        &self,
        generation: u64,
        fencing_token: u64,
    ) -> Result<(), ProviderAdmissionError> {
        if generation == 0 || fencing_token == 0 {
            return Err(ProviderAdmissionError::StaleFencingToken);
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        advance_worker_lease_in_transaction(&transaction, generation, fencing_token)?;
        transaction
            .commit()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)
    }
}
