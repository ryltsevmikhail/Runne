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
        let capability =
            ProviderRuntimeLaunchCapability::from_state(&state, config.lease_ttl_seconds)?;
        transaction
            .commit()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        Ok(capability)
    }

    /// Renews the exact active launch lease without changing its authority revision.
    /// The opaque launch proof fixes the maximum lease duration; renewal is due
    /// only in the final fifth of that lease and never changes budgets or policy.
    pub fn renew_runtime_launch_lease(
        &self,
        launch: &ProviderRuntimeLaunchCapability,
    ) -> Result<bool, ProviderAdmissionError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let now = self.now();
        let state = load_runtime_authority(&transaction)?
            .ok_or(ProviderAdmissionError::AuthorityDenied)?;
        if !state.active {
            return Err(ProviderAdmissionError::AuthorityDenied);
        }
        if !state.capability_allowed || state.capability_revocation_observed {
            return Err(if state.capability_revocation_observed {
                ProviderAdmissionError::CapabilityRevoked
            } else {
                ProviderAdmissionError::CapabilityDenied
            });
        }
        if !state.approval_allowed || state.approval_revocation_observed {
            return Err(if state.approval_revocation_observed {
                ProviderAdmissionError::ApprovalRevoked
            } else {
                ProviderAdmissionError::ApprovalDenied
            });
        }
        launch.verify_state(&state)?;
        let ttl = i64::try_from(launch.lease_ttl_seconds())
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let renewal_window = ttl / 5;
        let current_expiry = state
            .capability_expires_at
            .min(state.approval_expires_at);
        if current_expiry.saturating_sub(now) > renewal_window {
            transaction
                .commit()
                .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
            return Ok(false);
        }
        let unresolved: bool = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM provider_dispatch_attempts WHERE state IN (1, 3, 4, 6)
                    UNION ALL
                    SELECT 1 FROM provider_terminal_outbox WHERE state = 1
                 )",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        if unresolved {
            return Err(ProviderAdmissionError::PostClaimUncertain);
        }
        let expires_at = now
            .checked_add(ttl)
            .ok_or(ProviderAdmissionError::RepositoryFailure)?;
        let updated = transaction
            .execute(
                "UPDATE provider_runtime_authority_state SET
                    capability_expires_at = ?1, approval_expires_at = ?1
                 WHERE id = 1 AND active = 1 AND state_revision = ?2
                   AND runtime_authority_id = ?3 AND database_generation = ?4
                   AND expected_generation = lease_generation
                   AND expected_fencing_token = lease_fencing_token
                   AND capability_allowed = 1 AND approval_allowed = 1
                   AND capability_revocation_observed = 0
                   AND approval_revocation_observed = 0
                   AND capability_expires_at = ?5 AND approval_expires_at = ?6",
                params![
                    expires_at,
                    i64::try_from(state.state_revision)
                        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?,
                    state.runtime_authority_id.as_slice(),
                    i64::try_from(state.database_generation)
                        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?,
                    state.capability_expires_at,
                    state.approval_expires_at,
                ],
            )
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        if updated != 1 {
            return Err(ProviderAdmissionError::StaleFencingToken);
        }
        transaction
            .commit()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        Ok(true)
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
