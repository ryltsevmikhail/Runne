impl SqliteProviderExecutionStore {
    /// Opens the authoritative runtime database and validates schema V13.
    pub fn open(path: &Path) -> Result<Self, ProviderAdmissionError> {
        Self::open_with_now(path, Arc::new(unix_timestamp))
    }

    fn open_with_now(
        path: &Path,
        now: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Result<Self, ProviderAdmissionError> {
        let path = path
            .to_str()
            .ok_or(ProviderAdmissionError::RepositoryFailure)?;
        let connection =
            open_with_pragmas(path).map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        Self::open_with_connection_and_now(path, connection, now)
    }

    /// Adopts a validated writable connection without reopening its path.
    pub fn open_with_connection(
        path: &str,
        connection: Connection,
    ) -> Result<Self, ProviderAdmissionError> {
        Self::open_with_connection_and_now(path, connection, Arc::new(unix_timestamp))
    }

    fn open_with_connection_and_now(
        path: &str,
        connection: Connection,
        now: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Result<Self, ProviderAdmissionError> {
        apply_migrations(&connection).map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        run_startup_gates(&connection, path)
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        Ok(Self {
            connection: Mutex::new(connection),
            now,
            #[cfg(test)]
            fail_effect_readback: AtomicBool::new(false),
        })
    }

    /// Atomically commits authority state and returns exact durable read-back.
    pub fn issue(
        &self,
        request: &ProviderAuthorityIssueRequest,
    ) -> Result<ProviderAuthorityIssueOutcome, ProviderAdmissionError> {
        request.validate()?;
        let semantic_digest = execution_semantic_digest(request);
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;

        if let Some(existing) =
            load_existing_admission(&transaction, &request.provider_idempotency_key)?
        {
            return if existing.semantic_digest == semantic_digest {
                Ok(ProviderAuthorityIssueOutcome::Existing {
                    state: existing.state,
                })
            } else {
                Err(ProviderAdmissionError::AuthorityConflict)
            };
        }

        let state =
            load_runtime_authority(&transaction)?.ok_or(ProviderAdmissionError::AuthorityDenied)?;
        verify_runtime_authority(&state, request, self.now())?;
        verify_prepared(&transaction, request)?;
        ensure_call_is_unclaimed(&transaction, request.prepared.call_id)?;

        let requested_tokens = request
            .requested_input_tokens
            .checked_add(request.requested_output_tokens)
            .ok_or(ProviderAdmissionError::TokenBudgetDenied)?;
        let available_tokens = state
            .token_budget_limit
            .checked_sub(state.token_budget_reserved)
            .and_then(|available| available.checked_sub(state.token_budget_settled))
            .ok_or(ProviderAdmissionError::TokenBudgetDenied)?;
        if requested_tokens > available_tokens {
            return Err(ProviderAdmissionError::TokenBudgetDenied);
        }
        let available_cost = state
            .cost_budget_limit_micros
            .checked_sub(state.cost_budget_reserved_micros)
            .and_then(|available| available.checked_sub(state.cost_budget_settled_micros))
            .ok_or(ProviderAdmissionError::CostBudgetDenied)?;
        if request.max_cost_micros > available_cost {
            return Err(ProviderAdmissionError::CostBudgetDenied);
        }

        let ids = IssuedIds::random();
        let now = self.now();
        let expires_at = state.capability_expires_at.min(state.approval_expires_at);
        if expires_at <= now {
            return Err(ProviderAdmissionError::AuthorityDenied);
        }
        let claim = ProviderDispatchClaim {
            call_id: request.prepared.call_id,
            attempt_id: DispatchAttemptId::from_bytes(ids.dispatch_attempt_id),
            permit_id: ids.permit_id,
            prepared_digest: request.prepared.prepared_digest,
            render_digest: request.prepared.render_digest,
            profile_digest: request.prepared.profile_digest,
            token_reservation_id: ids.token_reservation_id,
            cost_reservation_id: ids.cost_reservation_id,
            fencing_token: state.expected_fencing_token,
            provider_idempotency_key: request.provider_idempotency_key.clone(),
        };
        let authority_ref =
            ProviderEffectAuthorityRef::new(ids.authority_id, state.state_revision)?;
        commit_issuance(
            &transaction,
            request,
            &state,
            &claim,
            authority_ref,
            semantic_digest,
            requested_tokens,
            now,
            expires_at,
        )?;
        transaction
            .commit()
            .map_err(|_| ProviderAdmissionError::PostClaimUncertain)?;
        durable_readback::load_durable_authority_record(
            &connection,
            request,
            &state,
            claim.attempt_id,
        )
        .map(|admission| ProviderAuthorityIssueOutcome::Winner(Box::new(admission)))
        .map_err(|_| ProviderAdmissionError::PostClaimUncertain)
    }

    /// Revalidates the exact admitted authority and commits the 120-second effect CAS.
    pub fn start_effect(
        &self,
        claim: &ProviderDispatchClaim,
    ) -> Result<ProviderEffectStartReceipt, ProviderAdmissionError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        start_effect(&mut connection, claim, self.now(), || self.now(), {
            #[cfg(test)]
            {
                self.fail_effect_readback.swap(false, Ordering::SeqCst)
            }
            #[cfg(not(test))]
            {
                false
            }
        })
    }

    #[cfg(test)]
    pub(crate) fn fail_next_effect_readback(&self) {
        self.fail_effect_readback.store(true, Ordering::SeqCst);
    }

    /// Installs or advances runtime-owned authority state.
    ///
    /// Aggregate settled and reserved budgets survive authority refresh.
    /// Generation rollback and same-generation fence replacement fail closed.
    pub fn install_runtime_authority(
        &self,
        config: &ProviderRuntimeAuthorityConfig,
    ) -> Result<(), ProviderAdmissionError> {
        config.validate()?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        install_runtime_authority_in_transaction(&transaction, config, self.now(), false)?;
        transaction
            .commit()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)
    }

    /// Installs runtime authority, freezes attempts owned by an older worker
    /// lease, and advances the lease in one crash-safe transaction.
    pub fn install_runtime_authority_and_advance_worker_lease(
        &self,
        config: &ProviderRuntimeAuthorityConfig,
    ) -> Result<(), ProviderAdmissionError> {
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
        transaction
            .commit()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)
    }

    /// Advances only the worker lease projection, used by supervisor recovery.
    ///
    /// Issuance freezes until a matching authority state is installed.
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

    /// Returns the number of atomically admitted provider executions.
    pub fn admitted_count(&self) -> Result<u64, ProviderAdmissionError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM provider_execution_admissions",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        u64::try_from(count).map_err(|_| ProviderAdmissionError::RepositoryFailure)
    }

    /// Reads the non-secret token and cost utilization in one SQLite snapshot.
    pub fn utilization(
        &self,
    ) -> Result<(ProviderBudgetUtilization, ProviderBudgetUtilization), ProviderAdmissionError>
    {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        load_utilization(&connection)
    }

    fn now(&self) -> i64 {
        (self.now)()
    }
}

impl SqliteProviderExecutionStore {
    fn active_journal_key_binding_impl(
        &self,
    ) -> Result<Option<ProviderJournalKeyBinding>, ProviderExecutionError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        load_active_journal_key(&connection).map(|record| record.map(|record| record.binding))
    }
}
