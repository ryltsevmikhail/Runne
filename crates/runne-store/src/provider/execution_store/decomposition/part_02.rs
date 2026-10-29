use secondary_profile_grant::{secondary_budget_available, verify_existing_profile_grant};

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
        let connection = open_managed_connection(Path::new(path), ConnectionMode::Writer)
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        Self::open_with_connection_and_now(path, connection, now)
    }
    /// Adopts a validated writable connection without reopening its path.
    pub fn open_with_connection(
        path: &str,
        connection: ManagedConnection,
    ) -> Result<Self, ProviderAdmissionError> {
        Self::open_with_connection_and_now(path, connection, Arc::new(unix_timestamp))
    }

    fn open_with_connection_and_now(
        _path: &str,
        connection: ManagedConnection,
        now: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Result<Self, ProviderAdmissionError> {
        connection
            .restore_online_issuance_guard()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        apply_migrations(&connection).map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        readiness_from_managed(&connection)
            .and_then(|_| publication_from_managed(&connection).map(|_| ()))
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let store = Self {
            connection: Arc::new(Mutex::new(connection)),
            now,
            online_effect_proof: Arc::new(OnlineEffectProofState::new()),
            #[cfg(feature = "test-support")]
            next_dispatch_attempt_id_for_test: Mutex::new(None),
            #[cfg(test)]
            fail_effect_readback: AtomicBool::new(false),
            #[cfg(test)]
            effect_receipt_pause: Mutex::new(None),
        };
        Ok(store)
    }
    /// Atomically commits authority state and returns exact durable read-back.
    pub fn issue(
        &self,
        launch: &ProviderRuntimeLaunchCapability,
        request: &ProviderAuthorityIssueRequest,
    ) -> Result<ProviderAuthorityIssueOutcome, ProviderAdmissionError> {
        self.issue_with_profile_grant(launch, request, None)
    }

    /// Issues a dispatch using one exact store-issued secondary profile grant.
    pub fn issue_secondary_profile(
        &self,
        launch: &ProviderRuntimeLaunchCapability,
        grant: &crate::provider::ProviderSecondaryProfileGrant,
        request: &ProviderAuthorityIssueRequest,
    ) -> Result<ProviderAuthorityIssueOutcome, ProviderAdmissionError> {
        self.issue_with_profile_grant(launch, request, Some(grant))
    }

    fn issue_with_profile_grant(
        &self,
        launch: &ProviderRuntimeLaunchCapability,
        request: &ProviderAuthorityIssueRequest,
        grant: Option<&crate::provider::ProviderSecondaryProfileGrant>,
    ) -> Result<ProviderAuthorityIssueOutcome, ProviderAdmissionError> {
        request.validate()?;
        let semantic_digest = execution_semantic_digest(request);
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let issuance_guard = connection.online_issuance_guard();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;

        let state =
            load_runtime_authority(&transaction)?.ok_or(ProviderAdmissionError::AuthorityDenied)?;
        launch.verify_state(&state)?;

        if let Some(existing) =
            load_existing_admission(&transaction, &request.provider_idempotency_key)?
        {
            verify_existing_profile_grant(&transaction, &request.provider_idempotency_key, grant)?;
            if existing.provider_id.as_deref() != Some(request.provider_id.as_str()) {
                return Err(ProviderAdmissionError::AuthorityConflict);
            }
            return if existing.semantic_digest == semantic_digest {
                Ok(ProviderAuthorityIssueOutcome::Existing {
                    state: existing.state,
                })
            } else {
                Err(ProviderAdmissionError::AuthorityConflict)
            };
        }
        let is_d2_tool_profile = grant.is_some_and(|grant| {
            matches!(
                grant.spec().profile_id(),
                "runne-linux-agent-tools-v1" | "runne-deepseek-responses-tools/1"
            )
        });
        if is_d2_tool_profile {
            crate::store::taskrun_provider_start::verify_fresh_d2_running_attempt(
                &transaction,
                state.runtime_authority_id,
                request.taskrun_id,
                request.conversation_id,
                request.execution_attempt_id,
                &request.principal_id,
                request.prepared.profile_digest,
            )
        } else {
            crate::store::taskrun_provider_start::verify_fresh_running_attempt(
                &transaction,
                state.runtime_authority_id,
                request.taskrun_id,
                request.conversation_id,
                request.execution_attempt_id,
                &request.principal_id,
            )
        }
        .map_err(|_| ProviderAdmissionError::AuthorityDenied)?;
        let online_proof = self.online_effect_proof(&transaction)?;
        let online_proof = online_proof
            .as_ref()
            .ok_or(ProviderAdmissionError::AuthorityDenied)?;
        if let Some(grant) = grant {
            grant.verify_for_issue(&transaction, &state, request, self.now())?;
        } else {
            verify_runtime_authority(&state, request, self.now())?;
        }
        verify_prepared(&transaction, request)?;
        ensure_call_is_unclaimed(&transaction, request.prepared.call_id)?;

        let requested_tokens = request
            .requested_input_tokens
            .checked_add(request.requested_output_tokens)
            .ok_or(ProviderAdmissionError::TokenBudgetDenied)?;
        let available_tokens = match grant {
            Some(grant) => secondary_budget_available(&transaction, grant.grant_id())?.0,
            None => state
                .token_budget_limit
                .checked_sub(state.token_budget_reserved)
                .and_then(|available| available.checked_sub(state.token_budget_settled))
                .ok_or(ProviderAdmissionError::TokenBudgetDenied)?,
        };
        if requested_tokens > available_tokens {
            return Err(ProviderAdmissionError::TokenBudgetDenied);
        }
        let available_cost = match grant {
            Some(grant) => secondary_budget_available(&transaction, grant.grant_id())?.1,
            None => state
                .cost_budget_limit_micros
                .checked_sub(state.cost_budget_reserved_micros)
                .and_then(|available| available.checked_sub(state.cost_budget_settled_micros))
                .ok_or(ProviderAdmissionError::CostBudgetDenied)?,
        };
        if request.max_cost_micros > available_cost {
            return Err(ProviderAdmissionError::CostBudgetDenied);
        }

        let ids = IssuedIds::random_with_dispatch_attempt_id({
            #[cfg(feature = "test-support")]
            {
                self.take_next_dispatch_attempt_id_for_test()?
            }
            #[cfg(not(feature = "test-support"))]
            {
                None
            }
        });
        let now = self.now();
        let expires_at = state.capability_expires_at.min(state.approval_expires_at);
        if expires_at <= now {
            return Err(ProviderAdmissionError::AuthorityDenied);
        }
        let claim = ProviderDispatchClaim {
            provider_id: request.provider_id.clone(),
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
            &issuance_guard,
            online_proof,
            request,
            &state,
            &claim,
            authority_ref,
            semantic_digest,
            requested_tokens,
            grant.map(|grant| (grant.grant_id(), grant.binding_id())),
            now,
            expires_at,
        )?;
        transaction
            .commit()
            .map_err(|_| ProviderAdmissionError::PostClaimUncertain)?;
        let admission = durable_readback::load_durable_authority_record(
            &connection,
            request,
            &state,
            claim.attempt_id,
        )
        .map_err(|_| ProviderAdmissionError::PostClaimUncertain)?;
        verify_existing_profile_grant(&connection, &request.provider_idempotency_key, grant)?;
        Ok(ProviderAuthorityIssueOutcome::Winner(Box::new(admission)))
    }

    #[cfg(test)]
    pub(crate) fn fail_next_effect_readback(&self) {
        self.fail_effect_readback.store(true, Ordering::SeqCst);
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

    pub(super) fn now(&self) -> i64 {
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
