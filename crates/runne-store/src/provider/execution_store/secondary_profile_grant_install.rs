impl SqliteProviderExecutionStore {
    /// Installs a secondary grant without changing the active owner capability or primary budget.
    pub fn install_secondary_profile_grant(
        &self,
        launch: &ProviderRuntimeLaunchCapability,
        spec: ProviderSecondaryProfileGrantSpec,
    ) -> Result<ProviderSecondaryProfileGrant, ProviderAdmissionError> {
        self.install_secondary_profile_grant_inner(launch, spec)?
            .ok_or(ProviderAdmissionError::AuthorityConflict)
    }

    /// Installs or reads back an exact grant, preserving an irreversible revoke.
    /// `None` means the exact configured grant is durably revoked.
    pub fn install_secondary_profile_grant_if_active(
        &self,
        launch: &ProviderRuntimeLaunchCapability,
        spec: ProviderSecondaryProfileGrantSpec,
    ) -> Result<Option<ProviderSecondaryProfileGrant>, ProviderAdmissionError> {
        self.install_secondary_profile_grant_inner(launch, spec)
    }

    fn install_secondary_profile_grant_inner(
        &self,
        launch: &ProviderRuntimeLaunchCapability,
        spec: ProviderSecondaryProfileGrantSpec,
    ) -> Result<Option<ProviderSecondaryProfileGrant>, ProviderAdmissionError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let state = super::load_runtime_authority(&transaction)?
            .ok_or(ProviderAdmissionError::AuthorityDenied)?;
        launch.verify_state(&state)?;
        validate_state(&state, &spec)?;
        if state.profile_digest == spec.profile_digest() {
            return Err(ProviderAdmissionError::AuthorityConflict);
        }
        if let Some(existing) = load_by_profile(&transaction, &spec)? {
            let capability = capability_from_row(existing, spec.clone())?;
            if capability.authority_id != state.runtime_authority_id
                || capability.database_generation != state.database_generation
            {
                return Err(ProviderAdmissionError::AuthorityConflict);
            }
            if !capability_is_enabled(&transaction, capability.grant_id)? {
                if exact_revoked_spec(&transaction, capability.grant_id, &spec)? {
                    transaction
                        .commit()
                        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
                    return Ok(None);
                }
                return Err(ProviderAdmissionError::AuthorityConflict);
            }
            validate_spec_row(&transaction, &capability, &spec)?;
            if same_owner(&capability, &state)
                && capability_is_active(&transaction, capability.grant_id, capability.binding_id)?
            {
                transaction
                    .commit()
                    .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
                return Ok(Some(capability));
            }
            transaction.execute(
                "UPDATE provider_secondary_profile_bindings SET closed_at=?2,close_reason='renewed'
                 WHERE grant_id=?1 AND closed_at IS NULL",
                params![capability.grant_id.as_slice(), self.now()],
            ).map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
            let binding_id = insert_binding(&transaction, capability.grant_id, &state, self.now())?;
            let persisted = capability_from_row(
                load_by_profile(&transaction, &spec)?
                    .ok_or(ProviderAdmissionError::RepositoryFailure)?,
                spec.clone(),
            )?;
            if persisted.binding_id != binding_id
                || !same_owner(&persisted, &state)
                || !capability_is_active(&transaction, persisted.grant_id, persisted.binding_id)?
            {
                return Err(ProviderAdmissionError::RepositoryFailure);
            }
            transaction
                .commit()
                .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
            return Ok(Some(persisted));
        }
        let grant_id = random_id();
        state
            .activation_binding_kind
            .ok_or(ProviderAdmissionError::AuthorityDenied)?;
        transaction.execute(
            "INSERT INTO provider_secondary_profile_grants (
              grant_id,runtime_authority_id,database_generation,provider_id,profile_id,credential_realm,
              profile_digest,pricing_revision_digest,token_budget_limit,token_budget_reserved,
              token_budget_settled,cost_budget_limit_micros,cost_budget_reserved_micros,
              cost_budget_settled_micros,enabled,created_at,revoked_at
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,0,0,?10,0,0,1,?11,NULL)",
            params![grant_id.as_slice(), state.runtime_authority_id.as_slice(), i64_value(state.database_generation)?,
                spec.provider_id(), spec.profile_id(),
                spec.credential_realm(), spec.profile_digest().as_slice(), spec.pricing_revision_digest().as_slice(),
                i64_value(spec.token_budget_limit())?, i64_value(spec.cost_budget_limit_micros())?, self.now()],
        ).map_err(|_| ProviderAdmissionError::AuthorityConflict)?;
        let binding_id = insert_binding(&transaction, grant_id, &state, self.now())?;
        let persisted = capability_from_row(
            load_by_profile(&transaction, &spec)?
                .ok_or(ProviderAdmissionError::RepositoryFailure)?,
            spec,
        )?;
        if persisted.grant_id != grant_id
            || persisted.binding_id != binding_id
            || !same_owner(&persisted, &state)
            || !capability_is_active(&transaction, persisted.grant_id, persisted.binding_id)?
        {
            return Err(ProviderAdmissionError::RepositoryFailure);
        }
        transaction
            .commit()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        Ok(Some(persisted))
    }
}
