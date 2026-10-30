use super::*;
use runne_application::provider::ProviderLeaseBindingKind;

impl SqliteProviderExecutionStore {
    /// Explicit offline transition after runtime verification of both installations.
    /// Changes only installation-derived identities; never renews grants or budgets.
    pub fn upgrade_external_installation(
        &self,
        before: &ProviderRuntimeAuthorityConfig,
        after: &ProviderRuntimeAuthorityConfig,
    ) -> Result<(), ProviderAdmissionError> {
        before.validate()?;
        after.validate()?;
        let mut normalized = after.clone();
        normalized.activation_binding_digest = before.activation_binding_digest;
        normalized.owner_id.clone_from(&before.owner_id);
        normalized
            .capability_grant_id
            .clone_from(&before.capability_grant_id);
        normalized.approval_id.clone_from(&before.approval_id);
        if &normalized != before
            || before.activation_binding_kind != ProviderLeaseBindingKind::ExternalOwnerPrivate
            || before.activation_binding_digest == after.activation_binding_digest
        {
            return Err(ProviderAdmissionError::AuthorityConflict);
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let state = load_runtime_authority(&tx)?.ok_or(ProviderAdmissionError::AuthorityDenied)?;
        if !state.active
            || !state.capability_allowed
            || !state.approval_allowed
            || state.capability_revocation_observed
            || state.approval_revocation_observed
        {
            return Err(ProviderAdmissionError::AuthorityDenied);
        }
        // A lost acknowledgement is safe to retry; no second revision or grant renewal.
        if state.immutable_binding_matches(after) {
            state.validate_renewal(after, true)?;
            return Ok(());
        }
        state.validate_renewal(before, true)?;
        if before.generation <= state.expected_generation
            || before.fencing_token <= state.expected_fencing_token
            || state.token_budget_reserved != 0
            || state.cost_budget_reserved_micros != 0
        {
            return Err(ProviderAdmissionError::StaleFencingToken);
        }
        let pending: bool = tx
            .query_row(
                "SELECT EXISTS(
                SELECT 1 FROM provider_dispatch_attempts WHERE state NOT IN (2, 5)
                UNION ALL SELECT 1 FROM provider_terminal_outbox WHERE state = 1
                UNION ALL SELECT 1 FROM provider_credential_operations
                  WHERE state NOT IN ('COMPLETED','FAILED','EXPIRED','CANCELLED','TOMBSTONED')
                UNION ALL SELECT 1 FROM provider_credential_verification_observations WHERE state='LEASED'
                UNION ALL SELECT 1 FROM provider_credential_authority_heads
                  WHERE hard_fence_disposition IS NOT NULL OR release_migration_state IN ('PENDING','VERIFIED')
                UNION ALL SELECT 1 FROM provider_credential_operations
                  WHERE native_effect_disposition='POSSIBLE_EFFECT'
                    AND state != 'COMPLETED'
             )",
                [],
                |r| r.get(0),
            )
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        if pending {
            return Err(ProviderAdmissionError::PostClaimUncertain);
        }
        let revision = state
            .state_revision
            .checked_add(1)
            .ok_or(ProviderAdmissionError::RepositoryFailure)?;
        let changed = tx
            .execute(
                "UPDATE provider_runtime_authority_state SET
                owner_id=?1, capability_grant_id=?2, approval_id=?3,
                activation_binding_digest=?4, state_revision=?5,
                expected_generation=?6, lease_generation=?6,
                expected_fencing_token=?7, lease_fencing_token=?7
             WHERE id=1 AND state_revision=?8 AND activation_binding_digest=?9",
                params![
                    after.owner_id,
                    after.capability_grant_id,
                    after.approval_id,
                    after.activation_binding_digest.as_slice(),
                    as_i64(revision)?,
                    as_i64(after.generation)?,
                    as_i64(after.fencing_token)?,
                    as_i64(state.state_revision)?,
                    before.activation_binding_digest.as_slice()
                ],
            )
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        if changed != 1 {
            return Err(ProviderAdmissionError::AuthorityConflict);
        }
        tx.commit()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)
    }
}
