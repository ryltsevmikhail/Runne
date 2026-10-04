use runne_application::provider::{
    ProviderAdmissionError, ProviderAuthorityIssueRequest, ProviderBudgetUtilization,
    ProviderExecutionError, ProviderSecondaryProfileGrantSpec,
};
use rusqlite::{OptionalExtension, Transaction, params};

use super::super::runtime_launch_capability::ProviderRuntimeLaunchCapability;
use super::{RuntimeAuthorityState, SqliteProviderExecutionStore};

#[path = "secondary_profile_grant_binding.rs"]
mod binding;
use binding::validate_state;
pub(super) use binding::{
    capability_from_row, capability_is_active, capability_is_enabled, exact_revoked_spec,
    i64_value, insert_binding, load_by_profile, random_id, read_u64, same_owner, validate_spec_row,
    verify_grant_owner, verify_secondary_attempt_binding,
};

/// Store-issued proof for one explicitly configured secondary profile grant.
#[derive(Debug, PartialEq, Eq)]
pub struct ProviderSecondaryProfileGrant {
    grant_id: [u8; 16],
    binding_id: [u8; 16],
    authority_id: [u8; 16],
    database_generation: u64,
    owner_id: String,
    authority_revision: u64,
    scope: String,
    activation_binding_kind: String,
    activation_binding_digest: [u8; 32],
    spec: ProviderSecondaryProfileGrantSpec,
}

impl ProviderSecondaryProfileGrant {
    /// Selected secondary profile identity, not an owner authority token.
    pub fn spec(&self) -> &ProviderSecondaryProfileGrantSpec {
        &self.spec
    }

    pub(crate) const fn grant_id(&self) -> [u8; 16] {
        self.grant_id
    }
    pub(crate) const fn binding_id(&self) -> [u8; 16] {
        self.binding_id
    }
}

pub(super) fn secondary_budget_available(
    transaction: &Transaction<'_>,
    id: [u8; 16],
) -> Result<(u64, u64), ProviderAdmissionError> {
    let row: (u64, u64, u64, u64, u64, u64) = transaction
        .query_row(
            "SELECT token_budget_limit,token_budget_reserved,token_budget_settled,
                cost_budget_limit_micros,cost_budget_reserved_micros,cost_budget_settled_micros
         FROM provider_secondary_profile_grants WHERE grant_id=?1 AND enabled=1",
            [id.as_slice()],
            |row| {
                Ok((
                    read_u64(row, 0)?,
                    read_u64(row, 1)?,
                    read_u64(row, 2)?,
                    read_u64(row, 3)?,
                    read_u64(row, 4)?,
                    read_u64(row, 5)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?
        .ok_or(ProviderAdmissionError::AuthorityDenied)?;
    let tokens = row
        .0
        .checked_sub(row.1)
        .and_then(|v| v.checked_sub(row.2))
        .ok_or(ProviderAdmissionError::TokenBudgetDenied)?;
    let cost = row
        .3
        .checked_sub(row.4)
        .and_then(|v| v.checked_sub(row.5))
        .ok_or(ProviderAdmissionError::CostBudgetDenied)?;
    Ok((tokens, cost))
}

pub(super) fn verify_existing_profile_grant(
    connection: &rusqlite::Connection,
    key: &str,
    expected: Option<&ProviderSecondaryProfileGrant>,
) -> Result<(), ProviderAdmissionError> {
    let expected = expected.map(|grant| (grant.grant_id, grant.binding_id));
    let stored_pair: Option<(Vec<u8>, Vec<u8>)> = connection.query_row(
        "SELECT grant_id,binding_id FROM provider_secondary_profile_attempts WHERE provider_idempotency_key=?1",
        [key], |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional().map_err(|_|ProviderAdmissionError::RepositoryFailure)?;
    if stored_pair
        .as_ref()
        .map(|(g, b)| (g.as_slice(), b.as_slice()))
        == expected.as_ref().map(|(g, b)| (g.as_slice(), b.as_slice()))
    {
        Ok(())
    } else {
        Err(ProviderAdmissionError::AuthorityConflict)
    }
}

include!("secondary_profile_grant_install.rs");

impl SqliteProviderExecutionStore {
    /// Irreversibly closes new admissions and effects for an exact secondary grant.
    pub fn revoke_secondary_profile_grant(
        &self,
        launch: &ProviderRuntimeLaunchCapability,
        grant: &ProviderSecondaryProfileGrant,
    ) -> Result<(), ProviderAdmissionError> {
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
        verify_grant_owner(grant, &state)?;
        transaction
            .execute(
                "UPDATE provider_secondary_profile_grants SET enabled=0,revoked_at=?2
             WHERE grant_id=?1 AND enabled=1 AND runtime_authority_id=?3
               AND database_generation=?4",
                params![
                    grant.grant_id.as_slice(),
                    self.now(),
                    state.runtime_authority_id.as_slice(),
                    i64_value(state.database_generation)?
                ],
            )
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        transaction
            .execute(
                "UPDATE provider_secondary_profile_bindings SET closed_at=?2,close_reason='revoked'
             WHERE binding_id=?1 AND closed_at IS NULL",
                params![grant.binding_id.as_slice(), self.now()],
            )
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        transaction
            .commit()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)
    }

    /// Reads only this grant's token and cost utilization.
    pub fn secondary_profile_utilization(
        &self,
        launch: &ProviderRuntimeLaunchCapability,
        grant: &ProviderSecondaryProfileGrant,
    ) -> Result<(ProviderBudgetUtilization, ProviderBudgetUtilization), ProviderAdmissionError>
    {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let state = super::load_runtime_authority(&transaction)?
            .ok_or(ProviderAdmissionError::AuthorityDenied)?;
        launch.verify_state(&state)?;
        verify_grant_owner(grant, &state)?;
        let values: (u64, u64, u64, u64, u64, u64) = transaction
            .query_row(
                "SELECT token_budget_limit,token_budget_reserved,token_budget_settled,
                    cost_budget_limit_micros,cost_budget_reserved_micros,cost_budget_settled_micros
             FROM provider_secondary_profile_grants WHERE grant_id=?1 AND enabled=1",
                [grant.grant_id.as_slice()],
                |row| {
                    Ok((
                        read_u64(row, 0)?,
                        read_u64(row, 1)?,
                        read_u64(row, 2)?,
                        read_u64(row, 3)?,
                        read_u64(row, 4)?,
                        read_u64(row, 5)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?
            .ok_or(ProviderAdmissionError::AuthorityDenied)?;
        transaction
            .commit()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        Ok((
            ProviderBudgetUtilization::new(values.0, values.1, values.2)?,
            ProviderBudgetUtilization::new(values.3, values.4, values.5)?,
        ))
    }
}
