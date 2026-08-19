use runne_application::provider::{
    ProviderAdmissionError, ProviderBudgetUtilization, ProviderLeaseBindingKind,
};
use rusqlite::{Connection, OptionalExtension};

use super::authority_config::ProviderRuntimeAuthorityConfig;

#[derive(Debug)]
pub(super) struct RuntimeAuthorityState {
    pub(super) runtime_authority_id: [u8; 16],
    pub(super) database_generation: u64,
    pub(super) principal_id: String,
    pub(super) owner_id: String,
    pub(super) scope: String,
    pub(super) expected_generation: u64,
    pub(super) lease_generation: u64,
    pub(super) expected_fencing_token: u64,
    pub(super) lease_fencing_token: u64,
    pub(super) capability_grant_id: String,
    pub(super) capability_revision: u64,
    pub(super) capability_allowed: bool,
    pub(super) capability_expires_at: i64,
    pub(super) capability_revocation_epoch: u64,
    pub(super) capability_revocation_observed: bool,
    pub(super) approval_id: String,
    pub(super) approval_revision: u64,
    pub(super) approval_allowed: bool,
    pub(super) approval_expires_at: i64,
    pub(super) approval_revocation_epoch: u64,
    pub(super) approval_revocation_observed: bool,
    pub(super) profile_digest: [u8; 32],
    pub(super) pricing_revision_digest: [u8; 32],
    pub(super) token_budget_limit: u64,
    pub(super) token_budget_reserved: u64,
    pub(super) token_budget_settled: u64,
    pub(super) activation_binding_kind: Option<ProviderLeaseBindingKind>,
    pub(super) activation_binding_digest: [u8; 32],
    pub(super) cost_budget_limit_micros: u64,
    pub(super) cost_budget_reserved_micros: u64,
    pub(super) cost_budget_settled_micros: u64,
    pub(super) authority_ttl_seconds: u64,
    pub(super) state_revision: u64,
    pub(super) active: bool,
}

impl RuntimeAuthorityState {
    fn base_binding_matches(&self, config: &ProviderRuntimeAuthorityConfig) -> bool {
        self.runtime_authority_id == config.runtime_authority_id
            && self.database_generation == config.database_generation
            && self.principal_id == config.principal_id
            && self.owner_id == config.owner_id
            && self.scope == config.scope
            && self.capability_grant_id == config.capability_grant_id
            && self.approval_id == config.approval_id
            && self.profile_digest == config.profile_digest
            && self.pricing_revision_digest == config.pricing_revision_digest
            && self.token_budget_limit == config.token_budget_limit
            && self.cost_budget_limit_micros == config.cost_budget_limit_micros
            && self.authority_ttl_seconds == config.authority_ttl_seconds
    }

    pub(super) fn immutable_binding_matches(
        &self,
        config: &ProviderRuntimeAuthorityConfig,
    ) -> bool {
        self.base_binding_matches(config)
            && self.activation_binding_kind == Some(config.activation_binding_kind)
            && self.activation_binding_digest == config.activation_binding_digest
    }

    pub(super) fn validate_renewal(
        &self,
        config: &ProviderRuntimeAuthorityConfig,
        allow_generation_advance: bool,
    ) -> Result<(), ProviderAdmissionError> {
        let legacy_revalidation = !self.active
            && self.activation_binding_kind.is_none()
            && self.activation_binding_digest == [0; 32]
            && self.capability_revocation_epoch == 0
            && self.approval_revocation_epoch == 0
            && self.base_binding_matches(config);
        if !self.immutable_binding_matches(config) && !legacy_revalidation {
            return Err(ProviderAdmissionError::AuthorityConflict);
        }
        let exact_worker = self.expected_generation == config.generation
            && self.expected_fencing_token == config.fencing_token;
        if !exact_worker
            && !(allow_generation_advance && config.generation > self.expected_generation)
        {
            return Err(ProviderAdmissionError::StaleFencingToken);
        }
        if config.capability_revision < self.capability_revision
            || config.capability_revocation_epoch < self.capability_revocation_epoch
            || (!legacy_revalidation && !self.capability_allowed && config.capability_allowed)
        {
            return Err(ProviderAdmissionError::CapabilityRevoked);
        }
        if config.approval_revision < self.approval_revision
            || config.approval_revocation_epoch < self.approval_revocation_epoch
            || (!legacy_revalidation && !self.approval_allowed && config.approval_allowed)
        {
            return Err(ProviderAdmissionError::ApprovalRevoked);
        }
        if self.capability_allowed
            && !config.capability_allowed
            && (config.capability_revision <= self.capability_revision
                || config.capability_revocation_epoch <= self.capability_revocation_epoch)
        {
            return Err(ProviderAdmissionError::CapabilityRevoked);
        }
        if self.approval_allowed
            && !config.approval_allowed
            && (config.approval_revision <= self.approval_revision
                || config.approval_revocation_epoch <= self.approval_revocation_epoch)
        {
            return Err(ProviderAdmissionError::ApprovalRevoked);
        }
        Ok(())
    }

    pub(super) fn capability_revocation_observed_on_renewal(
        &self,
        config: &ProviderRuntimeAuthorityConfig,
    ) -> bool {
        self.capability_revocation_observed
            || (self.capability_allowed && !config.capability_allowed)
    }

    pub(super) fn approval_revocation_observed_on_renewal(
        &self,
        config: &ProviderRuntimeAuthorityConfig,
    ) -> bool {
        self.approval_revocation_observed || (self.approval_allowed && !config.approval_allowed)
    }
}

pub(super) fn load_utilization(
    connection: &Connection,
) -> Result<(ProviderBudgetUtilization, ProviderBudgetUtilization), ProviderAdmissionError> {
    let values = connection
        .query_row(
            "SELECT token_budget_limit, token_budget_reserved, token_budget_settled,
                    cost_budget_limit_micros, cost_budget_reserved_micros, cost_budget_settled_micros
             FROM provider_runtime_authority_state WHERE id = 1",
            [],
            |row| {
                Ok((
                    as_u64(row.get(0)?)?, as_u64(row.get(1)?)?, as_u64(row.get(2)?)?,
                    as_u64(row.get(3)?)?, as_u64(row.get(4)?)?, as_u64(row.get(5)?)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?
        .ok_or(ProviderAdmissionError::AuthorityDenied)?;
    Ok((
        ProviderBudgetUtilization::new(values.0, values.1, values.2)?,
        ProviderBudgetUtilization::new(values.3, values.4, values.5)?,
    ))
}

pub(super) fn binding_kind(value: &str) -> rusqlite::Result<Option<ProviderLeaseBindingKind>> {
    match value {
        "protected_v2" => Ok(Some(ProviderLeaseBindingKind::ProtectedV2)),
        "external_owner_private" => Ok(Some(ProviderLeaseBindingKind::ExternalOwnerPrivate)),
        "legacy_unbound" => Ok(None),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn as_u64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)
}
