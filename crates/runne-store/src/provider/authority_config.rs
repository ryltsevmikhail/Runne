use runne_application::provider::{ProviderAdmissionError, ProviderLeaseBindingKind};

/// Runtime-owned provider authority and budget state installed at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRuntimeAuthorityConfig {
    /// Stable runtime authority identity.
    pub runtime_authority_id: [u8; 16],
    /// Current authoritative database generation.
    pub database_generation: u64,
    /// Authenticated principal accepted for this local runtime.
    pub principal_id: String,
    /// Runtime-derived effect owner.
    pub owner_id: String,
    /// Runtime-derived provider effect scope.
    pub scope: String,
    /// Expected worker generation.
    pub generation: u64,
    /// Expected worker fencing token.
    pub fencing_token: u64,
    /// Durable capability grant identity and revision.
    pub capability_grant_id: String,
    pub capability_revision: u64,
    pub capability_allowed: bool,
    pub capability_revocation_epoch: u64,
    /// Durable approval identity and revision.
    pub approval_id: String,
    pub approval_revision: u64,
    pub approval_allowed: bool,
    pub approval_revocation_epoch: u64,
    /// Exact immutable provider profile and pricing revision.
    pub profile_digest: [u8; 32],
    pub pricing_revision_digest: [u8; 32],
    /// Closed activation binding.
    pub activation_binding_kind: ProviderLeaseBindingKind,
    pub activation_binding_digest: [u8; 32],
    /// Durable aggregate token and cost budgets.
    pub token_budget_limit: u64,
    pub cost_budget_limit_micros: u64,
    /// Maximum effect authority and exact runtime lease durations.
    pub authority_ttl_seconds: u64,
    pub lease_ttl_seconds: u64,
}

impl ProviderRuntimeAuthorityConfig {
    pub(super) fn validate(&self) -> Result<(), ProviderAdmissionError> {
        if self.runtime_authority_id == [0; 16]
            || self.database_generation == 0
            || self.generation == 0
            || self.fencing_token == 0
            || self.capability_revision == 0
            || self.capability_revocation_epoch == 0
            || self.approval_revision == 0
            || self.approval_revocation_epoch == 0
            || self.activation_binding_digest == [0; 32]
            || !(1..=300).contains(&self.authority_ttl_seconds)
            || self.lease_ttl_seconds != 600
            || ![
                &self.principal_id,
                &self.owner_id,
                &self.scope,
                &self.capability_grant_id,
                &self.approval_id,
            ]
            .into_iter()
            .all(|value| bounded_text(value))
            || [
                self.database_generation,
                self.generation,
                self.fencing_token,
                self.capability_revision,
                self.capability_revocation_epoch,
                self.approval_revision,
                self.approval_revocation_epoch,
                self.token_budget_limit,
                self.cost_budget_limit_micros,
            ]
            .into_iter()
            .any(|value| i64::try_from(value).is_err())
        {
            return Err(ProviderAdmissionError::InvalidSemanticContext);
        }
        Ok(())
    }
}

fn bounded_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.bytes().any(|byte| byte.is_ascii_control())
}
