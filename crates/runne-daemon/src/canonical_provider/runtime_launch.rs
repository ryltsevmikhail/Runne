use super::composition::{
    PROVIDER_POLICY_V1_COST_BUDGET_MICROS, PROVIDER_POLICY_V1_EFFECT_TTL_SECONDS,
    PROVIDER_POLICY_V1_LEASE_SECONDS, PROVIDER_POLICY_V1_REVISION, PROVIDER_POLICY_V1_TOKEN_BUDGET,
};
use super::projection::{derived_identity, policy_binding_digest};
use super::*;

pub(super) fn activate(
    store: &SqliteProviderExecutionStore,
    runtime_authority_id: [u8; 16],
    runtime_generation: u64,
    provenance: &DaemonActivationProvenance,
    profile: &SharedTextProviderProfile,
    scope: &str,
) -> Result<ProviderRuntimeLaunchCapability, DaemonError> {
    store
        .activate_runtime_launch(&configuration(
            runtime_authority_id,
            runtime_generation,
            provenance,
            profile,
            scope,
        ))
        .map_err(|_| DaemonError::Bootstrap("provider authority unavailable".into()))
}

pub(super) fn configuration(
    runtime_authority_id: [u8; 16],
    runtime_generation: u64,
    provenance: &DaemonActivationProvenance,
    profile: &SharedTextProviderProfile,
    scope: &str,
) -> ProviderRuntimeAuthorityConfig {
    let policy_binding = policy_binding_digest(provenance.digest(), profile);
    ProviderRuntimeAuthorityConfig {
        runtime_authority_id,
        database_generation: 1,
        principal_id: "local-owner".to_owned(),
        owner_id: derived_identity("owner", policy_binding),
        scope: scope.to_owned(),
        generation: runtime_generation,
        fencing_token: runtime_generation,
        capability_grant_id: derived_identity("capability", policy_binding),
        capability_revision: PROVIDER_POLICY_V1_REVISION,
        capability_allowed: true,
        capability_revocation_epoch: PROVIDER_POLICY_V1_REVISION,
        approval_id: derived_identity("approval", policy_binding),
        approval_revision: PROVIDER_POLICY_V1_REVISION,
        approval_allowed: true,
        approval_revocation_epoch: PROVIDER_POLICY_V1_REVISION,
        profile_digest: profile.profile_digest(),
        pricing_revision_digest: profile.pricing_revision_digest(),
        activation_binding_kind: provenance.kind(),
        activation_binding_digest: provenance.digest(),
        token_budget_limit: PROVIDER_POLICY_V1_TOKEN_BUDGET,
        cost_budget_limit_micros: PROVIDER_POLICY_V1_COST_BUDGET_MICROS,
        authority_ttl_seconds: PROVIDER_POLICY_V1_EFFECT_TTL_SECONDS,
        lease_ttl_seconds: PROVIDER_POLICY_V1_LEASE_SECONDS,
    }
}
