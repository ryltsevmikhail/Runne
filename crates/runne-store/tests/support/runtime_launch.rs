use runne_application::provider::ProviderLeaseBindingKind;
use runne_store::provider::{
    ProviderRuntimeAuthorityConfig, ProviderRuntimeLaunchCapability, SqliteProviderExecutionStore,
};

pub(super) fn activate(
    execution: &SqliteProviderExecutionStore,
) -> ProviderRuntimeLaunchCapability {
    execution.activate_runtime_launch(&config()).unwrap()
}

fn config() -> ProviderRuntimeAuthorityConfig {
    ProviderRuntimeAuthorityConfig {
        runtime_authority_id: [21; 16],
        database_generation: 1,
        principal_id: "provider-test-principal".into(),
        owner_id: "provider-test-runtime".into(),
        scope: "provider.dispatch".into(),
        generation: 1,
        fencing_token: 9,
        capability_grant_id: "provider-test-grant".into(),
        capability_revision: 1,
        capability_allowed: true,
        capability_revocation_epoch: 1,
        approval_id: "provider-test-approval".into(),
        approval_revision: 1,
        approval_allowed: true,
        approval_revocation_epoch: 1,
        profile_digest: [4; 32],
        pricing_revision_digest: [22; 32],
        activation_binding_kind: ProviderLeaseBindingKind::ProtectedV2,
        activation_binding_digest: [23; 32],
        token_budget_limit: 10_000,
        cost_budget_limit_micros: 1_000_000,
        authority_ttl_seconds: 120,
        lease_ttl_seconds: 600,
    }
}
