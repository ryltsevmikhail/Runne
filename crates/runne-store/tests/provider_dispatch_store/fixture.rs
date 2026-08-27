use runne_application::provider::ProviderLeaseBindingKind;
use runne_store::provider::{
    ProviderRuntimeAuthorityConfig, ProviderRuntimeLaunchCapability, SqliteProviderDispatchStore,
};

use crate::validated_reopen::ProviderTestDatabase;

pub(super) fn fresh_store(
    name: &str,
) -> (
    ProviderTestDatabase,
    SqliteProviderDispatchStore,
    ProviderRuntimeLaunchCapability,
) {
    let database = ProviderTestDatabase::new(name);
    let execution = database.execution();
    let launch = execution.activate_runtime_launch(&config()).unwrap();
    crate::online_proof::arm(&execution, 1);
    let dispatch = database.dispatch();
    (database, dispatch, launch)
}

pub(super) fn config() -> ProviderRuntimeAuthorityConfig {
    ProviderRuntimeAuthorityConfig {
        runtime_authority_id: [1; 16],
        database_generation: 1,
        principal_id: "provider-dispatch-test-principal".to_owned(),
        owner_id: "provider-dispatch-test-runtime".to_owned(),
        scope: "provider.dispatch".to_owned(),
        generation: 1,
        fencing_token: 9,
        capability_grant_id: "provider-dispatch-test-grant".to_owned(),
        capability_revision: 1,
        capability_allowed: true,
        capability_revocation_epoch: 1,
        approval_id: "provider-dispatch-test-approval".to_owned(),
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
