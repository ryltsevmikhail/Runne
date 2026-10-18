use super::super::super::RootAdmissionGateway;
use super::*;
use runne_application::permission_modes::LocalCommandPermissionBindingV1;
use runne_store::store::{ManagedIdentityMetadata, PermissionModeAuthorityContext};

pub(super) fn current_policy(
    roots: &RootAdmissionGateway,
    store: &StoreTransaction,
    binding: &LocalCommandPermissionBindingV1,
) -> bool {
    current_policy_stop_reason(roots, store, binding).is_none()
}
pub(super) fn current_policy_stop_reason(
    roots: &RootAdmissionGateway,
    store: &StoreTransaction,
    binding: &LocalCommandPermissionBindingV1,
) -> Option<u8> {
    let project = runne_application::project_trust::ProjectTrustProjectId::from_bytes(
        *binding.project_id().as_bytes(),
    );
    let Ok(lease) = store.observe_local_command_permission_trust(binding) else {
        return Some(6);
    };
    let Ok(trust) = lease.snapshot() else {
        return Some(6);
    };
    if trust != binding.closed_rules_snapshot()
        || trust.record.status == runne_application::project_trust::ProjectTrustStatus::Untrusted
    {
        return Some(3);
    }
    let authority = PermissionModeAuthorityContext::new(
        &binding.selection().scope.principal_id,
        project,
        lease.as_ref(),
        None,
    );
    let Ok(current) = store.load_permission_mode_selection_with_managed_identity(
        &binding.selection().scope,
        &binding.selection().scope.principal_id,
        &authority,
    ) else {
        return Some(6);
    };
    if current.selection != *binding.selection() {
        return Some(2);
    }
    let now = super::super::now_millis();
    if current
        .selection
        .expires_at_unix_ms
        .is_some_and(|expiry| expiry <= now)
        || binding.approval().expires_at_unix_ms <= now
    {
        return Some(5);
    }
    let managed_matches = matches!(
        current.identity,
        ManagedIdentityMetadata::ClosedRulesV2(ref value)
            if value.snapshot == trust && value.canonical_digest == binding.closed_rules_digest()
    );
    if !managed_matches {
        return Some(3);
    }
    let root_current = roots
        .with_local_command_root_version(
            binding.selection().scope.workspace_id,
            binding.workspace_version(),
            binding.admitted_root_version(),
            *binding.held_root_identity_digest().as_bytes(),
            |_| Ok(()),
        )
        .is_ok();
    drop(lease);
    if !root_current { Some(4) } else { None }
}
