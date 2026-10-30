use super::super::super::RootAdmissionGateway;
use super::*;
use runne_application::permission_modes::LocalCommandPermissionBindingV1;

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
    match store.observe_local_command_permission_policy(binding) {
        Ok(None) => {}
        Ok(Some(reason)) => return Some(reason),
        Err(_) => return Some(6),
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
    if !root_current { Some(4) } else { None }
}
