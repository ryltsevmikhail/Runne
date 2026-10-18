use runne_store::store::taskrun_tool_invocation::{
    ToolInvocationBindingV1, ToolPermissionAdmissionV1,
};

pub(super) fn durable_admission_matches(
    saved: &ToolPermissionAdmissionV1,
    current: &ToolPermissionAdmissionV1,
) -> bool {
    durable_admission_facts_match(saved, current)
        && saved.decision_source == current.decision_source
}

pub(super) fn durable_admission_facts_match(
    saved: &ToolPermissionAdmissionV1,
    current: &ToolPermissionAdmissionV1,
) -> bool {
    saved.key == current.key
        && saved.runtime_authority_id == current.runtime_authority_id
        && saved.principal_id == current.principal_id
        && saved.workspace_id == current.workspace_id
        && saved.selected_mode == current.selected_mode
        && saved.authorization_revision == current.authorization_revision
        && saved.managed_policy_version == current.managed_policy_version
        && saved.managed_policy_digest == current.managed_policy_digest
        && saved.composite_scope_digest == current.composite_scope_digest
        && saved.containment == current.containment
        && saved.native_scope_handle == current.native_scope_handle
        && saved.relevant_policy_digest == current.relevant_policy_digest
        && saved.expires_at_unix_ms == current.expires_at_unix_ms
}

pub(super) fn persisted_binding_matches(
    saved: &ToolInvocationBindingV1,
    current: &ToolInvocationBindingV1,
) -> bool {
    if !saved.canonical_arguments.is_empty() {
        return false;
    }
    let mut current = current.clone();
    current.canonical_arguments.clear();
    saved == &current
}
