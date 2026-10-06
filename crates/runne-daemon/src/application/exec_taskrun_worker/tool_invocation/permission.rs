use super::permission_build::*;
use super::*;
use runne_application::permission_modes::{
    self, CompositeEffectScope, ContainmentStrategy, ManagedDisposition, ManagedPolicyEvaluation,
    PermissionPolicyCompiler, PermissionScope, PolicyDecision, admit_effective_mode,
    admit_invocation_scope,
};
use runne_domain::id::IntegrityDigest;
use runne_platform::local_command_linux::LinuxCompositeScopeAdmission;
use runne_store::store::{
    PermissionModeSelectionSnapshot,
    taskrun_tool_invocation::{
        ToolInvocationBindingV1, ToolInvocationState, ToolPermissionAdmissionV1,
        ToolPermissionDecisionSource,
    },
};

pub(super) struct PreparedPermissionInvocation {
    pub(super) scope: CompositeEffectScope,
    pub(super) native_receipt: permission_modes::NativeScopeAdmissionReceipt,
    pub(super) admission: ToolPermissionAdmissionV1,
    pub(super) requires_human: bool,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn prepare(
    snapshot: &PermissionModeSelectionSnapshot,
    runtime_authority: &str,
    principal: &ApiPrincipalId,
    workspace_id: runne_domain::id::WorkspaceId,
    root_identity: IntegrityDigest,
    binding: &ToolInvocationBindingV1,
    saved_state: Option<ToolInvocationState>,
    native: &LinuxCompositeScopeAdmission,
    now: i64,
) -> Result<PreparedPermissionInvocation, ()> {
    let scope = invocation_scope(
        snapshot,
        runtime_authority,
        principal,
        workspace_id,
        root_identity,
        binding,
        native,
    )?;
    let effective_scope = effective_scope(snapshot, &scope)?;
    let effective = admit_effective_mode(
        snapshot.selection.selected_mode,
        snapshot.selection.preset_version,
        &effective_scope,
        native,
    )
    .map_err(|_| ())?;
    let native_receipt = admit_invocation_scope(&scope, native).map_err(|_| ())?;
    let candidate = approval_binding(snapshot, principal, &scope, binding);
    let approved = saved_state
        .is_some_and(|state| state == ToolInvocationState::Approved)
        .then_some(candidate.clone());
    let decision = PermissionPolicyCompiler::compile(&permission_modes::PolicyEvaluationInput {
        selection: snapshot.selection.clone(),
        effective,
        effective_scope,
        invocation: permission_modes::InvocationPolicyRequest {
            action: action(binding),
            resource: resource_facts(binding),
            composite_scope: scope.clone(),
            candidate_binding: candidate,
            approved_binding: approved,
            native_admission: Some(native_receipt),
        },
        managed: ManagedPolicyEvaluation {
            scope_digest: scope.digest().map_err(|_| ())?,
            policy_digest: snapshot.managed_policy_digest,
            disposition: ManagedDisposition::Allow,
        },
        now_unix_ms: now,
    });
    let requires_human = match decision {
        PolicyDecision::Allow { .. } => false,
        PolicyDecision::RequireApproval { .. } => true,
        PolicyDecision::Deny(_) => return Err(()),
    };
    let scope_digest = scope.digest().map_err(|_| ())?;
    let admission = ToolPermissionAdmissionV1 {
        key: binding.key,
        runtime_authority_id: runtime_authority.to_owned(),
        principal_id: principal.as_str().to_owned(),
        workspace_id,
        selected_mode: snapshot.selection.selected_mode,
        authorization_revision: snapshot.selection.authorization_revision,
        managed_policy_version: snapshot.managed_policy_version,
        managed_policy_digest: snapshot.managed_policy_digest,
        composite_scope_digest: IntegrityDigest::from_bytes(*scope_digest.as_bytes()),
        containment: ContainmentStrategy::WorkspaceBoundV1,
        native_scope_handle: IntegrityDigest::from_bytes(
            *native_receipt.platform_handle_id().as_bytes(),
        ),
        decision_source: if requires_human {
            ToolPermissionDecisionSource::Human
        } else {
            ToolPermissionDecisionSource::AutoPreset
        },
        relevant_policy_digest: snapshot.managed_policy_digest,
        expires_at_unix_ms: binding.approval_expires_at,
    };
    Ok(PreparedPermissionInvocation {
        scope,
        native_receipt,
        admission,
        requires_human,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn prepare_from_store(
    store: &runne_store::store::StoreTransaction,
    scope: &PermissionScope,
    principal: &ApiPrincipalId,
    workspace_id: runne_domain::id::WorkspaceId,
    root_identity: IntegrityDigest,
    binding: &ToolInvocationBindingV1,
    saved_state: Option<ToolInvocationState>,
    native: &LinuxCompositeScopeAdmission,
    now: i64,
) -> Result<PreparedPermissionInvocation, ()> {
    let snapshot = store
        .load_permission_mode_selection_snapshot(scope, principal)
        .map_err(|_| ())?;
    let saved = store
        .load_taskrun_tool_permission_admission(binding.key)
        .map_err(|_| ())?;
    let prepared = prepare(
        &snapshot,
        &store.runtime_authority_id().0,
        principal,
        workspace_id,
        root_identity,
        binding,
        saved_state,
        native,
        now,
    )?;
    if saved
        .as_ref()
        .is_some_and(|value| !durable_admission_matches(value, &prepared.admission))
    {
        return Err(());
    }
    Ok(prepared)
}

pub(super) fn durable_admission_matches(
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
        && saved.decision_source == current.decision_source
        && saved.relevant_policy_digest == current.relevant_policy_digest
        && saved.expires_at_unix_ms == current.expires_at_unix_ms
}
