use super::permission_build::*;
use super::*;
use runne_application::permission_modes::{
    self, CompositeEffectScope, CompositeScopeDigest, ContainmentStrategy, ManagedDisposition,
    ManagedPolicyCoverage, ManagedPolicyEvaluation, NativeScopeAdmissionPort, PermissionAction,
    PermissionPolicyCompiler, PermissionScope, PolicyDecision, admit_effective_mode,
    admit_invocation_scope,
};
use runne_application::project_trust::{
    ManagedEffectDecision, ProjectTrustEffectPolicySnapshot, ProjectTrustProjectId,
    managed_effect_policy_digest_v2,
};
use runne_domain::id::IntegrityDigest;
use runne_platform::local_command_linux::{LinuxCompositeScopeAdmission, PreparedToolHelperV1};
use runne_store::store::{
    PermissionModeSelectionSnapshot,
    taskrun_tool_invocation::{
        ToolInvocationBindingV1, ToolInvocationState, ToolInvocationStoredRecord,
        ToolPermissionAdmissionV1, ToolPermissionDecisionSource,
    },
};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

#[path = "permission/managed.rs"]
mod managed;
#[cfg(test)]
#[path = "permission/managed_tests.rs"]
mod managed_tests;

pub(super) struct PreparedPermissionInvocation {
    pub(super) scope: CompositeEffectScope,
    pub(super) native_receipt: permission_modes::NativeScopeAdmissionReceipt,
    pub(super) admission: ToolPermissionAdmissionV1,
    pub(super) requires_human: bool,
    helper: Mutex<Option<PreparedToolHelperV1>>,
}

impl PreparedPermissionInvocation {
    pub(super) fn attach_helper(&self, helper: PreparedToolHelperV1) -> Result<(), ()> {
        let mut slot = self.helper.lock().map_err(|_| ())?;
        if slot.is_some() {
            return Err(());
        }
        *slot = Some(helper);
        Ok(())
    }

    pub(super) fn take_helper(&self) -> Result<PreparedToolHelperV1, ()> {
        self.helper.lock().map_err(|_| ())?.take().ok_or(())
    }
}

pub(super) struct CurrentManagedPolicyCapture {
    pub(super) project: ProjectTrustProjectId,
    pub(super) snapshot: ProjectTrustEffectPolicySnapshot,
    _lease: Box<dyn runne_application::project_trust::ProjectTrustEffectLease>,
}

pub(super) fn capture_current_managed_policy(
    root: &crate::application::root_handle_admission::RootAdmissionGateway,
    workspace_id: runne_domain::id::WorkspaceId,
    expected: runne_application::project_trust::TrustToken,
    project_id: [u8; 16],
) -> Result<CurrentManagedPolicyCapture, ()> {
    let project = ProjectTrustProjectId::from_bytes(project_id);
    let lease = root
        .acquire_local_command_effect_lease(workspace_id, expected)
        .map_err(|_| ())?;
    let snapshot = lease.snapshot().map_err(|_| ())?;
    Ok(CurrentManagedPolicyCapture {
        project,
        snapshot,
        _lease: lease,
    })
}

pub(super) fn stable_tool_id(bytes: &[u8]) -> [u8; 16] {
    let mut value: [u8; 16] = Sha256::digest(bytes)[..16]
        .try_into()
        .expect("fixed digest prefix");
    value[6] = (value[6] & 0x0f) | 0x70;
    value[8] = (value[8] & 0x3f) | 0x80;
    value
}

#[path = "permission/canonical.rs"]
mod canonical;
pub(super) use canonical::canonical_arguments_for_mode;

pub(super) fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn prepare(
    snapshot: &PermissionModeSelectionSnapshot,
    trust_project: ProjectTrustProjectId,
    trust_snapshot: &ProjectTrustEffectPolicySnapshot,
    runtime_authority: &str,
    principal: &ApiPrincipalId,
    workspace_id: runne_domain::id::WorkspaceId,
    root_identity: IntegrityDigest,
    binding: &ToolInvocationBindingV1,
    saved_invocation: Option<&ToolInvocationStoredRecord>,
    saved_admission: Option<&ToolPermissionAdmissionV1>,
    native: &LinuxCompositeScopeAdmission,
    helper_admission: &dyn NativeScopeAdmissionPort,
    now: i64,
) -> Result<PreparedPermissionInvocation, ()> {
    let policy_digest = IntegrityDigest::from_bytes(
        managed_effect_policy_digest_v2(trust_project, trust_snapshot).ok_or(())?,
    );
    let scope = invocation_scope(
        ManagedPolicyCoverage::from_closed_snapshot(trust_project, trust_snapshot).ok_or(())?,
        runtime_authority,
        principal,
        workspace_id,
        root_identity,
        binding,
        native,
    )?;
    let managed_disposition = managed_disposition(&scope, trust_project, trust_snapshot)
        .map_err(|_| super::super::provider::d2_stage("permission_managed"))?;
    let effective_scope = effective_scope(snapshot, &scope, trust_project, trust_snapshot, native)?;
    let effective = admit_effective_mode(
        snapshot.selection.selected_mode,
        snapshot.selection.preset_version,
        &effective_scope,
        helper_admission,
    )
    .map_err(|_| super::super::provider::d2_stage("permission_effective"))?;
    let native_receipt = admit_invocation_scope(&scope, helper_admission)
        .map_err(|_| super::super::provider::d2_stage("permission_native"))?;
    let helper_executable = if action(binding) == PermissionAction::ProcessStart {
        Some(native.tool_helper_executable_digest().map_err(|_| ())?)
    } else {
        None
    };
    let candidate = approval_binding(principal, &scope, binding, helper_executable);
    let scope_digest = scope.digest().map_err(|_| ())?;
    let mut admission = ToolPermissionAdmissionV1 {
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
        decision_source: ToolPermissionDecisionSource::Human,
        relevant_policy_digest: policy_digest,
        expires_at_unix_ms: binding.approval_expires_at,
    };
    let approved = saved_invocation
        .zip(saved_admission)
        .filter(|(record, saved)| {
            record.receipt.state == ToolInvocationState::Approved
                && managed::persisted_binding_matches(&record.binding, binding)
                && saved.decision_source == ToolPermissionDecisionSource::Human
                && managed::durable_admission_facts_match(saved, &admission)
        })
        .and_then(|(record, saved)| {
            let mut original =
                approval_binding(principal, &scope, &record.binding, helper_executable);
            original.composite_scope_digest =
                CompositeScopeDigest::from_bytes(*saved.composite_scope_digest.as_bytes());
            original.containment_version = saved.containment;
            original.relevant_policy_digest = saved.relevant_policy_digest;
            (original == candidate).then_some(original)
        });
    let decision = PermissionPolicyCompiler::compile(&permission_modes::PolicyEvaluationInput {
        selection: snapshot.selection.clone(),
        effective,
        effective_scope,
        invocation: permission_modes::InvocationPolicyRequest {
            action: action(binding),
            resource: resource_facts(binding),
            composite_scope: scope.clone(),
            candidate_binding: candidate,
            approved_binding: approved.clone(),
            native_admission: Some(native_receipt),
        },
        managed: ManagedPolicyEvaluation {
            scope_digest: scope.digest().map_err(|_| ())?,
            policy_digest,
            disposition: managed_disposition,
        },
        now_unix_ms: now,
    });
    let requires_human = match decision {
        PolicyDecision::Allow { .. } => false,
        PolicyDecision::RequireApproval { .. } => true,
        PolicyDecision::Deny(_) => {
            super::super::provider::d2_stage("permission_compiler");
            return Err(());
        }
    };
    admission.decision_source = if requires_human || approved.is_some() {
        ToolPermissionDecisionSource::Human
    } else {
        ToolPermissionDecisionSource::AutoPreset
    };
    Ok(PreparedPermissionInvocation {
        scope,
        native_receipt,
        admission,
        requires_human,
        helper: Mutex::new(None),
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn prepare_from_store(
    store: &runne_store::store::StoreTransaction,
    scope: &PermissionScope,
    principal: &ApiPrincipalId,
    workspace_id: runne_domain::id::WorkspaceId,
    root_identity: IntegrityDigest,
    trust_project: ProjectTrustProjectId,
    trust_snapshot: &ProjectTrustEffectPolicySnapshot,
    binding: &ToolInvocationBindingV1,
    native: &LinuxCompositeScopeAdmission,
    now: i64,
) -> Result<PreparedPermissionInvocation, ()> {
    let snapshot = store
        .load_permission_mode_selection_snapshot(scope, principal)
        .map_err(|_| ())?;
    let saved = store
        .load_taskrun_tool_permission_admission(binding.key)
        .map_err(|_| ())?;
    let saved_invocation = store
        .load_taskrun_tool_invocation(binding.key)
        .map_err(|_| ())?;
    if saved_invocation
        .as_ref()
        .is_some_and(|record| !managed::persisted_binding_matches(&record.binding, binding))
    {
        return Err(());
    }
    let preparation = store.local_permission_preparation().map_err(|_| ())?;
    let helper_admission = preparation.helper_scope_admission_port();
    let prepared = prepare(
        &snapshot,
        trust_project,
        trust_snapshot,
        &store.runtime_authority_id().0,
        principal,
        workspace_id,
        root_identity,
        binding,
        saved_invocation.as_ref(),
        saved.as_ref(),
        native,
        &helper_admission,
        now,
    )?;
    if saved
        .as_ref()
        .is_some_and(|value| !managed::durable_admission_matches(value, &prepared.admission))
    {
        return Err(());
    }
    Ok(prepared)
}

fn managed_disposition(
    scope: &CompositeEffectScope,
    project: ProjectTrustProjectId,
    snapshot: &ProjectTrustEffectPolicySnapshot,
) -> Result<ManagedDisposition, ()> {
    let closed = ManagedPolicyCoverage::from_closed_snapshot(project, snapshot).ok_or(())?;
    let mut exact_scope = scope.clone();
    exact_scope.managed_policy = closed;
    if !closed.supports_closed_scope(&exact_scope) {
        return Err(());
    }
    match closed.scope_minimum_disposition(&exact_scope).ok_or(())? {
        ManagedEffectDecision::Allow => Ok(ManagedDisposition::Allow),
        ManagedEffectDecision::Ask => Ok(ManagedDisposition::Ask),
        ManagedEffectDecision::Deny => Ok(ManagedDisposition::Deny),
    }
}
