//! Transaction-local policy data. A compatible result is never an execution permit.
use super::{model::now_ms, retained_context::OriginalCaptureContextV1};
use crate::store::{ManagedIdentityMetadata, PermissionModeAuthorityContext, StoreTransaction};
use runne_application::{
    permission_modes::{
        LocalCommandPermissionBindingV1, ManagedPolicyCoverage, ModeSelection,
        RetainedScopeCompatibilityV1, assess_retained_scope_compatibility_v1,
    },
    ports::EventStoreError,
    project_trust::{ManagedEffectDecision, ProjectTrustEffectLease, ProjectTrustProjectId},
};
use rusqlite::Transaction;

pub(super) struct Assessment {
    pub(super) selection: ModeSelection,
    pub(super) stop: Option<u8>,
}

pub(super) fn assess_context(
    tx: &Transaction<'_>,
    store: &StoreTransaction,
    original: &OriginalCaptureContextV1,
    capture: &super::read::LocalCommandPermissionCaptureV1,
    project: ProjectTrustProjectId,
    lease: &dyn ProjectTrustEffectLease,
) -> Result<Assessment, EventStoreError> {
    let now = now_ms();
    let admission = super::admission_checks::classify_original_admission(
        tx,
        capture,
        &super::original_approval_facts::OriginalApprovalFacts::from_context(original),
        now,
    )?;
    let scope = &original.selection.scope;
    let authority = PermissionModeAuthorityContext::new(&scope.principal_id, project, lease, None);
    let (selected, current) =
        crate::store::permission_modes::current_on_connection(store, tx, scope, &authority)
            .map_err(|_| EventStoreError::CorruptData)?;
    let selection = selected.selection;
    let stop = if !matches!(selected.identity, ManagedIdentityMetadata::ClosedRulesV2(_)) {
        Some(3)
    } else if let Some(reason) = selection_stop_for_admission(
        &original.selection,
        &selection,
        original.approval.expires_at_unix_ms,
        now,
        Some(&admission),
    ) {
        Some(reason)
    } else {
        let mut current_scope = original.scope.clone();
        current_scope.managed_policy =
            ManagedPolicyCoverage::from_closed_snapshot(project, &current.snapshot)
                .ok_or(EventStoreError::CorruptData)?;
        current_scope
            .validate()
            .map_err(|_| EventStoreError::CorruptData)?;
        if current_scope
            .managed_policy
            .scope_minimum_disposition(&current_scope)
            == Some(ManagedEffectDecision::Deny)
        {
            Some(3)
        } else {
            match assess_retained_scope_compatibility_v1(
                project,
                &original.scope,
                &original.closed_snapshot,
                project,
                &current_scope,
                &current.snapshot,
                original.preset_version,
                original.source_policy_version,
                original.command_policy_version,
            ) {
                RetainedScopeCompatibilityV1::Compatible { .. } => None,
                RetainedScopeCompatibilityV1::IdentityChanged => Some(3),
                RetainedScopeCompatibilityV1::RelevantChange
                | RetainedScopeCompatibilityV1::Unsupported => Some(2),
                RetainedScopeCompatibilityV1::Invalid => return Err(EventStoreError::CorruptData),
            }
        }
    };
    Ok(Assessment { selection, stop })
}

pub(super) fn assess_binding(
    tx: &Transaction<'_>,
    store: &StoreTransaction,
    binding: &LocalCommandPermissionBindingV1,
    lease: &dyn ProjectTrustEffectLease,
) -> Result<Assessment, EventStoreError> {
    let (capture, context) =
        super::retained_policy_rows::load(tx, binding.assignment().taskrun_id)?;
    if capture.canonical_binding_digest != *binding.digest().as_bytes() {
        return Err(EventStoreError::CorruptData);
    }
    let project = ProjectTrustProjectId::from_bytes(*binding.project_id().as_bytes());
    super::model::verify_workspace(tx, binding)?;
    if let Some(context) = context.as_ref() {
        let result = assess_context(tx, store, context, &capture, project, lease)?;
        if result.stop != Some(2) {
            return Ok(result);
        }
        // Valid Unsupported is not a new ordinary exact-current admission gate.
        if !matches!(
            context.semantic_projection,
            super::retained_context::OriginalSemanticProjectionV1::UnsupportedV1
        ) {
            return Ok(result);
        }
    }
    // Legacy/Unsupported has NO retention. Preserve only the pre-existing exact-current
    // ordinary binding path; immutable proof/native checks remain with the caller.
    let scope = &binding.selection().scope;
    let authority = PermissionModeAuthorityContext::new(&scope.principal_id, project, lease, None);
    let (selected, current) =
        crate::store::permission_modes::current_on_connection(store, tx, scope, &authority)
            .map_err(|_| EventStoreError::CorruptData)?;
    let receipt_matches = matches!(selected.identity, ManagedIdentityMetadata::ClosedRulesV2(ref value)
        if value.snapshot == current.snapshot && value.canonical_digest == binding.closed_rules_digest());
    let stop = if selected
        .selection
        .expires_at_unix_ms
        .is_some_and(|v| v <= now_ms())
        || binding.approval().expires_at_unix_ms <= now_ms()
    {
        Some(5)
    } else if selected.selection != *binding.selection()
        || !receipt_matches
        || current.snapshot != binding.closed_rules_snapshot()
    {
        Some(2)
    } else {
        None
    };
    Ok(Assessment {
        selection: selected.selection,
        stop,
    })
}

// Pending/no-admission DATA control. It never supplies original Human evidence.
#[cfg(test)]
pub(super) fn selection_stop(
    original: &ModeSelection,
    current: &ModeSelection,
    original_approval_expiry: i64,
    now: i64,
) -> Option<u8> {
    selection_stop_for_admission(original, current, original_approval_expiry, now, None)
}

pub(super) fn selection_stop_for_admission(
    original: &ModeSelection,
    current: &ModeSelection,
    original_approval_expiry: i64,
    now: i64,
    admission: Option<&super::admission_checks::VerifiedOriginalAdmission>,
) -> Option<u8> {
    if current.scope != original.scope
        || current.preset_version != original.preset_version
        || current.expires_at_unix_ms != original.expires_at_unix_ms
    {
        Some(2)
    } else if current.expires_at_unix_ms.is_some_and(|v| v <= now)
        || original_approval_expiry <= now
    {
        Some(5)
    } else if current.selected_mode != original.selected_mode
        // Revision zero is the missing-row default, not a trusted mode receipt.
        && (current.authorization_revision == 0
            || !admission.is_some_and(|verified| verified.live_human(now)))
    {
        Some(2)
    } else {
        None
    }
}

pub(super) fn require_current(
    tx: &Transaction<'_>,
    store: &StoreTransaction,
    binding: &LocalCommandPermissionBindingV1,
    lease: &dyn ProjectTrustEffectLease,
) -> Result<ModeSelection, EventStoreError> {
    let assessment = assess_binding(tx, store, binding, lease)?;
    if assessment.stop.is_some() {
        return Err(EventStoreError::CorruptData);
    }
    Ok(assessment.selection)
}
