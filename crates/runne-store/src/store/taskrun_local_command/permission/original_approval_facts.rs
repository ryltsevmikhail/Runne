use super::retained_context::OriginalCaptureContextV1;
use runne_application::{
    permission_modes::{
        ApprovalBinding, CompositeEffectScope, LocalCommandPermissionBindingV1, ModeSelection,
    },
    project_trust::ProjectTrustEffectPolicySnapshot,
};

// An original-data projection only; never a reconstructed checked command.
pub(super) struct OriginalApprovalFacts<'a> {
    pub(super) approval: &'a ApprovalBinding,
    pub(super) selection: &'a ModeSelection,
    pub(super) scope: &'a CompositeEffectScope,
    pub(super) snapshot: ProjectTrustEffectPolicySnapshot,
    pub(super) canonical_digest: [u8; 32],
}

impl<'a> OriginalApprovalFacts<'a> {
    pub(super) fn from_binding(binding: &'a LocalCommandPermissionBindingV1) -> Self {
        Self {
            approval: binding.approval(),
            selection: binding.selection(),
            scope: binding.scope(),
            snapshot: binding.closed_rules_snapshot(),
            canonical_digest: *binding.digest().as_bytes(),
        }
    }

    pub(super) fn from_context(context: &'a OriginalCaptureContextV1) -> Self {
        Self {
            approval: &context.approval,
            selection: &context.selection,
            scope: &context.scope,
            snapshot: context.closed_snapshot,
            canonical_digest: context.canonical_binding_digest,
        }
    }
}
