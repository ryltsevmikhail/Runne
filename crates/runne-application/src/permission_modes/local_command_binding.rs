use runne_domain::{
    id::{IntegrityDigest, InvocationId, ProjectId},
    task_run::TaskRunLocalCommand,
};

use super::{
    binding::ApprovalBinding,
    composite::{CompositeEffectScope, CompositeScopeDigest},
    local_command_digest::local_command_permission_binding_digest,
    local_command_limits::LocalInvocationLimitsV1,
    local_command_validation::{
        LocalCommandPermissionBindingError, validate_local_command_permission_binding,
    },
    model::ModeSelection,
};

use crate::{ports::TaskRunAssignmentIdentity, project_trust::ProjectTrustEffectPolicySnapshot};

/// Canonical schema version for checked portable command permission data.
pub const LOCAL_COMMAND_PERMISSION_BINDING_SCHEMA_VERSION: u16 = 1;
/// Canonical compiler version for checked portable command permission data.
pub const LOCAL_COMMAND_PERMISSION_BINDING_COMPILER_VERSION: u16 = 1;
/// Version tag for the complete six-rule managed snapshot encoder.
pub(super) const CLOSED_RULES_ENCODER_VERSION_V2: u16 = 2;

/// Caller-supplied data checked into an immutable portable binding.
///
/// This value carries no human proof, native handle, or live admission authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalCommandPermissionBindingInputV1 {
    /// Current selection observation from the permission-mode owner.
    pub selection: ModeSelection,
    /// Immutable assignment identity returned by the committed claim.
    pub assignment: TaskRunAssignmentIdentity,
    /// Immutable claim stream version from the claim receipt, never a head read.
    pub claim_stream_version: u64,
    /// Invocation identity covered by the exact approval.
    pub invocation_id: InvocationId,
    /// Project identity associated with the held workspace root.
    pub project_id: ProjectId,
    /// Project aggregate version observed by its owner.
    pub project_version: u64,
    /// Current workspace version returned by the held-root owner.
    pub workspace_version: u64,
    /// Active root version returned separately by the held-root owner.
    pub admitted_root_version: u64,
    /// Identity digest for the currently held native root.
    pub held_root_identity_digest: IntegrityDigest,
    /// Exact bounded task-run command intent.
    pub command: TaskRunLocalCommand,
    /// Supplied legacy command digest, checked against `command.intent_digest()`.
    pub command_intent_digest: IntegrityDigest,
    /// Full exact approval compatibility key; any proof remains separately owned.
    ///
    /// The checker compares its task/attempt/invocation, principal, composite
    /// scope, and containment duplicates with this input. The remaining key
    /// fields are preserved byte-for-byte through `ApprovalBinding::digest()`.
    /// In particular, the normalized-arguments and environment digests are
    /// not inferred from the structured command here, and target identity,
    /// target version, cwd identity, and executable identity must be resolved
    /// against held objects by their trusted compiler/native owner. A target
    /// version is not a project, workspace, or admitted-root version, and this
    /// value makes no argv-file conditional-access claim. The effect-specific
    /// policy digest is also preserved as supplied; its exact projection is
    /// the approval owner's responsibility.
    pub approval: ApprovalBinding,
    /// Exact immutable composite scope covered by the approval.
    pub scope: CompositeEffectScope,
    /// Complete six-rule snapshot read under the managed-policy owner.
    pub closed_rules_snapshot: ProjectTrustEffectPolicySnapshot,
    /// Supplied canonical App V2 digest for the complete snapshot.
    pub closed_rules_digest: IntegrityDigest,
    /// One-GO invocation output and runtime limits.
    pub limits: LocalInvocationLimitsV1,
}

/// Checked, immutable, authority-free data for one X2 local-command invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalCommandPermissionBindingV1 {
    pub(super) selection: ModeSelection,
    pub(super) assignment: TaskRunAssignmentIdentity,
    pub(super) claim_stream_version: u64,
    pub(super) invocation_id: InvocationId,
    pub(super) project_id: ProjectId,
    pub(super) project_version: u64,
    pub(super) workspace_version: u64,
    pub(super) admitted_root_version: u64,
    pub(super) held_root_identity_digest: IntegrityDigest,
    pub(super) command: TaskRunLocalCommand,
    pub(super) command_intent_digest: IntegrityDigest,
    pub(super) approval: ApprovalBinding,
    pub(super) scope: CompositeEffectScope,
    pub(super) scope_digest: CompositeScopeDigest,
    pub(super) closed_rules_snapshot: ProjectTrustEffectPolicySnapshot,
    pub(super) closed_rules_digest: IntegrityDigest,
    pub(super) limits: LocalInvocationLimitsV1,
}

impl LocalCommandPermissionBindingV1 {
    /// Validates all duplicated identities and supplied canonical digests.
    pub fn checked(
        input: LocalCommandPermissionBindingInputV1,
    ) -> Result<Self, LocalCommandPermissionBindingError> {
        let scope_digest = validate_local_command_permission_binding(&input)?;
        Ok(Self {
            selection: input.selection,
            assignment: input.assignment,
            claim_stream_version: input.claim_stream_version,
            invocation_id: input.invocation_id,
            project_id: input.project_id,
            project_version: input.project_version,
            workspace_version: input.workspace_version,
            admitted_root_version: input.admitted_root_version,
            held_root_identity_digest: input.held_root_identity_digest,
            command: input.command,
            command_intent_digest: input.command_intent_digest,
            approval: input.approval,
            scope: input.scope,
            scope_digest,
            closed_rules_snapshot: input.closed_rules_snapshot,
            closed_rules_digest: input.closed_rules_digest,
            limits: input.limits,
        })
    }

    /// Returns the deterministic digest for this fully checked value.
    pub fn digest(&self) -> IntegrityDigest {
        local_command_permission_binding_digest(self)
    }

    /// Returns the immutable assignment identity from the committed claim.
    pub const fn assignment(&self) -> &TaskRunAssignmentIdentity {
        &self.assignment
    }

    /// Returns the invocation identity covered by the exact approval.
    pub const fn invocation_id(&self) -> InvocationId {
        self.invocation_id
    }

    /// Returns the project identity associated with the closed snapshot.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Returns the immutable claim stream version from the committed claim receipt.
    pub const fn claim_stream_version(&self) -> u64 {
        self.claim_stream_version
    }

    /// Returns the permission selection snapshot.
    pub const fn selection(&self) -> &ModeSelection {
        &self.selection
    }

    /// Returns the exact task-run command.
    pub const fn command(&self) -> &TaskRunLocalCommand {
        &self.command
    }

    /// Returns the checked legacy command intent digest.
    pub const fn command_intent_digest(&self) -> IntegrityDigest {
        self.command_intent_digest
    }

    /// Returns the exact approval compatibility binding.
    pub const fn approval(&self) -> &ApprovalBinding {
        &self.approval
    }

    /// Returns the complete immutable composite scope.
    pub const fn scope(&self) -> &CompositeEffectScope {
        &self.scope
    }

    /// Returns the complete six-rule managed snapshot.
    pub const fn closed_rules_snapshot(&self) -> ProjectTrustEffectPolicySnapshot {
        self.closed_rules_snapshot
    }

    /// Returns the checked canonical App V2 snapshot digest.
    pub const fn closed_rules_digest(&self) -> IntegrityDigest {
        self.closed_rules_digest
    }

    /// Returns the closed-rule encoder version included in this digest.
    pub const fn closed_rules_encoder_version(&self) -> u16 {
        CLOSED_RULES_ENCODER_VERSION_V2
    }

    /// Returns the project version observed by the workspace owner.
    pub const fn project_version(&self) -> u64 {
        self.project_version
    }

    /// Returns the current workspace version from held-root admission.
    pub const fn workspace_version(&self) -> u64 {
        self.workspace_version
    }

    /// Returns the separate active-root version from held-root admission.
    pub const fn admitted_root_version(&self) -> u64 {
        self.admitted_root_version
    }

    /// Returns the held root's identity digest.
    pub const fn held_root_identity_digest(&self) -> IntegrityDigest {
        self.held_root_identity_digest
    }

    /// Returns the one-GO limits.
    pub const fn limits(&self) -> LocalInvocationLimitsV1 {
        self.limits
    }
}
