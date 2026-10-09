//! Exact, immutable invocation approval compatibility binding.

use runne_api::ApiPrincipalId;
use runne_domain::id::{AttemptId, IntegrityDigest, InvocationId, TaskRunId};
use sha2::{Digest, Sha256};

use super::{
    composite::{CompositeScopeDigest, ContainmentStrategy},
    resource::PermissionAction,
};

/// Canonical task, attempt, and invocation identities covered by approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvocationIdentity {
    /// Runtime task run owning this effect.
    pub task_run_id: TaskRunId,
    /// Concrete attempt making the effect.
    pub attempt_id: AttemptId,
    /// Canonical tool invocation approval unit.
    pub invocation_id: InvocationId,
}

/// Exact immutable approval compatibility key for one invocation.
///
/// Message identity, transport authentication epoch, and the raw current
/// authorization revision are intentionally absent. A compatible binding
/// survives an unrelated message or transport refresh; its caller must still
/// check current mode authority, expiry, task state, cancellation and managed
/// policy at the durable effect boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalBinding {
    /// Canonical taxonomy action.
    pub action: PermissionAction,
    /// Digest of normalized exact arguments.
    pub normalized_arguments_digest: IntegrityDigest,
    /// Digest of the exact tool schema version.
    pub tool_schema_digest: IntegrityDigest,
    /// Principal authenticated at trusted ingress.
    pub principal_id: ApiPrincipalId,
    /// Task/attempt/invocation approval identity.
    pub invocation: InvocationIdentity,
    /// Held target identity, not a caller path string.
    pub target_identity_digest: IntegrityDigest,
    /// Observed target version or precondition generation.
    pub target_version: u64,
    /// Exact environment map digest.
    pub environment_digest: IntegrityDigest,
    /// Held current-working-directory identity digest.
    pub cwd_identity_digest: IntegrityDigest,
    /// Initial sealed executable identity, when the action starts a process.
    pub executable_digest: Option<IntegrityDigest>,
    /// Complete filesystem/network/child/budget/containment scope digest.
    pub composite_scope_digest: CompositeScopeDigest,
    /// Concrete containment strategy covered by approval.
    pub containment_version: ContainmentStrategy,
    /// Digest of only the policy semantics relevant to this effect.
    pub relevant_policy_digest: IntegrityDigest,
    /// Exact expiry in Unix milliseconds.
    pub expires_at_unix_ms: i64,
}

impl ApprovalBinding {
    /// Whether the held approval still matches an exact candidate invocation.
    pub fn is_compatible_with(&self, candidate: &Self, now_unix_ms: i64) -> bool {
        self == candidate && now_unix_ms < self.expires_at_unix_ms
    }

    /// Canonical SHA-256 over every compatibility field with domain separation.
    pub fn digest(&self) -> IntegrityDigest {
        let mut hash = Sha256::new();
        hash.update(b"runne:d21:invocation-approval-binding:v1\0");
        hash.update([action_tag(self.action)]);
        hash.update(self.normalized_arguments_digest.as_bytes());
        hash.update(self.tool_schema_digest.as_bytes());
        put_bytes(&mut hash, self.principal_id.as_str().as_bytes());
        hash.update(self.invocation.task_run_id.as_bytes());
        hash.update(self.invocation.attempt_id.as_bytes());
        hash.update(self.invocation.invocation_id.as_bytes());
        hash.update(self.target_identity_digest.as_bytes());
        hash.update(self.target_version.to_be_bytes());
        hash.update(self.environment_digest.as_bytes());
        hash.update(self.cwd_identity_digest.as_bytes());
        match self.executable_digest {
            Some(digest) => {
                hash.update([1]);
                hash.update(digest.as_bytes());
            }
            None => hash.update([0]),
        }
        hash.update(self.composite_scope_digest.as_bytes());
        hash.update([containment_tag(self.containment_version)]);
        hash.update(self.relevant_policy_digest.as_bytes());
        hash.update(self.expires_at_unix_ms.to_be_bytes());
        IntegrityDigest::from_bytes(hash.finalize().into())
    }
}

fn action_tag(action: PermissionAction) -> u8 {
    match action {
        PermissionAction::FsRead => 1,
        PermissionAction::FsCreate => 2,
        PermissionAction::FsWrite => 3,
        PermissionAction::FsDelete => 4,
        PermissionAction::NetworkConnect => 5,
        PermissionAction::NetworkSend => 6,
        PermissionAction::ProcessStart => 7,
    }
}

fn containment_tag(strategy: ContainmentStrategy) -> u8 {
    match strategy {
        ContainmentStrategy::WorkspaceBoundV1 => 1,
        ContainmentStrategy::SameUserCompositeV1 => 2,
        ContainmentStrategy::SameUserCompositeV2 => 3,
    }
}

fn put_bytes(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u32).to_be_bytes());
    hash.update(value);
}
