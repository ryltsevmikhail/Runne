use crate::permission_modes::compiler_rules::workspace_process_scope;
use crate::project_trust::{
    ManagedEffectClass, ManagedEffectDecision, ProjectTrustEffectPolicySnapshot,
    ProjectTrustProjectId, managed_effect_policy_digest_v2,
};
use runne_domain::id::IntegrityDigest;
use sha2::{Digest, Sha256};
use std::hash::{Hash, Hasher};

use super::super::{
    ChildDelegationScope, CompositeEffectScope, ContainmentStrategy, FilesystemPermission,
    FilesystemPosture, NetworkScope,
};

/// Immutable snapshot evidence. This value proves neither T1 provenance nor launch authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClosedManagedCoverageV1 {
    project: ProjectTrustProjectId,
    snapshot: ProjectTrustEffectPolicySnapshot,
    policy_digest: IntegrityDigest,
}

impl Hash for ClosedManagedCoverageV1 {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.project.hash(state);
        let status_tag = match self.snapshot.record.status {
            crate::project_trust::ProjectTrustStatus::Untrusted => 1_u8,
            crate::project_trust::ProjectTrustStatus::Trusted => 2,
            crate::project_trust::ProjectTrustStatus::Managed => 3,
        };
        status_tag.hash(state);
        self.snapshot.record.instance_epoch.hash(state);
        self.snapshot.record.revision.hash(state);
        self.snapshot.record.managed_deny_mask.hash(state);
        self.snapshot.policy.version.hash(state);
        for class in ManagedEffectClass::ALL {
            self.snapshot.policy.decision_for(class).hash(state);
        }
        self.policy_digest.hash(state);
    }
}

impl ClosedManagedCoverageV1 {
    pub(super) fn from_snapshot(
        project: ProjectTrustProjectId,
        snapshot: &ProjectTrustEffectPolicySnapshot,
    ) -> Option<Self> {
        if project.as_bytes().iter().all(|byte| *byte == 0) {
            return None;
        }
        let policy_digest =
            IntegrityDigest::from_bytes(managed_effect_policy_digest_v2(project, snapshot)?);
        Some(Self {
            project,
            snapshot: *snapshot,
            policy_digest,
        })
    }

    pub(crate) const fn policy_digest(self) -> IntegrityDigest {
        self.policy_digest
    }

    pub(crate) const fn disposition(self, class: ManagedEffectClass) -> ManagedEffectDecision {
        self.snapshot.policy.decision_for(class)
    }

    pub(crate) fn scope_minimum_disposition(
        self,
        scope: &CompositeEffectScope,
    ) -> ManagedEffectDecision {
        let mut minimum = ManagedEffectDecision::Allow;
        let mut add = |class| {
            minimum = stricter(minimum, self.disposition(class));
        };
        if scope.containment == ContainmentStrategy::SameUserCompositeV2 {
            for right in &scope.filesystem.permissions {
                add(class_for_right(*right));
            }
            // Content-capable creation requires the separately governed write class.
            if scope
                .filesystem
                .permissions
                .contains(&FilesystemPermission::Create)
            {
                add(ManagedEffectClass::FsWrite);
            }
            if matches!(scope.filesystem.posture, FilesystemPosture::BroadSameUser) {
                add(ManagedEffectClass::ProcessStart);
                if !scope.network.is_none() {
                    add(ManagedEffectClass::NetworkUse);
                }
            }
            return minimum;
        }
        match &scope.filesystem.posture {
            FilesystemPosture::BroadSameUser => {
                for class in [
                    ManagedEffectClass::FsRead,
                    ManagedEffectClass::FsCreate,
                    ManagedEffectClass::FsWrite,
                    ManagedEffectClass::FsDelete,
                    ManagedEffectClass::ProcessStart,
                ] {
                    add(class);
                }
                if scope.network.is_broad() {
                    add(ManagedEffectClass::NetworkUse);
                }
            }
            FilesystemPosture::BoundedRoots(_) => {
                if workspace_process_scope(scope) {
                    add(ManagedEffectClass::ProcessStart);
                }
                for right in &scope.filesystem.permissions {
                    add(class_for_right(*right));
                }
            }
            FilesystemPosture::None => {}
        }
        minimum
    }

    pub(crate) fn supports_scope(self, scope: &CompositeEffectScope) -> bool {
        if workspace_process_scope(scope) {
            return scope.managed_policy.policy_digest() == self.policy_digest
                && self.disposition(ManagedEffectClass::ProcessStart)
                    != ManagedEffectDecision::Deny
                && scope.filesystem.permissions.iter().all(|right| {
                    self.disposition(class_for_right(*right)) != ManagedEffectDecision::Deny
                });
        }
        if scope.containment == ContainmentStrategy::SameUserCompositeV2 {
            return self.supports_scope_shape(scope);
        }
        let required = match (&scope.filesystem.posture, scope.containment, scope.network) {
            (
                FilesystemPosture::BroadSameUser,
                ContainmentStrategy::SameUserCompositeV1,
                NetworkScope::BroadSameUser,
            ) => [
                Some(ManagedEffectClass::FsRead),
                Some(ManagedEffectClass::FsCreate),
                Some(ManagedEffectClass::FsWrite),
                Some(ManagedEffectClass::FsDelete),
                Some(ManagedEffectClass::ProcessStart),
                Some(ManagedEffectClass::NetworkUse),
            ],
            (
                FilesystemPosture::BroadSameUser,
                ContainmentStrategy::SameUserCompositeV1,
                NetworkScope::None,
            ) => [
                Some(ManagedEffectClass::FsRead),
                Some(ManagedEffectClass::FsCreate),
                Some(ManagedEffectClass::FsWrite),
                Some(ManagedEffectClass::FsDelete),
                Some(ManagedEffectClass::ProcessStart),
                None,
            ],
            (
                FilesystemPosture::BoundedRoots(_),
                ContainmentStrategy::WorkspaceBoundV1,
                NetworkScope::None,
            ) => [None; 6],
            _ => return false,
        };
        if scope.managed_policy.policy_digest() != self.policy_digest {
            return false;
        }
        if matches!(scope.filesystem.posture, FilesystemPosture::BroadSameUser)
            && ![
                FilesystemPermission::Read,
                FilesystemPermission::Create,
                FilesystemPermission::Write,
                FilesystemPermission::Delete,
            ]
            .iter()
            .all(|right| scope.filesystem.permissions.contains(right))
        {
            return false;
        }
        if matches!(scope.filesystem.posture, FilesystemPosture::BoundedRoots(_))
            && (scope.filesystem.permissions.is_empty()
                || scope.children != ChildDelegationScope::None)
        {
            return false;
        }
        if matches!(scope.filesystem.posture, FilesystemPosture::BroadSameUser)
            && scope.children != ChildDelegationScope::Unbounded
        {
            return false;
        }
        required
            .into_iter()
            .flatten()
            .all(|class| self.snapshot.policy.decision_for(class) != ManagedEffectDecision::Deny)
            && scope.filesystem.permissions.iter().all(|right| {
                self.snapshot.policy.decision_for(class_for_right(*right))
                    != ManagedEffectDecision::Deny
            })
    }

    pub(crate) fn supports_scope_shape(self, scope: &CompositeEffectScope) -> bool {
        if workspace_process_scope(scope) {
            return scope.managed_policy.policy_digest() == self.policy_digest;
        }
        if scope.managed_policy.policy_digest() != self.policy_digest {
            return false;
        }
        let rights_are_known = scope.filesystem.permissions.iter().all(|right| {
            matches!(
                right,
                FilesystemPermission::Read
                    | FilesystemPermission::Create
                    | FilesystemPermission::Write
                    | FilesystemPermission::Delete
            )
        });
        if !rights_are_known {
            return false;
        }
        match (&scope.filesystem.posture, scope.containment, scope.network) {
            (
                FilesystemPosture::BroadSameUser,
                ContainmentStrategy::SameUserCompositeV2,
                NetworkScope::BroadSameUser | NetworkScope::None,
            ) => {
                scope.children == ChildDelegationScope::Unbounded
                    && scope.budget.max_operations.is_none()
                    && scope.budget.max_bytes.is_none()
            }
            (
                FilesystemPosture::BoundedRoots(_),
                ContainmentStrategy::WorkspaceBoundV1,
                NetworkScope::None,
            ) => {
                !scope.filesystem.permissions.is_empty()
                    && scope.children == ChildDelegationScope::None
            }
            _ => false,
        }
    }

    pub(crate) fn update_composite_v2_digest(self, hash: &mut Sha256) {
        hash.update(self.project.as_bytes());
        hash.update([match self.snapshot.record.status {
            crate::project_trust::ProjectTrustStatus::Untrusted => 1,
            crate::project_trust::ProjectTrustStatus::Trusted => 2,
            crate::project_trust::ProjectTrustStatus::Managed => 3,
        }]);
        hash.update(self.snapshot.record.managed_deny_mask.to_be_bytes());
        hash.update(self.snapshot.record.instance_epoch.to_be_bytes());
        hash.update(self.snapshot.record.revision.to_be_bytes());
        hash.update(self.snapshot.policy.version.to_be_bytes());
        for class in ManagedEffectClass::ALL {
            let decision = self.snapshot.policy.decision_for(class);
            hash.update([class.tag(), decision.tag()]);
        }
        hash.update(crate::project_trust::FROZEN_POLICY_VERSION.to_be_bytes());
        hash.update(crate::project_trust::LOCAL_COMMAND_POLICY_VERSION.to_be_bytes());
        hash.update(self.policy_digest.as_bytes());
    }
}

impl NetworkScope {
    pub(crate) const fn is_broad(self) -> bool {
        matches!(self, Self::BroadSameUser)
    }

    pub(crate) const fn is_none(self) -> bool {
        matches!(self, Self::None)
    }
}

fn class_for_right(right: FilesystemPermission) -> ManagedEffectClass {
    match right {
        FilesystemPermission::Read => ManagedEffectClass::FsRead,
        FilesystemPermission::Create => ManagedEffectClass::FsCreate,
        FilesystemPermission::Write => ManagedEffectClass::FsWrite,
        FilesystemPermission::Delete => ManagedEffectClass::FsDelete,
    }
}

fn stricter(left: ManagedEffectDecision, right: ManagedEffectDecision) -> ManagedEffectDecision {
    use ManagedEffectDecision::{Allow, Ask, Deny};
    match (left, right) {
        (Deny, _) | (_, Deny) => Deny,
        (Ask, _) | (_, Ask) => Ask,
        _ => Allow,
    }
}
