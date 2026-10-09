use super::super::{attenuation::root_contains, scope_error::ScopeError};
use super::{CompositeEffectScope, ContainmentStrategy, FilesystemPosture, NetworkScope};

impl CompositeEffectScope {
    /// Rejects broad scopes without explicit protected-control-plane policy identity.
    pub fn validate(&self) -> Result<(), ScopeError> {
        if self.permission_scope.runtime_authority_id.0.is_empty()
            || self.permission_scope.runtime_authority_id.0.len() > 256
            || self
                .permission_scope
                .runtime_authority_id
                .0
                .chars()
                .any(char::is_control)
            || self
                .permission_scope
                .workspace_id
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(ScopeError::InvalidPermissionScope);
        }
        if self
            .protected_control_plane_policy_digest
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(ScopeError::MissingProtectedControlPlanePolicy);
        }
        if self
            .managed_policy
            .policy_digest()
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(ScopeError::MissingManagedPolicyDigest);
        }
        if self.network.is_broad()
            && !matches!(
                self.containment,
                ContainmentStrategy::SameUserCompositeV1 | ContainmentStrategy::SameUserCompositeV2
            )
        {
            return Err(ScopeError::BroadNetworkRequiresCompositeContainment);
        }
        if matches!(self.filesystem.posture, FilesystemPosture::BroadSameUser)
            && !matches!(
                self.containment,
                ContainmentStrategy::SameUserCompositeV1 | ContainmentStrategy::SameUserCompositeV2
            )
        {
            return Err(ScopeError::BroadFilesystemRequiresCompositeContainment);
        }
        if self.managed_policy.is_closed()
            && !matches!(
                self.network,
                NetworkScope::None | NetworkScope::BroadSameUser
            )
        {
            return Err(ScopeError::BroadFilesystemRequiresBroadNetwork);
        }
        if matches!(self.filesystem.posture, FilesystemPosture::BroadSameUser)
            && self.network != NetworkScope::BroadSameUser
            && !(self.network == NetworkScope::None && self.managed_policy.is_closed())
        {
            return Err(ScopeError::BroadFilesystemRequiresBroadNetwork);
        }
        if self.managed_policy.is_closed()
            && matches!(self.filesystem.posture, FilesystemPosture::BroadSameUser)
            && (self.budget.max_operations.is_some() || self.budget.max_bytes.is_some())
        {
            return Err(ScopeError::UnsupportedBroadEffectQuota);
        }
        if self.containment == ContainmentStrategy::SameUserCompositeV2
            && (!self.managed_policy.is_closed()
                || !matches!(self.filesystem.posture, FilesystemPosture::BroadSameUser))
        {
            return Err(ScopeError::BroadFilesystemRequiresCompositeContainment);
        }
        let roots = match &self.filesystem.posture {
            FilesystemPosture::None => return self.validate_lifetime(),
            FilesystemPosture::BoundedRoots(roots) if roots.is_empty() => {
                return Err(ScopeError::EmptyBoundedRoots);
            }
            FilesystemPosture::BoundedRoots(roots) => roots,
            FilesystemPosture::BroadSameUser => return self.validate_lifetime(),
        };
        for root in roots {
            if root.root_identity.as_bytes().iter().all(|byte| *byte == 0) {
                return Err(ScopeError::InvalidRootIdentity);
            }
            if root.components.iter().any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || part.contains('/')
                    || part.contains('\\')
                    || part.chars().any(char::is_control)
            }) {
                return Err(ScopeError::InvalidPathComponent);
            }
        }
        if roots.iter().enumerate().any(|(index, root)| {
            roots
                .iter()
                .skip(index + 1)
                .any(|other| root_contains(root, other) || root_contains(other, root))
        }) {
            return Err(ScopeError::OverlappingFilesystemRoots);
        }
        self.validate_lifetime()
    }

    fn validate_lifetime(&self) -> Result<(), ScopeError> {
        if self.lifetime_ms == 0 {
            Err(ScopeError::ZeroLifetime)
        } else {
            Ok(())
        }
    }
}
