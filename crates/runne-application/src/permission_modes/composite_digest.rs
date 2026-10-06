//! Canonical versioned encoding for immutable composite effect scopes.

use sha2::{Digest, Sha256};

use super::composite::{
    ChildDelegationScope, CompositeEffectScope, CompositeScopeDigest, ContainmentStrategy,
    FilesystemPermission, FilesystemPosture, NetworkScope,
};
use super::scope_error::ScopeError;

impl CompositeEffectScope {
    /// SHA-256 over every scope field after validating canonical scope shape.
    pub fn digest(&self) -> Result<CompositeScopeDigest, ScopeError> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"runne:d21:composite-effect-scope:v1\0");
        put_bytes(
            &mut hash,
            self.permission_scope.runtime_authority_id.0.as_bytes(),
        );
        put_bytes(
            &mut hash,
            self.permission_scope.principal_id.as_str().as_bytes(),
        );
        hash.update(self.permission_scope.workspace_id.as_bytes());
        hash.update(self.protected_control_plane_policy_digest.as_bytes());
        hash.update(self.managed_policy.policy_digest().as_bytes());
        hash.update([u8::from(self.managed_policy.is_unrestricted())]);
        hash.update([containment_tag(self.containment)]);
        hash_filesystem(&mut hash, &self.filesystem.posture);
        hash.update((self.filesystem.permissions.len() as u32).to_be_bytes());
        for permission in &self.filesystem.permissions {
            hash.update([filesystem_permission_tag(*permission)]);
        }
        hash_network(&mut hash, self.network);
        hash_child_scope(&mut hash, self.children);
        put_option_u64(&mut hash, self.budget.max_operations);
        put_option_u64(&mut hash, self.budget.max_bytes);
        hash.update(self.lifetime_ms.to_be_bytes());
        Ok(CompositeScopeDigest::from_bytes(hash.finalize().into()))
    }
}

fn hash_filesystem(hash: &mut Sha256, posture: &FilesystemPosture) {
    match posture {
        FilesystemPosture::None => hash.update([0]),
        FilesystemPosture::BoundedRoots(roots) => {
            hash.update([1]);
            hash.update((roots.len() as u32).to_be_bytes());
            for root in roots {
                hash.update(root.root_identity.as_bytes());
                hash.update((root.components.len() as u32).to_be_bytes());
                for part in &root.components {
                    put_bytes(hash, part.as_bytes());
                }
            }
        }
        FilesystemPosture::BroadSameUser => hash.update([2]),
    }
}

fn hash_network(hash: &mut Sha256, network: NetworkScope) {
    match network {
        NetworkScope::None => hash.update([0]),
        NetworkScope::Brokered { policy_digest } => {
            hash.update([1]);
            hash.update(policy_digest.as_bytes());
        }
        NetworkScope::BroadSameUser => hash.update([2]),
    }
}

fn hash_child_scope(hash: &mut Sha256, scope: ChildDelegationScope) {
    match scope {
        ChildDelegationScope::None => hash.update([0]),
        ChildDelegationScope::MaxDepth(depth) => {
            hash.update([1]);
            hash.update(depth.to_be_bytes());
        }
        ChildDelegationScope::Unbounded => hash.update([2]),
    }
}

fn containment_tag(strategy: ContainmentStrategy) -> u8 {
    match strategy {
        ContainmentStrategy::WorkspaceBoundV1 => 1,
        ContainmentStrategy::SameUserCompositeV1 => 2,
    }
}

fn filesystem_permission_tag(permission: FilesystemPermission) -> u8 {
    match permission {
        FilesystemPermission::Read => 1,
        FilesystemPermission::Create => 2,
        FilesystemPermission::Write => 3,
        FilesystemPermission::Delete => 4,
    }
}

fn put_bytes(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u32).to_be_bytes());
    hash.update(bytes);
}

fn put_option_u64(hash: &mut Sha256, value: Option<u64>) {
    match value {
        Some(value) => {
            hash.update([1]);
            hash.update(value.to_be_bytes());
        }
        None => hash.update([0]),
    }
}
