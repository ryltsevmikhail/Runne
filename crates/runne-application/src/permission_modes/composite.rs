//! Canonical composite effect scope for process invocations and child grants.

use std::collections::BTreeSet;

use runne_domain::id::IntegrityDigest;

use super::attenuation::root_contains;
use super::model::PermissionScope;
use super::scope_error::ScopeError;

/// Opaque SHA-256 identity for one canonical composite scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CompositeScopeDigest(IntegrityDigest);

impl CompositeScopeDigest {
    /// Creates a digest from its canonical 32-byte representation.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(IntegrityDigest::from_bytes(bytes))
    }

    /// Returns canonical digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

/// Filesystem operation enabled inside a granted root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FilesystemPermission {
    Read,
    Create,
    Write,
    Delete,
}

/// Held root identity and canonical relative path components.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FilesystemRoot {
    /// Opaque held root identity supplied by runtime admission.
    pub root_identity: IntegrityDigest,
    /// Canonical relative components below that root; empty means its root.
    pub components: Vec<String>,
}

impl FilesystemRoot {
    /// Builds a root after rejecting noncanonical path components.
    pub fn new(
        root_identity: IntegrityDigest,
        components: Vec<String>,
    ) -> Result<Self, ScopeError> {
        if root_identity.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(ScopeError::InvalidRootIdentity);
        }
        if components.iter().any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || part.contains('/')
                || part.contains('\\')
                || part.chars().any(char::is_control)
        }) {
            return Err(ScopeError::InvalidPathComponent);
        }
        Ok(Self {
            root_identity,
            components,
        })
    }
}

/// Granted filesystem roots and operations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FilesystemScope {
    /// Explicit roots or an explicit same-user breadth marker.
    pub posture: FilesystemPosture,
    /// Operations allowed beneath every root in this scope.
    pub permissions: BTreeSet<FilesystemPermission>,
}

/// Empty roots never mean broad filesystem access.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum FilesystemPosture {
    /// No filesystem resources are admitted.
    #[default]
    None,
    /// Only held root identities and relative subtrees are admitted.
    BoundedRoots(BTreeSet<FilesystemRoot>),
    /// Ordinary same-user filesystem breadth inside protected namespaces.
    BroadSameUser,
}

/// Network posture included in an immutable process scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkScope {
    /// No network effects are admitted.
    None,
    /// Network effects use the exact named broker policy digest.
    Brokered { policy_digest: IntegrityDigest },
    /// Broad same-user network inside the admitted namespace boundary.
    BroadSameUser,
}

/// Child process delegation limit; `None` means descendants cannot widen scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChildDelegationScope {
    /// No descendants receive delegated effects.
    None,
    /// Descendants are allowed to this finite depth.
    MaxDepth(u16),
    /// Descendants inherit attenuation without a depth limit.
    Unbounded,
}

/// Managed policy class from one global snapshot, copied unchanged to related
/// broad and attenuated scopes so attenuation preserves the same semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ManagedPolicyCoverage {
    /// The runtime matched this digest and found no applicable restrictive rules.
    Unrestricted { policy_digest: IntegrityDigest },
    /// The snapshot has restrictive rules; each invocation still receives its
    /// own exact Allow/Ask/Deny result from the managed-policy owner.
    Restricted { policy_digest: IntegrityDigest },
}

impl ManagedPolicyCoverage {
    /// Digest that must be bound to admission, approval, and the effect release.
    pub const fn policy_digest(self) -> IntegrityDigest {
        match self {
            Self::Unrestricted { policy_digest } | Self::Restricted { policy_digest } => {
                policy_digest
            }
        }
    }

    /// Whether the exact composite scope has no restrictive managed rules.
    pub const fn is_unrestricted(self) -> bool {
        matches!(self, Self::Unrestricted { .. })
    }
}

/// Finite effect budget, where `None` means unbounded in that dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EffectBudget {
    /// Maximum number of effect operations.
    pub max_operations: Option<u64>,
    /// Maximum aggregate bytes read or written.
    pub max_bytes: Option<u64>,
}

/// Versioned containment strategies understood by this contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContainmentStrategy {
    /// Existing workspace-root confinement.
    WorkspaceBoundV1,
    /// Admitted broad same-user filesystem/network namespace strategy.
    SameUserCompositeV1,
}

/// Immutable filesystem/network/child/budget/lifetime process grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositeEffectScope {
    /// Exact runtime authority, authenticated principal, and workspace scope.
    pub permission_scope: PermissionScope,
    /// Filesystem roots and rights.
    pub filesystem: FilesystemScope,
    /// Network destination posture.
    pub network: NetworkScope,
    /// Matched managed-policy coverage and digest for the complete scope.
    pub managed_policy: ManagedPolicyCoverage,
    /// Descendant delegation ceiling.
    pub children: ChildDelegationScope,
    /// Effect operation and byte budgets.
    pub budget: EffectBudget,
    /// Maximum invocation lifetime in milliseconds.
    pub lifetime_ms: u64,
    /// Enforcement strategy that must be present before release.
    pub containment: ContainmentStrategy,
    /// Digest of held protected-root identities and control-plane isolation strategy.
    pub protected_control_plane_policy_digest: IntegrityDigest,
}

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
        if self.containment == ContainmentStrategy::SameUserCompositeV1
            && self
                .protected_control_plane_policy_digest
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(ScopeError::MissingProtectedControlPlanePolicy);
        }
        if self.network == NetworkScope::BroadSameUser
            && self.containment != ContainmentStrategy::SameUserCompositeV1
        {
            return Err(ScopeError::BroadNetworkRequiresCompositeContainment);
        }
        if matches!(self.filesystem.posture, FilesystemPosture::BroadSameUser)
            && self.containment != ContainmentStrategy::SameUserCompositeV1
        {
            return Err(ScopeError::BroadFilesystemRequiresCompositeContainment);
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
        if matches!(self.filesystem.posture, FilesystemPosture::BroadSameUser)
            && self.network != NetworkScope::BroadSameUser
        {
            return Err(ScopeError::BroadFilesystemRequiresBroadNetwork);
        }
        let roots = match &self.filesystem.posture {
            FilesystemPosture::BoundedRoots(roots) if roots.is_empty() => {
                return Err(ScopeError::EmptyBoundedRoots);
            }
            FilesystemPosture::BoundedRoots(roots) => roots,
            _ => return self.validate_lifetime(),
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
