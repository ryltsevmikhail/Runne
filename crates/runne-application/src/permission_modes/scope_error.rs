//! Stable fail-closed errors for malformed composite effect scopes.

/// Invalid, ambiguous, or noncanonical scope input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeError {
    /// A filesystem component was empty, dot, parent, or contained a separator.
    InvalidPathComponent,
    /// A held filesystem root identity was the zero digest.
    InvalidRootIdentity,
    /// Scope omitted its protected-control-plane policy digest.
    MissingProtectedControlPlanePolicy,
    /// Broad networking requires the same-user composite namespace strategy.
    BroadNetworkRequiresCompositeContainment,
    /// Broad filesystem access requires the same-user composite namespace strategy.
    BroadFilesystemRequiresCompositeContainment,
    /// Composite scopes require a nonzero managed-policy digest.
    MissingManagedPolicyDigest,
    /// Broad filesystem and network posture must be requested together.
    BroadFilesystemRequiresBroadNetwork,
    /// Bounded root policy must contain at least one explicit root.
    EmptyBoundedRoots,
    /// Two bounded filesystem roots overlap under the same held identity.
    OverlappingFilesystemRoots,
    /// Invocation scopes require a finite positive lifetime.
    ZeroLifetime,
    /// Authority, principal, or workspace identity is invalid.
    InvalidPermissionScope,
}
