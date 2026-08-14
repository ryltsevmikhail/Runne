#[derive(Debug, Error)]
pub enum AppCoreError {
    #[error("client storage unavailable")]
    Storage(#[from] rusqlite::Error),
    #[error("client storage unavailable")]
    StoreOpen(#[from] StoreOpenError),
    #[error("local project rejected")]
    Project(#[from] ProjectOpenError),
    #[error("recent root unavailable")]
    RecentRoot(#[from] RecentRootError),
    #[error("stored theme is invalid")]
    InvalidTheme,
    #[error("application state unavailable")]
    StateUnavailable,
    #[error("diagnostics unavailable")]
    Diagnostics(#[from] SecurityTransactionError),
    #[error("runtime is unavailable")]
    RuntimeUnavailable,
    #[error("stored conversation reference is invalid")]
    InvalidConversationReference,
    #[error("project is unavailable")]
    ProjectUnavailable,
    #[error("runtime_identity_conflict")]
    RuntimeIdentityConflict,
    #[error("local_projection_unavailable")]
    LocalProjectionUnavailable,
    #[error("replay_resync_required")]
    ReplayResyncRequired,
    #[error("runtime_revoked")]
    RuntimeRevoked,
    #[error("runtime_incompatible")]
    RuntimeIncompatible,
    #[error("anchored mutation admission is unavailable")]
    MutationUnavailable,
    #[error("mutation request is invalid")]
    InvalidMutation,
    #[error("generation provider output was rejected")]
    GenerationRejected,
    #[error("generation input was prohibited")]
    ProhibitedInputRejected,
}

/// Native-child disposition after a root admission failure.
///
/// A possible bind send preserves authoritative reconciliation rather than
/// reaping the child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeAuthorityDisposition {
    ReapBeforeDispatch,
    ReleaseWithoutReap,
}

/// Redacted failure returned by the native bind-then-open coordinator.
#[derive(Debug)]
pub struct NativeMutationFailure {
    disposition: NativeAuthorityDisposition,
}

impl NativeMutationFailure {
    #[must_use]
    pub const fn pre_dispatch() -> Self {
        Self::new(NativeAuthorityDisposition::ReapBeforeDispatch)
    }

    const fn new(disposition: NativeAuthorityDisposition) -> Self {
        Self { disposition }
    }

    #[must_use]
    pub const fn disposition(&self) -> NativeAuthorityDisposition {
        self.disposition
    }
}
