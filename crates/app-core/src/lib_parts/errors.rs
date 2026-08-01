#[derive(Debug, Error)]
pub enum AppCoreError {
    #[error("client storage unavailable")]
    Storage(#[from] rusqlite::Error),
    #[error("client storage unavailable")]
    StoreOpen(#[from] StoreOpenError),
    #[error("local project rejected")]
    Project(#[from] ProjectOpenError),
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
}
