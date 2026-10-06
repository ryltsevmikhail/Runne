//! Stable errors for permission-mode command and effect admission boundaries.

use thiserror::Error;

/// Closed error vocabulary shared by runtime mode commands and projections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PermissionModeError {
    /// The requested mode revision is stale.
    #[error("permission mode revision is stale")]
    StaleRevision,
    /// The same idempotency key was reused for another semantic command.
    #[error("permission mode idempotency conflict")]
    IdempotencyConflict,
    /// Full access lacks a fresh proof bound to this exact command.
    #[error("fresh full-access re-authentication is required")]
    ReauthenticationRequired,
    /// Managed policy denied the requested selection or effect.
    #[error("permission mode denied by managed policy")]
    PolicyDenied,
    /// Required native enforcement is unavailable.
    #[error("permission mode enforcement is unavailable")]
    EnforcementUnavailable,
    /// The selected permission grant or challenge has expired.
    #[error("permission mode authority expired")]
    Expired,
    /// The invocation or mode change was cancelled before authorization.
    #[error("permission mode operation was cancelled")]
    Cancelled,
    /// A started effect needs reconciliation before another release.
    #[error("permission mode effect requires reconciliation")]
    ReconciliationRequired,
    /// The requested composite scope has no enforceable representation.
    #[error("composite permission scope is unenforceable")]
    CompositePolicyUnenforceable,
    /// This runtime does not implement the requested preset generation.
    #[error("permission mode preset version is unsupported")]
    UnsupportedPresetVersion,
    /// The canonical intent digest does not match the submitted semantics.
    #[error("permission mode intent digest is invalid")]
    InvalidIntentDigest,
    /// A non-full-access command carried proof or challenge state.
    #[error("unexpected re-authentication proof")]
    UnexpectedReauthenticationProof,
}
