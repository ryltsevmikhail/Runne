//! Stable failures for the macOS structured-command adapter.

/// Closed launch failures. Native paths and operating-system details are not retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MacOsCommandError {
    /// Required native restrictions or delegates are unavailable.
    #[error("protected macOS command execution unavailable")]
    Unavailable,
    /// This composite scope cannot be represented by the admitted profile.
    #[error("macOS composite process scope cannot be enforced")]
    CompositePolicyUnenforceable,
    /// The structured command or held descriptor set is invalid.
    #[error("structured macOS command is invalid")]
    Invalid,
    /// Gate, exact-area attach, or child-state proof failed.
    #[error("macOS command gate is unverified")]
    Unverified,
    /// Child wait exceeded the caller's bounded policy.
    #[error("macOS command wait timed out")]
    Timeout,
    /// Process-area lifecycle operation failed.
    #[error("managed process area operation failed")]
    Area,
}
