//! Stable failures for the gated Linux command adapter.

use crate::process_managed_area::ManagedAreaError;

/// Closed launch failures. Native paths and operating-system details are not retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LinuxCommandError {
    /// Required kernel restrictions or delegated cgroup support are unavailable.
    #[error("protected Linux command execution unavailable")]
    Unavailable,
    /// This composite scope cannot be represented by the admitted Linux profile.
    #[error("Linux composite process scope cannot be enforced")]
    CompositePolicyUnenforceable,
    /// The structured command or held descriptor set is invalid.
    #[error("structured Linux command is invalid")]
    Invalid,
    /// Gate, exact-area attach, or child-state proof failed.
    #[error("Linux command gate is unverified")]
    Unverified,
    /// Child wait exceeded the caller's bounded policy.
    #[error("Linux command wait timed out")]
    Timeout,
    /// Exact managed-area lifecycle operation failed.
    #[error("managed process area operation failed")]
    Area,
}

impl From<ManagedAreaError> for LinuxCommandError {
    fn from(_: ManagedAreaError) -> Self {
        Self::Area
    }
}
