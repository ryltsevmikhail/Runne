//! Закрытые ошибки security application-слоя.

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityError {
    GrantNotFound,
    GrantNotActive,
    GrantExpired,
    GrantRevoked,
    ScopeMismatch,
    ActionMismatch,
    ResourceMismatch,
    ConstraintMismatch,
    StaleAuthEpoch,
    StaleGeneration,
    ApprovalExpired,
    ApprovalDenied,
    ApprovalAlreadyDecided,
    GrantRequired,
    BudgetUnavailable,
    SandboxUnavailable,
    StorageUnavailable,
    ArithmeticOverflow,
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::GrantNotFound => "grant not found",
            Self::GrantNotActive => "grant is not active",
            Self::GrantExpired => "grant has expired",
            Self::GrantRevoked => "grant has been revoked",
            Self::ScopeMismatch => "grant scope does not cover request",
            Self::ActionMismatch => "grant action does not cover request",
            Self::ResourceMismatch => "grant resource does not cover request",
            Self::ConstraintMismatch => "grant constraints do not cover request",
            Self::StaleAuthEpoch => "authorization epoch is stale",
            Self::StaleGeneration => "generation is stale",
            Self::ApprovalExpired => "approval request has expired",
            Self::ApprovalDenied => "approval was denied",
            Self::ApprovalAlreadyDecided => "approval already has a decision",
            Self::GrantRequired => "an active grant is required",
            Self::BudgetUnavailable => "budget reservation is unavailable",
            Self::SandboxUnavailable => "sandbox permit is unavailable",
            Self::StorageUnavailable => "security storage is unavailable",
            Self::ArithmeticOverflow => "security counter overflow",
        };
        f.write_str(message)
    }
}

impl std::error::Error for SecurityError {}
