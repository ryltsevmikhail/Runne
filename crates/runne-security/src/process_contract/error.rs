//! Closed, marker-safe process contract errors.

use core::fmt;

/// Closed failures that never carry process input or provider data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessContractError {
    /// Intent encoding or platform input was malformed.
    IntentMalformed,
    /// A required input or output bound was exceeded.
    InputBoundsExceeded,
    /// The exact environment was not authorized by an internal grant.
    EnvironmentNotGranted,
    /// An environment name can shape execution despite an exact internal grant.
    EnvironmentDenied,
    /// Canonical digest encoding could not represent the intent.
    DigestEncodingInvalid,
    /// Capability was expired, replayed, or did not exactly bind the intent.
    CapabilityInvalid,
    /// Trusted executable verification no longer matches the sealed intent.
    ExecutableVerificationFailed,
    /// Trusted working-directory verification no longer matches the sealed intent.
    CwdVerificationFailed,
    /// Approval was expired, denied, or did not exactly bind the intent.
    ApprovalInvalid,
}

impl fmt::Display for ProcessContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::IntentMalformed => "process intent is malformed",
            Self::InputBoundsExceeded => "process input bounds were exceeded",
            Self::EnvironmentNotGranted => "process environment is not granted",
            Self::EnvironmentDenied => "process environment name is denied",
            Self::DigestEncodingInvalid => "process digest encoding is invalid",
            Self::CapabilityInvalid => "process capability is invalid",
            Self::ExecutableVerificationFailed => "process executable verification failed",
            Self::CwdVerificationFailed => "process working directory verification failed",
            Self::ApprovalInvalid => "process approval is invalid",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ProcessContractError {}
