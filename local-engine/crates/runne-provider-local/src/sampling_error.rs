//! Sampling errors: bounded, typed (SAMPLING §Traceability /
//! ERRORS). Debug names are contract surface.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SamplingError {
    /// Per-call value outside the BackendProfile hard bounds; never
    /// clamped (LOCAL-INV-008).
    OutOfRange(&'static str),
    /// Unknown key inside the `local-engine.sampling.v1` map.
    UnknownField(String),
    /// Non-integer, wrong type, or structurally malformed profile.
    Malformed,
    /// Profile serialization exceeds the 1 KiB budget.
    Oversize,
    /// `reasoning_effort` set while the backend profile does not
    /// support reasoning.
    ReasoningEffortUnsupported,
}

impl fmt::Display for SamplingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange(k) => write!(f, "sampling out of range: {k}"),
            Self::UnknownField(k) => write!(f, "unknown sampling field: {k}"),
            Self::Malformed => write!(f, "malformed sampling profile"),
            Self::Oversize => write!(f, "sampling profile over 1 KiB budget"),
            Self::ReasoningEffortUnsupported => {
                write!(f, "reasoning effort unsupported by backend profile")
            }
        }
    }
}

impl std::error::Error for SamplingError {}
