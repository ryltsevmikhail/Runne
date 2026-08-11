use std::fmt;

/// Fixed protocol failures intentionally omit platform and native-handle detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// A protected frame or state transition was not valid.
    Rejected,
    /// The injected clock was not monotonic enough to establish a safe deadline.
    ClockRegression,
    /// A deadline calculation overflowed.
    ClockOverflow,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("protected handle protocol rejected")
    }
}

impl std::error::Error for ProtocolError {}
