/// Bounded fixture value limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixtureLimits {
    pub(crate) max_bytes: usize,
    pub(crate) max_depth: usize,
    pub(crate) max_items: usize,
    pub(crate) max_string_bytes: usize,
}

impl Default for FixtureLimits {
    fn default() -> Self { Self { max_bytes: 16_384, max_depth: 8, max_items: 64, max_string_bytes: 1_024 } }
}

/// Typed fixture approval policy; it never grants production authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureApprovalPolicy {
    /// Reject every call.
    AlwaysDeny,
    /// Require an exact approval for the capability.
    ExplicitPerCall,
    /// Require an externally issued exact approval receipt; never allow automatically.
    PreApprovedExactIntent,
    /// Deterministic fixture-only permit.
    FixtureDeterministicAllow,
}

/// Terminal call disposition without protocol payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureCallResult {
    /// Correlated terminal proof completed once.
    Completed,
    /// An effect may have occurred without terminal proof.
    Uncertain,
    /// Dispatch was durably cancelled before the effect boundary.
    Cancelled,
    /// Dispatch was durably disconnected before the effect boundary.
    Disconnected,
}
