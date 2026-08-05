/// Closed lifecycle states for a claimed process effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessLifecycleStateV1 {
    /// Admission validation is in progress before a claim exists.
    Validating,
    /// The outer admission has been projected into a claim.
    Claimed,
    /// A platform launch is awaiting exact evidence.
    Launching,
    /// The platform proved that no process started.
    NotStarted,
    /// Exact launch evidence exists and the process is running.
    Running,
    /// Exact lifecycle control is terminating the process tree.
    Terminating,
    /// Exact terminal evidence has been recorded.
    Completed,
    /// Recovery or evidence loss leaves the effect ambiguous.
    Uncertain,
}

impl ProcessLifecycleStateV1 {
    /// Returns whether this closed state graph permits the requested transition.
    pub const fn permits(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Validating, Self::Claimed)
                | (Self::Claimed, Self::Launching)
                | (
                    Self::Launching,
                    Self::NotStarted | Self::Running | Self::Uncertain
                )
                | (
                    Self::Running,
                    Self::Terminating | Self::Completed | Self::Uncertain
                )
                | (Self::Terminating, Self::Completed | Self::Uncertain)
                | (Self::Uncertain, Self::Uncertain)
        )
    }

    pub(crate) const fn requires_settlement(self) -> bool {
        matches!(self, Self::NotStarted | Self::Completed | Self::Uncertain)
    }
}
