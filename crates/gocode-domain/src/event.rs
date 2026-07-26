//! Domain events — three-stage event model, command context, aggregate type.
//! Full implementation in Task 3; this stub provides AggregateType needed by `id.rs`.

use core::fmt;

/// Discriminant for aggregate kind, used in error messages and routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AggregateType {
    /// Task run aggregate.
    TaskRun,
    /// Conversation aggregate.
    Conversation,
    /// Workspace aggregate.
    Workspace,
}

impl fmt::Display for AggregateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TaskRun => write!(f, "TaskRun"),
            Self::Conversation => write!(f, "Conversation"),
            Self::Workspace => write!(f, "Workspace"),
        }
    }
}
