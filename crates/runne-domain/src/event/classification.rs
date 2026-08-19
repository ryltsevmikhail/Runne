// ── Sensitivity ────────────────────────────────────────────────────────────

/// Data sensitivity classification for an event.
///
/// Determined deterministically from the event type — not a runtime choice.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Sensitivity {
    /// May be logged, relayed, and stored without special handling.
    Public,
    /// Restricted to the runtime process; not for external distribution.
    Internal,
    /// Contains secrets or PII; must be redacted in logs and diagnostics.
    Sensitive,
}

// ── AggregateType ──────────────────────────────────────────────────────────

/// Discriminant for aggregate kind, used in error messages and routing.
///
/// Note: forward-declared in `id.rs`; this is the canonical definition.
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

// ── Actor ──────────────────────────────────────────────────────────────────

/// Identity of the actor that issued a command.
///
/// Bounded by `MAX_ACTOR_BYTES` (256), ASCII printable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Actor(String);

impl Actor {
    /// Create a new `Actor`, validating bounds.
    pub fn new(s: impl Into<String>) -> Result<Self, InvalidIdReason> {
        let s = s.into();
        if s.is_empty() {
            return Err(InvalidIdReason::Empty);
        }
        let len = s.len();
        if len > MAX_ACTOR_BYTES {
            return Err(InvalidIdReason::TooLong {
                max: MAX_ACTOR_BYTES,
                actual: len,
            });
        }
        Ok(Self(s))
    }

    /// Return a reference to the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── EventType ──────────────────────────────────────────────────────────────

/// Canonical event type name, bounded by `MAX_EVENT_TYPE_BYTES` (128).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventType(String);

impl EventType {
    /// Create a new `EventType`, validating bounds.
    pub fn new(s: impl Into<String>) -> Result<Self, InvalidIdReason> {
        let s = s.into();
        if s.is_empty() {
            return Err(InvalidIdReason::Empty);
        }
        let len = s.len();
        if len > MAX_EVENT_TYPE_BYTES {
            return Err(InvalidIdReason::TooLong {
                max: MAX_EVENT_TYPE_BYTES,
                actual: len,
            });
        }
        Ok(Self(s))
    }

    /// Return a reference to the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
