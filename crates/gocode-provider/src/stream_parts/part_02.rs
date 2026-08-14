impl<'de> Deserialize<'de> for ProviderStreamEventKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawProviderStreamEventKind::deserialize(deserializer)?;
        let no_text = raw.text.is_none();
        let no_usage = raw.usage.is_none();
        let no_tool =
            raw.call_id.is_none() && raw.tool_name.is_none() && raw.arguments_json.is_none();
        let no_terminal = raw.disposition.is_none() && raw.reason.is_none();
        let kind = match raw.kind {
            RawProviderStreamEventTag::Started if no_text && no_usage && no_tool && no_terminal => {
                Self::Started
            }
            RawProviderStreamEventTag::TextDelta
                if raw.text.is_some() && no_usage && no_tool && no_terminal =>
            {
                Self::TextDelta {
                    text: raw.text.expect("guarded text"),
                }
            }
            RawProviderStreamEventTag::Usage
                if no_text && raw.usage.is_some() && no_tool && no_terminal =>
            {
                Self::Usage {
                    usage: raw.usage.expect("guarded usage"),
                }
            }
            RawProviderStreamEventTag::UsageUnavailable
                if no_text && no_usage && no_tool && no_terminal =>
            {
                Self::UsageUnavailable
            }
            RawProviderStreamEventTag::ToolCallRequested
                if no_text
                    && no_usage
                    && raw.call_id.is_some()
                    && raw.tool_name.is_some()
                    && raw.arguments_json.is_some()
                    && no_terminal =>
            {
                Self::ToolCallRequested {
                    call_id: raw.call_id.expect("guarded call id"),
                    tool_name: raw.tool_name.expect("guarded tool name"),
                    arguments_json: raw.arguments_json.expect("guarded arguments"),
                }
            }
            RawProviderStreamEventTag::Finished
                if no_text
                    && no_usage
                    && no_tool
                    && raw.disposition.is_some()
                    && raw.reason.is_some() =>
            {
                Self::Finished {
                    disposition: raw.disposition.expect("guarded disposition"),
                    reason: raw.reason.expect("guarded reason"),
                }
            }
            RawProviderStreamEventTag::ScannerCompleted
                if raw.text.is_some()
                    && no_usage
                    && no_tool
                    && raw.disposition.is_some()
                    && raw.reason.is_some() =>
            {
                Self::ScannerCompleted {
                    text: raw.text.expect("guarded text"),
                    disposition: raw.disposition.expect("guarded disposition"),
                    reason: raw.reason.expect("guarded reason"),
                }
            }
            RawProviderStreamEventTag::ScannerProgress
                if no_text && no_usage && no_tool && no_terminal =>
            {
                Self::ScannerProgress
            }
            _ => {
                return Err(<D::Error as serde::de::Error>::custom(
                    "provider stream event payload does not match its kind",
                ));
            }
        };
        validate_event_kind(&kind).map_err(<D::Error as serde::de::Error>::custom)?;
        Ok(kind)
    }
}
/// One ordered normalized provider stream event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderStreamEvent {
    sequence: u64,
    kind: ProviderStreamEventKind,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProviderStreamEvent {
    sequence: u64,
    kind: ProviderStreamEventKind,
}

impl<'de> Deserialize<'de> for ProviderStreamEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawProviderStreamEvent::deserialize(deserializer)?;
        Self::new(raw.sequence, raw.kind).map_err(<D::Error as serde::de::Error>::custom)
    }
}

impl ProviderStreamEvent {
    /// Constructs an event. Sequence continuity is validated by the stream.
    pub fn new(sequence: u64, kind: ProviderStreamEventKind) -> Result<Self, StreamError> {
        validate_event_kind(&kind)?;
        Ok(Self { sequence, kind })
    }

    /// Returns the event sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the normalized payload.
    pub const fn kind(&self) -> &ProviderStreamEventKind {
        &self.kind
    }
}

/// Item returned by the normalized stream boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderStreamItem {
    event: ProviderStreamEvent,
}

impl ProviderStreamItem {
    pub(crate) const fn new(event: ProviderStreamEvent) -> Self {
        Self { event }
    }

    /// Constructs an item from an already normalized adapter event.
    pub fn from_event(event: ProviderStreamEvent) -> Result<Self, StreamError> {
        validate_event_kind(event.kind())?;
        Ok(Self { event })
    }

    /// Returns the normalized event.
    pub const fn event(&self) -> &ProviderStreamEvent {
        &self.event
    }
}

/// Stateful validator for one ordered normalized provider stream.
#[derive(Debug, Clone, Default)]
pub struct ProviderStreamValidator {
    next_sequence: u64,
    started: bool,
    usage_seen: bool,
    terminal: bool,
}

impl ProviderStreamValidator {
    /// Reconstructs the exact grammar state from a runtime-owned durable cursor.
    ///
    /// A non-zero cursor proves that the already accepted event at sequence zero
    /// was `Started`; callers must persist only events accepted by this validator.
    pub fn resume_at(next_sequence: u64, usage_seen: bool) -> Result<Self, StreamError> {
        if next_sequence == 0 && usage_seen {
            return Err(StreamError::InvalidResumeState);
        }
        Ok(Self {
            next_sequence,
            started: next_sequence > 0,
            usage_seen,
            terminal: false,
        })
    }

    /// Accepts exactly one next event or returns a closed grammar error.
    pub fn accept(&mut self, event: &ProviderStreamEvent) -> Result<(), StreamError> {
        if event.sequence() != self.next_sequence {
            return Err(StreamError::InvalidScriptSequence {
                expected: self.next_sequence,
                actual: event.sequence(),
            });
        }
        if self.terminal {
            return Err(StreamError::EventAfterTerminal);
        }
        match event.kind() {
            ProviderStreamEventKind::Started if self.started => {
                return Err(StreamError::DuplicateStarted);
            }
            ProviderStreamEventKind::Started => self.started = true,
            _ if !self.started => return Err(StreamError::EventBeforeStarted),
            ProviderStreamEventKind::Usage { .. } | ProviderStreamEventKind::UsageUnavailable
                if self.usage_seen =>
            {
                return Err(StreamError::DuplicateUsage);
            }
            ProviderStreamEventKind::Usage { .. } | ProviderStreamEventKind::UsageUnavailable => {
                self.usage_seen = true;
            }
            ProviderStreamEventKind::Finished { .. }
            | ProviderStreamEventKind::ScannerCompleted { .. } => self.terminal = true,
            ProviderStreamEventKind::TextDelta { .. }
            | ProviderStreamEventKind::ToolCallRequested { .. }
            | ProviderStreamEventKind::ScannerProgress => {}
        }
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(StreamError::SequenceOverflow)?;
        Ok(())
    }
}

/// Fail-closed normalized stream error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StreamError {
    /// The requested stream does not exist.
    #[error("provider stream was not found")]
    NotFound,
    /// Cursor skipped an expected event.
    #[error("provider stream sequence gap: expected={expected}, actual={actual}")]
    SequenceGap {
        /// Next expected sequence.
        expected: u64,
        /// Requested sequence.
        actual: u64,
    },
    /// No further event exists.
    #[error("provider stream is closed")]
    Closed,
    /// The provider returned an unknown terminal reason.
    #[error("unknown provider finish reason: {raw}")]
    UnknownFinishReason {
        /// Bounded raw reason.
        raw: String,
    },
    /// Test/conformance script violated ordered sequencing.
    #[error("invalid scripted stream sequence: expected={expected}, actual={actual}")]
    InvalidScriptSequence {
        /// Expected sequence.
        expected: u64,
        /// Actual sequence.
        actual: u64,
    },
    /// A non-start event appeared before the stream start marker.
    #[error("provider stream event appeared before start")]
    EventBeforeStarted,
    /// A stream emitted its start marker more than once.
    #[error("provider stream emitted duplicate start")]
    DuplicateStarted,
    /// Usage evidence appeared more than once.
    #[error("provider stream emitted duplicate usage")]
    DuplicateUsage,
    /// Any event appeared after terminal evidence.
    #[error("provider stream emitted event after terminal")]
    EventAfterTerminal,
    /// Durable recovery metadata cannot represent a valid accepted prefix.
    #[error("provider stream recovery state is invalid")]
    InvalidResumeState,
    /// Event sequencing exceeded the supported cursor space.
    #[error("provider stream sequence overflow")]
    SequenceOverflow,
    /// A normalized provider payload was empty where content is required.
    #[error("provider stream payload is empty")]
    EmptyPayload,
    /// One normalized provider payload exceeded its byte bound.
    #[error("provider stream payload exceeds {max} bytes (actual {actual})")]
    PayloadTooLarge {
        /// Maximum accepted bytes.
        max: usize,
        /// Actual bytes.
        actual: usize,
    },
    /// Provider tool identity contained unsupported characters.
    #[error("provider tool identity is invalid")]
    InvalidToolIdentifier,
    /// Provider tool arguments were not one valid JSON value.
    #[error("provider tool arguments JSON is invalid")]
    InvalidToolArguments,
}
