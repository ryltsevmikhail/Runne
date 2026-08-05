use core::fmt;

use super::super::ProcessContractErrorV1;

/// Independent validated limits for process standard streams.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessOutputBoundsV1 {
    stdout: u64,
    stderr: u64,
    combined: u64,
}

impl ProcessOutputBoundsV1 {
    /// Creates coherent output limits with V1 closed stdin.
    pub fn new(
        stdin: u64,
        stdout: u64,
        stderr: u64,
        combined: u64,
    ) -> Result<Self, ProcessContractErrorV1> {
        if stdin != 0
            || combined == 0
            || stdout
                .checked_add(stderr)
                .is_none_or(|total| combined > total)
        {
            return Err(ProcessContractErrorV1::InputBoundsExceeded);
        }
        Ok(Self {
            stdout,
            stderr,
            combined,
        })
    }

    /// Rejects any nonempty input under the V1 closed-stdin contract.
    pub fn validate_stdin(&self, stdin: &[u8]) -> Result<(), ProcessContractErrorV1> {
        stdin
            .is_empty()
            .then_some(())
            .ok_or(ProcessContractErrorV1::InputBoundsExceeded)
    }

    /// Returns the cancellation disposition for invalid input before an external effect.
    pub fn cancel_for_stdin(&self, stdin: &[u8]) -> ProcessCancellationDispositionV1 {
        if self.validate_stdin(stdin).is_ok() {
            ProcessCancellationDispositionV1::NotCancelled
        } else {
            ProcessCancellationDispositionV1::PolicyRejected
        }
    }

    pub(super) const fn stdout_limit(&self) -> u64 {
        self.stdout
    }

    pub(super) const fn stderr_limit(&self) -> u64 {
        self.stderr
    }

    pub(super) const fn combined_limit(&self) -> u64 {
        self.combined
    }
}

/// Closed pre-effect cancellation result for policy validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessCancellationDispositionV1 {
    /// Policy validation did not cancel the planned effect.
    NotCancelled,
    /// Policy validation rejected input before an external effect.
    PolicyRejected,
}

/// One process output stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessOutputStreamV1 {
    /// The standard output stream.
    Stdout,
    /// The standard error stream.
    Stderr,
}

/// Validated maximum source read request with no writable fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessOutputReadBudgetV1 {
    stdout_remaining: u64,
    stderr_remaining: u64,
    combined_remaining: u64,
    max_chunk_bytes: u64,
    expected_sequence: u64,
}

impl ProcessOutputReadBudgetV1 {
    /// Creates a coherent source read budget.
    pub(crate) fn new(
        stdout_remaining: u64,
        stderr_remaining: u64,
        combined_remaining: u64,
        max_chunk_bytes: u64,
        expected_sequence: u64,
    ) -> Result<Self, ProcessOutputSourceViolationV1> {
        if combined_remaining == 0
            || max_chunk_bytes == 0
            || max_chunk_bytes > combined_remaining
            || max_chunk_bytes > stdout_remaining.max(stderr_remaining)
        {
            return Err(ProcessOutputSourceViolationV1::InvalidBudget);
        }
        Ok(Self {
            stdout_remaining,
            stderr_remaining,
            combined_remaining,
            max_chunk_bytes,
            expected_sequence,
        })
    }

    /// Returns the remaining stdout capacity.
    #[must_use]
    pub(crate) const fn stdout_remaining(&self) -> u64 {
        self.stdout_remaining
    }

    /// Returns the remaining stderr capacity.
    #[must_use]
    pub(crate) const fn stderr_remaining(&self) -> u64 {
        self.stderr_remaining
    }

    /// Returns the remaining shared capture capacity.
    #[must_use]
    pub(crate) const fn combined_remaining(&self) -> u64 {
        self.combined_remaining
    }

    /// Returns the maximum individual source read chunk.
    #[must_use]
    pub(crate) const fn max_chunk_bytes(&self) -> u64 {
        self.max_chunk_bytes
    }

    /// Returns the only acceptable global source event sequence.
    #[must_use]
    pub(crate) const fn expected_sequence(&self) -> u64 {
        self.expected_sequence
    }
}

/// One source event returned for an exact requested read budget.
#[derive(Clone, Eq, PartialEq)]
pub(crate) enum ProcessOutputSourceEventV1 {
    /// One raw chunk which must fit its accompanying requested budget.
    Chunk {
        /// The source-global event sequence.
        sequence: u64,
        /// The stream which produced the chunk.
        stream: ProcessOutputStreamV1,
        /// Transient raw bytes; they are not persisted by the event.
        bytes: Box<[u8]>,
        /// Whether this stream has another source event after this chunk.
        source_has_more: bool,
    },
    /// A terminal event for one stream.
    End {
        /// The source-global event sequence.
        sequence: u64,
        /// The stream which has ended.
        stream: ProcessOutputStreamV1,
    },
}

impl fmt::Debug for ProcessOutputSourceEventV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chunk {
                sequence,
                stream,
                bytes,
                source_has_more,
            } => f
                .debug_struct("ProcessOutputSourceEventV1::Chunk")
                .field("sequence", sequence)
                .field("stream", stream)
                .field("byte_count", &bytes.len())
                .field("source_has_more", source_has_more)
                .finish(),
            Self::End { sequence, stream } => f
                .debug_struct("ProcessOutputSourceEventV1::End")
                .field("sequence", sequence)
                .field("stream", stream)
                .finish(),
        }
    }
}

/// Closed source failures without provider payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessOutputSourceErrorV1 {
    /// The source closed before the requested bounded event was returned.
    Closed,
}

impl fmt::Display for ProcessOutputSourceErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("process output source is closed")
    }
}

impl std::error::Error for ProcessOutputSourceErrorV1 {}

/// Closed source protocol violations that make the output uncertain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessOutputSourceViolationV1 {
    /// A constructed read budget was internally incoherent.
    InvalidBudget,
    /// A source chunk exceeded the configured per-read maximum.
    ChunkTooLarge,
    /// A source emitted an empty chunk; only `End` completes a stream.
    ZeroProgress,
    /// A source event did not match the required global sequence.
    SequenceMismatch,
    /// A source chunk exceeded its stream's remaining capacity.
    ChannelBudgetExceeded,
    /// A source chunk exceeded the remaining shared capacity.
    CombinedBudgetExceeded,
    /// A source emitted data after it had ended that stream.
    StreamAlreadyEnded,
}

/// Reason a collector requests that a source stop producing output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessOutputStopReasonV1 {
    /// A channel or shared capture capacity was reached.
    OutputBoundsReached,
}

/// Metadata returned by a source after a bounded stop request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessOutputStopEvidenceV1 {
    stdout_truncated: bool,
    stderr_truncated: bool,
}

impl ProcessOutputStopEvidenceV1 {
    /// Records which captured prefixes are known to be truncated.
    #[must_use]
    pub const fn new(stdout_truncated: bool, stderr_truncated: bool) -> Self {
        Self {
            stdout_truncated,
            stderr_truncated,
        }
    }

    /// Returns whether the captured stdout prefix is truncated.
    #[must_use]
    pub const fn stdout_truncated(&self) -> bool {
        self.stdout_truncated
    }

    /// Returns whether the captured stderr prefix is truncated.
    #[must_use]
    pub const fn stderr_truncated(&self) -> bool {
        self.stderr_truncated
    }
}

/// Source of exactly one source-bounded output event per request.
pub(crate) trait ProcessOutputSourcePortV1 {
    /// Returns an event that conforms to the requested bounded budget.
    fn next_bounded(
        &mut self,
        budget: ProcessOutputReadBudgetV1,
    ) -> Result<ProcessOutputSourceEventV1, ProcessOutputSourceErrorV1>;

    /// Stops capture exactly once when a collector reaches an output bound.
    fn stop_capture(
        &mut self,
        reason: ProcessOutputStopReasonV1,
    ) -> Result<ProcessOutputStopEvidenceV1, ProcessOutputSourceErrorV1>;
}

/// Collector result failure; violations never expose a partial raw payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessOutputCaptureErrorV1 {
    /// The source closed before a complete bounded capture.
    SourceClosed,
    /// The source returned an event outside the exact contract.
    SourceViolation(ProcessOutputSourceViolationV1),
}
