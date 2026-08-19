use super::output_payload::channel_evidence;
use super::{
    ProcessCapturedOutputV1, ProcessOutputBoundsV1, ProcessOutputCallerIdV1,
    ProcessOutputCaptureErrorV1, ProcessOutputEvidenceV1, ProcessOutputReadBudgetV1,
    ProcessOutputSourceErrorV1, ProcessOutputSourceEventV1, ProcessOutputSourcePortV1,
    ProcessOutputSourceViolationV1, ProcessOutputStopReasonV1, ProcessOutputStreamV1,
    TransientProcessOutputChannelV1,
};

const MAX_CHUNK_BYTES: u64 = 65_536;

/// Source-bounded streaming collector with no whole-source input API.
pub(crate) struct ProcessOutputCollectorV1;

impl ProcessOutputCollectorV1 {
    /// Collects one source event at a time until both streams end or a cap stops capture.
    pub(crate) fn collect<S: ProcessOutputSourcePortV1>(
        bounds: &ProcessOutputBoundsV1,
        caller: &ProcessOutputCallerIdV1,
        source: &mut S,
    ) -> Result<ProcessCapturedOutputV1, ProcessOutputCaptureErrorV1> {
        let mut remaining = Remaining::new(bounds);
        let mut output = Output::default();
        let mut ended = Ended::default();
        let mut locally_truncated = Truncated::default();
        let mut sequence = 0;
        let stop_evidence = loop {
            // Each nonempty chunk consumes the checked shared budget, so its capacity
            // bounds chunk events; only one End event is accepted per stream.
            let budget = remaining.budget(sequence)?;
            let event = source.next_bounded(budget).map_err(source_error)?;
            let (event_sequence, stream) = event_identity(&event);
            if event_sequence != budget.expected_sequence() {
                return violation(ProcessOutputSourceViolationV1::SequenceMismatch);
            }
            sequence =
                sequence
                    .checked_add(1)
                    .ok_or(ProcessOutputCaptureErrorV1::SourceViolation(
                        ProcessOutputSourceViolationV1::SequenceMismatch,
                    ))?;
            if ended.contains(stream) {
                return violation(ProcessOutputSourceViolationV1::StreamAlreadyEnded);
            }
            match event {
                ProcessOutputSourceEventV1::End { .. } => {
                    ended.mark(stream);
                    locally_truncated.clear(stream);
                    if ended.complete() {
                        break None;
                    }
                }
                ProcessOutputSourceEventV1::Chunk {
                    bytes,
                    source_has_more,
                    ..
                } => {
                    let byte_count = u64::try_from(bytes.len()).map_err(|_| {
                        ProcessOutputCaptureErrorV1::SourceViolation(
                            ProcessOutputSourceViolationV1::ChunkTooLarge,
                        )
                    })?;
                    validate_chunk(byte_count, stream, &budget)?;
                    if byte_count == 0 {
                        return violation(ProcessOutputSourceViolationV1::ZeroProgress);
                    }
                    locally_truncated.set(stream, source_has_more);
                    remaining.consume(stream, byte_count);
                    output.append(stream, &bytes);
                    if remaining.combined == 0
                        || (source_has_more && remaining.for_stream(stream) == 0)
                    {
                        break Some(
                            source
                                .stop_capture(ProcessOutputStopReasonV1::OutputBoundsReached)
                                .map_err(source_error)?,
                        );
                    }
                }
            }
        };
        Ok(ProcessCapturedOutputV1 {
            evidence: ProcessOutputEvidenceV1 {
                stdout: channel_evidence(
                    &output.stdout,
                    locally_truncated.stdout
                        || stop_evidence.is_some_and(|value| value.stdout_truncated()),
                ),
                stderr: channel_evidence(
                    &output.stderr,
                    locally_truncated.stderr
                        || stop_evidence.is_some_and(|value| value.stderr_truncated()),
                ),
            },
            transient: TransientProcessOutputChannelV1 {
                caller: *caller,
                stdout: output.stdout,
                stderr: output.stderr,
            },
            stop_evidence,
        })
    }
}

#[derive(Default)]
struct Truncated {
    stdout: bool,
    stderr: bool,
}

impl Truncated {
    fn set(&mut self, stream: ProcessOutputStreamV1, source_has_more: bool) {
        match stream {
            ProcessOutputStreamV1::Stdout => self.stdout = source_has_more,
            ProcessOutputStreamV1::Stderr => self.stderr = source_has_more,
        }
    }

    fn clear(&mut self, stream: ProcessOutputStreamV1) {
        match stream {
            ProcessOutputStreamV1::Stdout => self.stdout = false,
            ProcessOutputStreamV1::Stderr => self.stderr = false,
        }
    }
}

fn source_error(_: ProcessOutputSourceErrorV1) -> ProcessOutputCaptureErrorV1 {
    ProcessOutputCaptureErrorV1::SourceClosed
}

fn violation<T>(reason: ProcessOutputSourceViolationV1) -> Result<T, ProcessOutputCaptureErrorV1> {
    Err(ProcessOutputCaptureErrorV1::SourceViolation(reason))
}

fn event_identity(event: &ProcessOutputSourceEventV1) -> (u64, ProcessOutputStreamV1) {
    match event {
        ProcessOutputSourceEventV1::Chunk {
            sequence, stream, ..
        }
        | ProcessOutputSourceEventV1::End { sequence, stream } => (*sequence, *stream),
    }
}

fn validate_chunk(
    bytes: u64,
    stream: ProcessOutputStreamV1,
    budget: &ProcessOutputReadBudgetV1,
) -> Result<(), ProcessOutputCaptureErrorV1> {
    let channel = match stream {
        ProcessOutputStreamV1::Stdout => budget.stdout_remaining(),
        ProcessOutputStreamV1::Stderr => budget.stderr_remaining(),
    };
    if bytes > channel {
        return violation(ProcessOutputSourceViolationV1::ChannelBudgetExceeded);
    }
    if bytes > budget.combined_remaining() {
        return violation(ProcessOutputSourceViolationV1::CombinedBudgetExceeded);
    }
    if bytes > budget.max_chunk_bytes() {
        return violation(ProcessOutputSourceViolationV1::ChunkTooLarge);
    }
    Ok(())
}

#[derive(Default)]
struct Output {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Output {
    fn append(&mut self, stream: ProcessOutputStreamV1, bytes: &[u8]) {
        match stream {
            ProcessOutputStreamV1::Stdout => self.stdout.extend_from_slice(bytes),
            ProcessOutputStreamV1::Stderr => self.stderr.extend_from_slice(bytes),
        }
    }
}

struct Remaining {
    stdout: u64,
    stderr: u64,
    combined: u64,
}

impl Remaining {
    fn new(bounds: &ProcessOutputBoundsV1) -> Self {
        Self {
            stdout: bounds.stdout_limit(),
            stderr: bounds.stderr_limit(),
            combined: bounds.combined_limit(),
        }
    }

    fn budget(
        &self,
        sequence: u64,
    ) -> Result<ProcessOutputReadBudgetV1, ProcessOutputCaptureErrorV1> {
        ProcessOutputReadBudgetV1::new(
            self.stdout,
            self.stderr,
            self.combined,
            MAX_CHUNK_BYTES
                .min(self.combined)
                .min(self.stdout.max(self.stderr)),
            sequence,
        )
        .map_err(ProcessOutputCaptureErrorV1::SourceViolation)
    }

    fn consume(&mut self, stream: ProcessOutputStreamV1, bytes: u64) {
        self.combined -= bytes;
        match stream {
            ProcessOutputStreamV1::Stdout => self.stdout -= bytes,
            ProcessOutputStreamV1::Stderr => self.stderr -= bytes,
        }
    }

    fn for_stream(&self, stream: ProcessOutputStreamV1) -> u64 {
        match stream {
            ProcessOutputStreamV1::Stdout => self.stdout,
            ProcessOutputStreamV1::Stderr => self.stderr,
        }
    }
}

#[derive(Default)]
struct Ended {
    stdout: bool,
    stderr: bool,
}

impl Ended {
    fn contains(&self, stream: ProcessOutputStreamV1) -> bool {
        match stream {
            ProcessOutputStreamV1::Stdout => self.stdout,
            ProcessOutputStreamV1::Stderr => self.stderr,
        }
    }

    fn mark(&mut self, stream: ProcessOutputStreamV1) {
        match stream {
            ProcessOutputStreamV1::Stdout => self.stdout = true,
            ProcessOutputStreamV1::Stderr => self.stderr = true,
        }
    }

    fn complete(&self) -> bool {
        self.stdout && self.stderr
    }
}
