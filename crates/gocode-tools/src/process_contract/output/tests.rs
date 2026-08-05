use super::{
    ProcessCapturedOutputV1, ProcessOutputBoundsV1, ProcessOutputCallerIdV1,
    ProcessOutputCaptureErrorV1, ProcessOutputCollectorV1, ProcessOutputReadBudgetV1,
    ProcessOutputSourceErrorV1, ProcessOutputSourceEventV1, ProcessOutputSourcePortV1,
    ProcessOutputSourceViolationV1, ProcessOutputStopEvidenceV1, ProcessOutputStopReasonV1,
    ProcessOutputStreamV1,
};

mod truncation;

struct ScriptedSource {
    events: Vec<ProcessOutputSourceEventV1>,
    requests: Vec<ProcessOutputReadBudgetV1>,
    stops: Vec<ProcessOutputStopReasonV1>,
    stop_evidence: ProcessOutputStopEvidenceV1,
    stop_fails: bool,
    next: usize,
}

impl ScriptedSource {
    fn new(events: Vec<ProcessOutputSourceEventV1>) -> Self {
        Self {
            events,
            requests: Vec::new(),
            stops: Vec::new(),
            stop_evidence: ProcessOutputStopEvidenceV1::new(false, false),
            stop_fails: false,
            next: 0,
        }
    }
}

impl ProcessOutputSourcePortV1 for ScriptedSource {
    fn next_bounded(
        &mut self,
        budget: ProcessOutputReadBudgetV1,
    ) -> Result<ProcessOutputSourceEventV1, ProcessOutputSourceErrorV1> {
        self.requests.push(budget);
        let event = self
            .events
            .get(self.next)
            .cloned()
            .ok_or(ProcessOutputSourceErrorV1::Closed)?;
        self.next += 1;
        Ok(event)
    }

    fn stop_capture(
        &mut self,
        reason: ProcessOutputStopReasonV1,
    ) -> Result<ProcessOutputStopEvidenceV1, ProcessOutputSourceErrorV1> {
        self.stops.push(reason);
        if self.stop_fails {
            return Err(ProcessOutputSourceErrorV1::Closed);
        }
        Ok(self.stop_evidence)
    }
}

fn bounds() -> ProcessOutputBoundsV1 {
    ProcessOutputBoundsV1::new(0, 4, 4, 6).expect("valid output bounds")
}

fn caller() -> ProcessOutputCallerIdV1 {
    ProcessOutputCallerIdV1::new([1; 16]).expect("opaque caller")
}

fn chunk(
    sequence: u64,
    stream: ProcessOutputStreamV1,
    bytes: &'static [u8],
    source_has_more: bool,
) -> ProcessOutputSourceEventV1 {
    ProcessOutputSourceEventV1::Chunk {
        sequence,
        stream,
        bytes: Box::from(bytes),
        source_has_more,
    }
}

fn end(sequence: u64, stream: ProcessOutputStreamV1) -> ProcessOutputSourceEventV1 {
    ProcessOutputSourceEventV1::End { sequence, stream }
}

fn capture(
    source: &mut ScriptedSource,
) -> Result<ProcessCapturedOutputV1, ProcessOutputCaptureErrorV1> {
    capture_with_bounds(&bounds(), source)
}

fn capture_with_bounds(
    bounds: &ProcessOutputBoundsV1,
    source: &mut ScriptedSource,
) -> Result<ProcessCapturedOutputV1, ProcessOutputCaptureErrorV1> {
    ProcessOutputCollectorV1::collect(bounds, &caller(), source)
}

#[test]
fn collector_never_requests_more_than_source_budget() {
    let mut source = ScriptedSource::new(vec![
        chunk(0, ProcessOutputStreamV1::Stdout, b"ab", true),
        chunk(1, ProcessOutputStreamV1::Stderr, b"cd", false),
        end(2, ProcessOutputStreamV1::Stdout),
        end(3, ProcessOutputStreamV1::Stderr),
    ]);
    capture(&mut source).expect("bounded capture");

    let requested = source.requests;
    assert_eq!(requested.len(), 4);
    assert_eq!(
        requested
            .iter()
            .map(|budget| {
                (
                    budget.stdout_remaining(),
                    budget.stderr_remaining(),
                    budget.combined_remaining(),
                    budget.max_chunk_bytes(),
                    budget.expected_sequence(),
                )
            })
            .collect::<Vec<_>>(),
        vec![
            (4, 4, 6, 4, 0),
            (2, 4, 4, 4, 1),
            (2, 2, 2, 2, 2),
            (2, 2, 2, 2, 3)
        ]
    );
}

#[test]
fn oversized_or_nonmonotonic_chunk_becomes_uncertain() {
    for event in [
        chunk(0, ProcessOutputStreamV1::Stdout, &[0; 65_537], false),
        chunk(1, ProcessOutputStreamV1::Stdout, b"a", false),
    ] {
        let mut source = ScriptedSource::new(vec![event]);
        assert!(matches!(
            capture(&mut source),
            Err(ProcessOutputCaptureErrorV1::SourceViolation(_))
        ));
    }
}

#[test]
fn zero_length_chunk_is_rejected_even_when_source_reports_no_more() {
    let mut source = ScriptedSource::new(vec![chunk(0, ProcessOutputStreamV1::Stdout, b"", false)]);
    assert!(matches!(
        capture(&mut source),
        Err(ProcessOutputCaptureErrorV1::SourceViolation(
            ProcessOutputSourceViolationV1::ZeroProgress
        ))
    ));
}

#[test]
fn combined_overflow_follows_source_sequence() {
    let mut source = ScriptedSource::new(vec![
        chunk(0, ProcessOutputStreamV1::Stderr, b"abc", false),
        chunk(1, ProcessOutputStreamV1::Stdout, b"def", true),
    ]);
    let captured = capture(&mut source).expect("source-ordered capture");
    let payload = captured
        .transient()
        .copy_for(&caller())
        .expect("exact caller receives the source-ordered prefix");
    assert_eq!(payload.stdout(), b"def");
    assert_eq!(payload.stderr(), b"abc");
}

#[test]
fn raw_payload_requires_exact_caller_and_debug_is_redacted() {
    let mut source = ScriptedSource::new(vec![
        chunk(0, ProcessOutputStreamV1::Stdout, b"out", false),
        end(1, ProcessOutputStreamV1::Stdout),
        end(2, ProcessOutputStreamV1::Stderr),
    ]);
    let captured = capture(&mut source).expect("complete capture");
    let payload = captured
        .transient()
        .copy_for(&caller())
        .expect("exact caller receives raw bytes");

    assert_eq!(payload.stdout(), b"out");
    assert!(
        captured
            .transient()
            .copy_for(&ProcessOutputCallerIdV1::new([2; 16]).expect("other caller"))
            .is_none()
    );
    assert!(!format!("{captured:?}").contains("out"));
    assert!(!format!("{payload:?}").contains("out"));
}
