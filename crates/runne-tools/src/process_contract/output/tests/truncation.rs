use super::{
    ProcessOutputBoundsV1, ProcessOutputCaptureErrorV1, ProcessOutputStopEvidenceV1,
    ProcessOutputStopReasonV1, ProcessOutputStreamV1, ScriptedSource, capture, capture_with_bounds,
    chunk, end,
};

#[test]
fn local_source_more_marks_prefix_truncated_despite_false_stop_evidence() {
    let mut source =
        ScriptedSource::new(vec![chunk(0, ProcessOutputStreamV1::Stdout, b"abcd", true)]);
    let captured = capture(&mut source).expect("bounded prefix");

    assert!(captured.evidence().stdout().truncated());
}

#[test]
fn source_more_followed_by_end_is_not_truncated() {
    let mut source = ScriptedSource::new(vec![
        chunk(0, ProcessOutputStreamV1::Stdout, b"ab", true),
        end(1, ProcessOutputStreamV1::Stdout),
        end(2, ProcessOutputStreamV1::Stderr),
    ]);
    let captured = capture(&mut source).expect("complete capture");

    assert!(!captured.evidence().stdout().truncated());
}

#[test]
fn ended_stream_clears_provisional_more_before_other_stream_hits_cap() {
    let mut source = ScriptedSource::new(vec![
        chunk(0, ProcessOutputStreamV1::Stdout, b"ab", true),
        end(1, ProcessOutputStreamV1::Stdout),
        chunk(2, ProcessOutputStreamV1::Stderr, b"cdef", false),
    ]);
    let captured = capture(&mut source).expect("bounded prefix");

    assert!(!captured.evidence().stdout().truncated());
    assert!(!captured.evidence().stderr().truncated());
}

#[test]
fn latest_source_has_more_false_clears_provisional_truncation_at_combined_cap() {
    let bounds = ProcessOutputBoundsV1::new(0, 6, 4, 6).expect("valid output bounds");
    let mut source = ScriptedSource::new(vec![
        chunk(0, ProcessOutputStreamV1::Stdout, b"ab", true),
        chunk(1, ProcessOutputStreamV1::Stdout, b"cdef", false),
    ]);
    let captured = capture_with_bounds(&bounds, &mut source).expect("bounded prefix");

    assert!(!captured.evidence().stdout().truncated());
    assert!(!captured.evidence().stderr().truncated());
    assert_eq!(
        source.stops,
        vec![ProcessOutputStopReasonV1::OutputBoundsReached]
    );
}

#[test]
fn combined_cap_uses_stop_evidence_for_unseen_stream_without_blanket_marking() {
    let bounds = ProcessOutputBoundsV1::new(0, 6, 4, 6).expect("valid output bounds");
    for (evidence, expected) in [
        ((false, false), (false, false)),
        ((false, true), (false, true)),
        ((true, false), (true, false)),
    ] {
        let mut source = ScriptedSource::new(vec![chunk(
            0,
            ProcessOutputStreamV1::Stdout,
            b"abcdef",
            false,
        )]);
        source.stop_evidence = ProcessOutputStopEvidenceV1::new(evidence.0, evidence.1);
        let captured = capture_with_bounds(&bounds, &mut source).expect("bounded prefix");

        assert_eq!(
            (
                captured.evidence().stdout().truncated(),
                captured.evidence().stderr().truncated(),
            ),
            expected
        );
        assert_eq!(
            source.stops,
            vec![ProcessOutputStopReasonV1::OutputBoundsReached]
        );
    }
}

#[test]
fn cap_calls_stop_capture_and_records_prefix_metadata() {
    let mut source =
        ScriptedSource::new(vec![chunk(0, ProcessOutputStreamV1::Stdout, b"abcd", true)]);
    source.stop_evidence = ProcessOutputStopEvidenceV1::new(true, false);
    let captured = capture(&mut source).expect("prefix capture");

    assert_eq!(
        source.stops,
        vec![ProcessOutputStopReasonV1::OutputBoundsReached]
    );
    assert_eq!(
        captured.stop_evidence(),
        Some(ProcessOutputStopEvidenceV1::new(true, false))
    );
    assert_eq!(captured.evidence().stdout().byte_count(), 4);
    assert_eq!(
        captured.evidence().stdout().digest(),
        [
            0x88, 0xd4, 0x26, 0x6f, 0xd4, 0xe6, 0x33, 0x8d, 0x13, 0xb8, 0x45, 0xfc, 0xf2, 0x89,
            0x57, 0x9d, 0x20, 0x9c, 0x89, 0x78, 0x23, 0xb9, 0x21, 0x7d, 0xa3, 0xe1, 0x61, 0x93,
            0x6f, 0x03, 0x15, 0x89,
        ]
    );
    assert!(captured.evidence().stdout().truncated());
}

#[test]
fn stop_failure_after_cap_returns_source_closed_without_partial_result() {
    let mut source =
        ScriptedSource::new(vec![chunk(0, ProcessOutputStreamV1::Stdout, b"abcd", true)]);
    source.stop_fails = true;

    assert_eq!(
        capture(&mut source).map(|_| ()),
        Err(ProcessOutputCaptureErrorV1::SourceClosed)
    );
    assert_eq!(
        source.stops,
        vec![ProcessOutputStopReasonV1::OutputBoundsReached]
    );
}
