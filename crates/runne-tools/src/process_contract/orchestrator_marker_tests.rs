use super::{
    ProcessAuditRecordV1, ProcessAuditStageV1, ProcessDispatchOutcomeV1, ProcessOrchestratorV1,
    ProcessOutputBoundsV1, ProcessOutputSourceEventV1, ProcessOutputStreamV1, VirtualGraceScriptV1,
    VirtualProcessTreeFixtureV1,
    orchestrator_test_support::{Cancel, Clock, Journal, OutputSource, admission, input},
};

#[test]
fn marker_output_persists_only_evidence_and_replay_has_no_source_or_effect_calls() {
    let marker = "TASK6_UNIQUE_RAW_OUTPUT_MARKER";
    let mut request = input(32);
    request.output_bounds =
        ProcessOutputBoundsV1::new(0, marker.len() as u64, 1, marker.len() as u64 + 1)
            .expect("marker-sized bounds");
    let mut journal = Journal::seeded();
    let platform = VirtualProcessTreeFixtureV1::new();
    platform
        .set_grace_script(VirtualGraceScriptV1::Complete)
        .expect("healthy fixture");
    let mut output = OutputSource::new([
        Ok(ProcessOutputSourceEventV1::Chunk {
            sequence: 0,
            stream: ProcessOutputStreamV1::Stdout,
            bytes: marker.as_bytes().to_vec().into_boxed_slice(),
            source_has_more: false,
        }),
        Ok(ProcessOutputSourceEventV1::End {
            sequence: 1,
            stream: ProcessOutputStreamV1::Stdout,
        }),
        Ok(ProcessOutputSourceEventV1::End {
            sequence: 2,
            stream: ProcessOutputStreamV1::Stderr,
        }),
    ]);
    let orchestrator = ProcessOrchestratorV1::new();

    let ProcessDispatchOutcomeV1::Terminal(first) = orchestrator
        .dispatch_input(
            request.clone(),
            &admission(),
            &mut journal,
            &platform,
            &platform,
            &mut output,
            &Clock::new(&[0, 0, 1]),
            &Cancel(false),
        )
        .expect("terminal marker capture")
    else {
        panic!("expected terminal marker capture")
    };
    let settlement = first.settlement().clone();
    let audit = ProcessAuditRecordV1::new(ProcessAuditStageV1::Terminal, settlement.clone());
    for debug in [
        format!("{first:?}"),
        format!("{settlement:?}"),
        format!("{:?}", settlement.output()),
        format!("{audit:?}"),
    ] {
        assert!(!debug.contains(marker));
    }
    let reads = output.reads();
    let calls = platform.call_log().expect("healthy fixture");

    let replay = orchestrator
        .dispatch_input(
            request,
            &admission(),
            &mut journal,
            &platform,
            &platform,
            &mut output,
            &Clock::new(&[0]),
            &Cancel(false),
        )
        .expect("pure journal replay");
    assert!(matches!(replay, ProcessDispatchOutcomeV1::Terminal(_)));
    assert_eq!(output.reads(), reads);
    assert_eq!(platform.call_log().expect("healthy fixture"), calls);
}
