use super::{
    ProcessContractErrorV1, ProcessDispatchOutcomeV1, ProcessOrchestratorV1, VirtualGraceScriptV1,
    VirtualProcessTreeFixtureV1,
    orchestrator_test_support::{Cancel, Clock, Journal, OutputSource, admission, input},
};

#[test]
fn lost_response_replay_preserves_cas_revision_and_sequence() {
    let mut journal = Journal::seeded();
    journal.lose_terminal_commit_response();
    let platform = completed_platform();
    let request = input(47);
    let orchestrator = ProcessOrchestratorV1::new();
    let mut output = OutputSource::terminal();

    assert_eq!(
        orchestrator.dispatch_input(
            request.clone(),
            &admission(),
            &mut journal,
            &platform,
            &platform,
            &mut output,
            &Clock::new(&[0, 0, 1]),
            &Cancel(false),
        ),
        Err(ProcessContractErrorV1::TerminalCommitFailed)
    );
    let record = journal.records["sealed-permit"].clone();
    let committed = record.settlement().expect("journal committed settlement");
    assert_eq!(committed.revision(), record.revision());
    assert_eq!(committed.sequence(), record.settlement_sequence());
    let calls = platform.call_log().expect("healthy fixture");
    let reads = output.reads();

    let ProcessDispatchOutcomeV1::Terminal(replay) = orchestrator
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
        .expect("lost-response replay")
    else {
        panic!("expected terminal replay");
    };
    assert_eq!(replay.settlement(), &committed);
    assert_eq!(platform.call_log().expect("healthy fixture"), calls);
    assert_eq!(output.reads(), reads);
}

fn completed_platform() -> VirtualProcessTreeFixtureV1 {
    let platform = VirtualProcessTreeFixtureV1::new();
    platform
        .set_grace_script(VirtualGraceScriptV1::Complete)
        .expect("healthy fixture");
    platform
}
