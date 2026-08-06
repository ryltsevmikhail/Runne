use gocode_platform_ports::process::ProcessTerminalDispositionV1;

use super::{
    ProcessDispatchOutcomeV1, ProcessLifecycleStateV1, ProcessOrchestratorV1,
    ProcessSettlementProofV1, ProcessUncertainReasonV1, VirtualGraceScriptV1,
    VirtualProcessTreeFixtureV1,
    orchestrator_test_support::{Cancel, Clock, Journal, OutputSource, admission, input},
};

fn terminal_platform() -> VirtualProcessTreeFixtureV1 {
    let platform = VirtualProcessTreeFixtureV1::new();
    platform
        .set_grace_script(VirtualGraceScriptV1::Complete)
        .expect("healthy fixture");
    platform
}

#[test]
fn terminal_settlement_atomically_contains_streamed_output_metadata() {
    let mut journal = Journal::seeded();
    let platform = terminal_platform();
    let mut output = OutputSource::streamed();

    let outcome = ProcessOrchestratorV1::new()
        .dispatch_input(
            input(1),
            &admission(),
            &mut journal,
            &platform,
            &platform,
            &mut output,
            &Clock::new(&[0, 0, 1]),
            &Cancel(false),
        )
        .expect("terminal settlement");

    let ProcessDispatchOutcomeV1::Terminal(result) = outcome else {
        panic!("expected metadata terminal result");
    };
    assert_eq!(result.settlement().output().stdout().byte_count(), 3);
    assert_eq!(result.settlement().output().stderr().byte_count(), 3);
    assert_eq!(
        result.settlement().proof().clone(),
        ProcessSettlementProofV1::Completed(
            gocode_platform_ports::process::ProcessTerminalEvidenceV1::new(
                &input(1).binding,
                ProcessTerminalDispositionV1::Completed,
                gocode_platform_ports::process::ProcessOwnerVerificationV1::Verified,
                gocode_platform_ports::process::ProcessTreeCleanupV1::Verified,
                [4; 32],
            )
            .expect("terminal evidence"),
        )
    );
    assert!(result.transient().is_some());
    assert_eq!(output.reads(), 4);
    assert_eq!(
        output
            .budgets()
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
            (4, 4, 8, 4, 0),
            (1, 4, 5, 4, 1),
            (1, 4, 5, 4, 2),
            (1, 1, 2, 1, 3)
        ]
    );
}

#[test]
fn not_started_settlement_does_not_read_output() {
    let mut journal = Journal::seeded();
    let platform = VirtualProcessTreeFixtureV1::new();
    platform
        .set_launch_script(super::VirtualLaunchScriptV1::NoProcessStarted)
        .expect("healthy fixture");
    let mut output = OutputSource::terminal();

    let outcome = ProcessOrchestratorV1::new()
        .dispatch_input(
            input(2),
            &admission(),
            &mut journal,
            &platform,
            &platform,
            &mut output,
            &Clock::new(&[0]),
            &Cancel(false),
        )
        .expect("not started settlement");

    assert_eq!(outcome.state(), Some(ProcessLifecycleStateV1::NotStarted));
    assert_eq!(output.reads(), 0);
}

#[test]
fn transient_payload_exists_only_on_first_authorized_return() {
    let mut journal = Journal::seeded();
    let platform = terminal_platform();
    let request = input(3);
    let mut output = OutputSource::streamed();
    let orchestrator = ProcessOrchestratorV1::new();

    let first = orchestrator
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
        .unwrap();
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
        .unwrap();

    let (ProcessDispatchOutcomeV1::Terminal(first), ProcessDispatchOutcomeV1::Terminal(replay)) =
        (first, replay)
    else {
        panic!("expected terminal results")
    };
    assert!(first.transient().is_some());
    assert!(replay.transient().is_none());
    assert_eq!(first.settlement(), replay.settlement());
}

#[test]
fn terminal_replay_has_no_transient_payload_or_source_reads() {
    let mut journal = Journal::seeded();
    let platform = terminal_platform();
    let request = input(4);
    let mut output = OutputSource::terminal();
    let orchestrator = ProcessOrchestratorV1::new();
    let _ = orchestrator
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
        .unwrap();
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
        .unwrap()
    else {
        panic!("expected terminal replay")
    };
    assert!(replay.transient().is_none());
    assert_eq!(output.reads(), reads);
}

#[test]
fn output_source_violation_settles_uncertain_without_partial_payload() {
    let mut journal = Journal::seeded();
    let platform = terminal_platform();
    let mut output = OutputSource::violating();

    assert_eq!(
        ProcessOrchestratorV1::new()
            .dispatch_input(
                input(5),
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut output,
                &Clock::new(&[0, 0, 1]),
                &Cancel(false)
            )
            .unwrap(),
        ProcessDispatchOutcomeV1::State(ProcessLifecycleStateV1::Uncertain)
    );
    let settlement = journal
        .records
        .get("sealed-permit")
        .unwrap()
        .settlement()
        .unwrap();
    assert_eq!(
        settlement.proof(),
        &ProcessSettlementProofV1::Uncertain(ProcessUncertainReasonV1::OutputEvidenceUnavailable)
    );
    assert_eq!(settlement.output().stdout().byte_count(), 0);
}

#[test]
fn lost_commit_response_replays_without_second_effect_or_output_read() {
    let mut journal = Journal::seeded();
    journal.lose_terminal_commit_response();
    let platform = terminal_platform();
    let request = input(6);
    let mut output = OutputSource::terminal();
    let orchestrator = ProcessOrchestratorV1::new();

    assert!(
        orchestrator
            .dispatch_input(
                request.clone(),
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut output,
                &Clock::new(&[0, 0, 1]),
                &Cancel(false)
            )
            .is_err()
    );
    let reads = output.reads();
    let calls = platform.call_log().unwrap();
    assert!(matches!(
        orchestrator
            .dispatch_input(
                request,
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut output,
                &Clock::new(&[0]),
                &Cancel(false)
            )
            .unwrap(),
        ProcessDispatchOutcomeV1::Terminal(_)
    ));
    assert_eq!(output.reads(), reads);
    assert_eq!(platform.call_log().unwrap(), calls);
}

#[test]
fn running_state_does_not_collect_output() {
    let mut journal = Journal::seeded();
    let platform = VirtualProcessTreeFixtureV1::new();
    let mut output = OutputSource::terminal();

    assert_eq!(
        ProcessOrchestratorV1::new()
            .dispatch_input(
                input(7),
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut output,
                &Clock::new(&[0, 0, 0]),
                &Cancel(false)
            )
            .unwrap(),
        ProcessDispatchOutcomeV1::State(ProcessLifecycleStateV1::Running)
    );
    assert_eq!(output.reads(), 0);
}
