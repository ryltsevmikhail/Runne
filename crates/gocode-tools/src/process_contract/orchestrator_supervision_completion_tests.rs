use super::{
    ProcessDispatchOutcomeV1, ProcessLifecycleStateV1, ProcessOrchestratorV1,
    VirtualCompletionScriptV1, VirtualProcessCallV1, VirtualProcessTreeFixtureV1,
    orchestrator_test_support::{Cancel, Clock, Journal, OutputSource, admission, input},
};

#[test]
fn normal_completion_observation_atomically_settles_output_and_replays_without_calls() {
    let (mut journal, platform, request) = running();
    platform
        .set_completion_script(VirtualCompletionScriptV1::Complete)
        .expect("healthy fixture");
    let mut output = OutputSource::streamed();
    let orchestrator = ProcessOrchestratorV1::new();

    let first = supervise(
        &orchestrator,
        request.clone(),
        &mut journal,
        &platform,
        &mut output,
    );
    let calls = platform.call_log().expect("healthy fixture");
    let reads = output.reads();
    let replay = supervise(&orchestrator, request, &mut journal, &platform, &mut output);

    assert!(matches!(first, ProcessDispatchOutcomeV1::Terminal(_)));
    assert!(matches!(replay, ProcessDispatchOutcomeV1::Terminal(_)));
    assert_eq!(first, replay);
    assert_eq!(calls, completion_calls());
    assert_eq!(platform.call_log().expect("healthy fixture"), calls);
    assert_eq!(reads, 4);
    assert_eq!(output.reads(), reads);
}

#[test]
fn terminal_supervision_replay_is_pure() {
    let (mut journal, platform, request) = running();
    platform
        .set_completion_script(VirtualCompletionScriptV1::Complete)
        .expect("healthy fixture");
    let mut output = OutputSource::terminal();
    let orchestrator = ProcessOrchestratorV1::new();
    let _ = supervise(
        &orchestrator,
        request.clone(),
        &mut journal,
        &platform,
        &mut output,
    );
    let calls = platform.call_log().expect("healthy fixture");
    let reads = output.reads();

    let replay = supervise(&orchestrator, request, &mut journal, &platform, &mut output);

    assert!(matches!(replay, ProcessDispatchOutcomeV1::Terminal(_)));
    assert_eq!(platform.call_log().expect("healthy fixture"), calls);
    assert_eq!(output.reads(), reads);
}

fn supervise(
    orchestrator: &ProcessOrchestratorV1,
    request: super::orchestrator_input::DispatchInputV1,
    journal: &mut Journal,
    platform: &VirtualProcessTreeFixtureV1,
    output: &mut OutputSource,
) -> ProcessDispatchOutcomeV1 {
    orchestrator
        .supervise_input(
            request,
            &admission(),
            journal,
            platform,
            platform,
            output,
            &Clock::new(&[0]),
            &Cancel(false),
        )
        .expect("completion supervision")
}

fn running() -> (
    Journal,
    VirtualProcessTreeFixtureV1,
    super::orchestrator_input::DispatchInputV1,
) {
    let mut journal = Journal::seeded();
    let platform = VirtualProcessTreeFixtureV1::new();
    let request = input(71);
    assert_eq!(
        ProcessOrchestratorV1::new()
            .dispatch_input(
                request.clone(),
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut OutputSource::terminal(),
                &Clock::new(&[0, 0, 0]),
                &Cancel(false),
            )
            .expect("running dispatch"),
        ProcessDispatchOutcomeV1::State(ProcessLifecycleStateV1::Running)
    );
    (journal, platform, request)
}

fn completion_calls() -> Vec<VirtualProcessCallV1> {
    vec![
        VirtualProcessCallV1::ValidateAndPrepare,
        VirtualProcessCallV1::Launch,
        VirtualProcessCallV1::ObserveTerminal,
    ]
}
