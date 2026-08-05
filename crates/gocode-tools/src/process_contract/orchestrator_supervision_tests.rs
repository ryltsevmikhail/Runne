use gocode_platform_ports::process::{ProcessOwnerVerificationV1, ProcessTreeCleanupV1};

use super::{
    ProcessDispatchOutcomeV1, ProcessLifecycleStateV1, ProcessOrchestratorV1,
    VirtualCompletionScriptV1, VirtualProcessCallV1, VirtualProcessTreeFixtureV1,
    orchestrator_test_support::{Cancel, Clock, Journal, OutputSource, admission, input},
};

#[test]
fn late_timeout_supervision_terminates_without_relaunch() {
    let (mut journal, platform, request) = running(0);
    let mut output = OutputSource::terminal();

    assert!(matches!(
        ProcessOrchestratorV1::new()
            .supervise_input(
                request,
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut output,
                &Clock::new(&[1, 1]),
                &Cancel(false),
            )
            .expect("timeout supervision"),
        ProcessDispatchOutcomeV1::Terminal(_)
    ));
    assert_eq!(
        platform.call_log().expect("healthy fixture"),
        forced_calls()
    );
}

#[test]
fn late_cancellation_supervision_terminates_without_relaunch() {
    let (mut journal, platform, request) = running(0);
    let mut output = OutputSource::terminal();

    assert!(matches!(
        ProcessOrchestratorV1::new()
            .supervise_input(
                request,
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut output,
                &Clock::new(&[0, 0]),
                &Cancel(true),
            )
            .expect("cancellation supervision"),
        ProcessDispatchOutcomeV1::Terminal(_)
    ));
    assert_eq!(
        platform.call_log().expect("healthy fixture"),
        forced_calls()
    );
}

#[test]
fn pending_completion_remains_running_without_output_read() {
    let (mut journal, platform, request) = running(0);
    let mut output = OutputSource::terminal();

    assert_eq!(
        ProcessOrchestratorV1::new()
            .supervise_input(
                request,
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut output,
                &Clock::new(&[0]),
                &Cancel(false),
            )
            .expect("pending supervision"),
        ProcessDispatchOutcomeV1::State(ProcessLifecycleStateV1::Running)
    );
    assert_eq!(
        platform.call_log().expect("healthy fixture"),
        completion_calls()
    );
    assert_eq!(output.reads(), 0);
}

#[test]
fn owner_or_cleanup_mismatch_completion_becomes_uncertain() {
    for (owner, cleanup) in [
        (
            ProcessOwnerVerificationV1::Mismatch,
            ProcessTreeCleanupV1::Verified,
        ),
        (
            ProcessOwnerVerificationV1::Verified,
            ProcessTreeCleanupV1::Unverified,
        ),
    ] {
        let (mut journal, platform, request) = running(0);
        platform
            .set_completion_script(VirtualCompletionScriptV1::Mismatch)
            .expect("healthy fixture");
        platform
            .set_terminal_verification(owner, cleanup)
            .expect("healthy fixture");
        let mut output = OutputSource::terminal();

        assert_eq!(
            ProcessOrchestratorV1::new()
                .supervise_input(
                    request,
                    &admission(),
                    &mut journal,
                    &platform,
                    &platform,
                    &mut output,
                    &Clock::new(&[0]),
                    &Cancel(false),
                )
                .expect("mismatched completion"),
            ProcessDispatchOutcomeV1::State(ProcessLifecycleStateV1::Uncertain)
        );
        assert_eq!(output.reads(), 0);
    }

    let (mut journal, platform, request) = running(0);
    platform
        .set_completion_script(VirtualCompletionScriptV1::Unavailable)
        .expect("healthy fixture");
    let mut output = OutputSource::terminal();
    assert_eq!(
        ProcessOrchestratorV1::new()
            .supervise_input(
                request,
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut output,
                &Clock::new(&[0]),
                &Cancel(false),
            )
            .expect("unavailable completion"),
        ProcessDispatchOutcomeV1::State(ProcessLifecycleStateV1::Uncertain)
    );
    assert_eq!(output.reads(), 0);
}

#[test]
fn graceful_failure_still_attempts_forced_exact_tree_cleanup() {
    let mut journal = Journal::seeded();
    let platform = VirtualProcessTreeFixtureV1::new();
    let request = input(72);
    platform.reject_graceful().expect("healthy fixture");
    let mut output = OutputSource::terminal();

    assert!(matches!(
        ProcessOrchestratorV1::new()
            .dispatch_input(
                request,
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut output,
                &Clock::new(&[0, 0, 1, 1]),
                &Cancel(false),
            )
            .expect("forced cleanup after graceful failure"),
        ProcessDispatchOutcomeV1::Terminal(_)
    ));
    assert_eq!(
        platform.call_log().expect("healthy fixture"),
        vec![
            VirtualProcessCallV1::ValidateAndPrepare,
            VirtualProcessCallV1::Launch,
            VirtualProcessCallV1::RequestGraceful,
            VirtualProcessCallV1::Terminate,
        ]
    );
}

#[test]
fn terminating_resume_forces_without_launch_or_graceful_repeat() {
    let (mut journal, platform, request) = running(0);
    journal
        .records
        .get_mut("sealed-permit")
        .expect("running record")
        .transition(ProcessLifecycleStateV1::Terminating)
        .expect("terminating state");
    let mut output = OutputSource::terminal();

    assert!(matches!(
        ProcessOrchestratorV1::new()
            .supervise_input(
                request,
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut output,
                &Clock::new(&[]),
                &Cancel(false),
            )
            .expect("terminating resume"),
        ProcessDispatchOutcomeV1::Terminal(_)
    ));
    assert_eq!(
        platform.call_log().expect("healthy fixture"),
        vec![
            VirtualProcessCallV1::ValidateAndPrepare,
            VirtualProcessCallV1::Launch,
            VirtualProcessCallV1::Terminate,
        ]
    );
}

#[test]
fn supervisor_clock_regression_uncertain() {
    let (mut journal, platform, request) = running(10);
    let mut output = OutputSource::terminal();

    assert_eq!(
        ProcessOrchestratorV1::new()
            .supervise_input(
                request,
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut output,
                &Clock::new(&[9]),
                &Cancel(false),
            )
            .expect("regressed supervision"),
        ProcessDispatchOutcomeV1::State(ProcessLifecycleStateV1::Uncertain)
    );
    assert!(platform.call_log().expect("healthy fixture").len() == 2);
}

fn running(
    started_at: u64,
) -> (
    Journal,
    VirtualProcessTreeFixtureV1,
    super::orchestrator_input::DispatchInputV1,
) {
    let mut journal = Journal::seeded();
    let platform = VirtualProcessTreeFixtureV1::new();
    let request = input(70);
    assert_eq!(
        ProcessOrchestratorV1::new()
            .dispatch_input(
                request.clone(),
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut OutputSource::terminal(),
                &Clock::new(&[started_at, started_at, started_at]),
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

fn forced_calls() -> Vec<VirtualProcessCallV1> {
    let mut calls = vec![
        VirtualProcessCallV1::ValidateAndPrepare,
        VirtualProcessCallV1::Launch,
        VirtualProcessCallV1::RequestGraceful,
        VirtualProcessCallV1::WaitForGrace,
    ];
    calls.push(VirtualProcessCallV1::Terminate);
    calls
}
