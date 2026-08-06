use super::{
    ProcessDispatchOutcomeV1, ProcessOrchestratorV1, VirtualGraceScriptV1, VirtualProcessCallV1,
    VirtualProcessTreeFixtureV1,
    orchestrator_test_support::{Cancel, Clock, Journal, OutputSource, admission, input},
};

#[test]
fn wait_for_grace_unavailable_attempts_forced_cleanup_without_relaunch() {
    let mut journal = Journal::seeded();
    let platform = VirtualProcessTreeFixtureV1::new();
    platform
        .set_grace_script(VirtualGraceScriptV1::Ambiguous)
        .expect("healthy fixture");

    assert!(matches!(
        ProcessOrchestratorV1::new()
            .dispatch_input(
                input(31),
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut OutputSource::terminal(),
                &Clock::new(&[0, 0, 1]),
                &Cancel(false),
            )
            .expect("unavailable grace evidence settles uncertain after cleanup"),
        ProcessDispatchOutcomeV1::Terminal(_)
    ));
    assert_eq!(
        platform.call_log().expect("healthy fixture"),
        vec![
            VirtualProcessCallV1::ValidateAndPrepare,
            VirtualProcessCallV1::Launch,
            VirtualProcessCallV1::RequestGraceful,
            VirtualProcessCallV1::WaitForGrace,
            VirtualProcessCallV1::Terminate,
        ]
    );
}
