use gocode_platform_ports::process::{
    HeldProcessTreeHandleV1, ProcessAttemptIdV1, ProcessGenerationIdV1, ProcessLifecycleBindingV1,
    ProcessOwnerIdV1, ProcessSessionIdV1,
};

use super::{
    ProcessDispatchOutcomeV1, ProcessLifecycleStateV1, ProcessOrchestratorV1, VirtualGraceScriptV1,
    VirtualLaunchScriptV1, VirtualProcessCallV1, VirtualProcessTreeFixtureV1,
    orchestrator_test_support::{Cancel, Clock, Journal, OutputSource, admission, input},
};

#[test]
fn launch_and_control_binding_mismatches_are_uncertain_without_tree_mutation() {
    for position in 0..5 {
        let mut journal = Journal::seeded();
        let platform = VirtualProcessTreeFixtureV1::with_descendants(2, 3);
        let input = input(20 + position);
        platform
            .set_launch_evidence_binding(mismatched_binding(&input.binding, position))
            .expect("healthy fixture");

        assert_eq!(
            ProcessOrchestratorV1::new()
                .dispatch_input(
                    input,
                    &admission(),
                    &mut journal,
                    &platform,
                    &platform,
                    &mut OutputSource::terminal(),
                    &Clock::new(&[0]),
                    &Cancel(false)
                )
                .unwrap(),
            ProcessDispatchOutcomeV1::State(ProcessLifecycleStateV1::Uncertain)
        );
        assert_eq!(
            platform.call_log().expect("healthy fixture"),
            vec![
                VirtualProcessCallV1::ValidateAndPrepare,
                VirtualProcessCallV1::Launch
            ]
        );
        assert_eq!(
            (
                platform.descendants().expect("healthy fixture"),
                platform.unrelated_descendants().expect("healthy fixture"),
            ),
            (2, 3)
        );
    }

    let mut journal = Journal::seeded();
    let platform = VirtualProcessTreeFixtureV1::with_descendants(2, 3);
    let input = input(25);
    platform
        .set_control_binding(mismatched_binding(&input.binding, 0))
        .expect("healthy fixture");

    assert_eq!(
        ProcessOrchestratorV1::new()
            .dispatch_input(
                input,
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut OutputSource::terminal(),
                &Clock::new(&[0, 0, 1]),
                &Cancel(false),
            )
            .unwrap(),
        ProcessDispatchOutcomeV1::State(ProcessLifecycleStateV1::Uncertain)
    );
    assert_eq!(
        platform.call_log().expect("healthy fixture"),
        vec![
            VirtualProcessCallV1::ValidateAndPrepare,
            VirtualProcessCallV1::Launch,
            VirtualProcessCallV1::RequestGraceful,
        ]
    );
    assert_eq!(
        (
            platform.descendants().expect("healthy fixture"),
            platform.unrelated_descendants().expect("healthy fixture"),
        ),
        (2, 3)
    );
}

#[test]
fn launch_and_forced_ambiguities_are_uncertain_while_graceful_cleanup_is_terminal() {
    for (launch, grace, force, expect_terminal) in [
        (
            VirtualLaunchScriptV1::Ambiguous,
            VirtualGraceScriptV1::Expire,
            false,
            false,
        ),
        (
            VirtualLaunchScriptV1::Launch,
            VirtualGraceScriptV1::Ambiguous,
            false,
            true,
        ),
        (
            VirtualLaunchScriptV1::Launch,
            VirtualGraceScriptV1::Expire,
            true,
            false,
        ),
    ] {
        let mut journal = Journal::seeded();
        let platform = VirtualProcessTreeFixtureV1::new();
        platform.set_launch_script(launch).expect("healthy fixture");
        platform.set_grace_script(grace).expect("healthy fixture");
        if force {
            platform.make_force_ambiguous().expect("healthy fixture");
        }
        let input = input(
            30 + u8::from(force)
                + if launch == VirtualLaunchScriptV1::Ambiguous {
                    1
                } else {
                    0
                },
        );
        let orchestrator = ProcessOrchestratorV1::new();

        assert_expected_dispatch_outcome(
            orchestrator
                .dispatch_input(
                    input.clone(),
                    &admission(),
                    &mut journal,
                    &platform,
                    &platform,
                    &mut OutputSource::terminal(),
                    &Clock::new(&[0, 0, 1]),
                    &Cancel(false),
                )
                .unwrap(),
            expect_terminal,
        );
        let calls = platform.call_log().expect("healthy fixture");
        assert_expected_dispatch_outcome(
            orchestrator
                .dispatch_input(
                    input,
                    &admission(),
                    &mut journal,
                    &platform,
                    &platform,
                    &mut OutputSource::terminal(),
                    &Clock::new(&[0]),
                    &Cancel(false),
                )
                .unwrap(),
            expect_terminal,
        );
        assert_eq!(platform.call_log().expect("healthy fixture"), calls);
    }
}

fn assert_expected_dispatch_outcome(outcome: ProcessDispatchOutcomeV1, expect_terminal: bool) {
    if expect_terminal {
        assert!(matches!(outcome, ProcessDispatchOutcomeV1::Terminal(_)));
    } else {
        assert_eq!(
            outcome,
            ProcessDispatchOutcomeV1::State(ProcessLifecycleStateV1::Uncertain)
        );
    }
}

fn mismatched_binding(
    binding: &ProcessLifecycleBindingV1,
    position: u8,
) -> ProcessLifecycleBindingV1 {
    let marker = [99; 16];
    ProcessLifecycleBindingV1::new(
        if position == 0 {
            ProcessOwnerIdV1::new(marker).unwrap()
        } else {
            binding.owner().clone()
        },
        if position == 1 {
            ProcessAttemptIdV1::new(marker).unwrap()
        } else {
            binding.attempt().clone()
        },
        if position == 2 {
            ProcessSessionIdV1::new(marker).unwrap()
        } else {
            binding.session().clone()
        },
        if position == 3 {
            ProcessGenerationIdV1::new(marker).unwrap()
        } else {
            binding.generation().clone()
        },
        if position == 4 {
            HeldProcessTreeHandleV1::new(marker).unwrap()
        } else {
            binding.tree_handle().clone()
        },
    )
}
