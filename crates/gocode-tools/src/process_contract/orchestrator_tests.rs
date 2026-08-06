use super::{
    ProcessDispatchOutcomeV1, ProcessLifecycleStateV1, ProcessOrchestratorV1,
    ProcessSettlementProofV1, ProcessUncertainReasonV1, VirtualProcessCallV1,
    VirtualProcessTreeFixtureV1,
    orchestrator_test_support::{Cancel, Clock, Journal, OutputSource, admission, input},
};
use gocode_platform_ports::process::{
    HeldFileIdentityV1, ProcessFileKindV1, ProcessSymlinkProofV1, VerifiedExecutableV1,
};

// These private-input checks are internal engine conformance only. Sealed end-to-end dispatch is
// deferred; the external integration test proves only the public `dispatch` signature compiles.

#[test]
fn timeout_before_dispatch_does_not_claim_or_touch_the_virtual_platform() {
    let mut journal = Journal::default();
    let platform = VirtualProcessTreeFixtureV1::new();
    let outcome = ProcessOrchestratorV1::new()
        .dispatch_input(
            input(1),
            &admission(),
            &mut journal,
            &platform,
            &platform,
            &mut OutputSource::terminal(),
            &Clock::new(&[0, 1]),
            &Cancel(false),
        )
        .expect("closed timeout result");

    assert_eq!(outcome, ProcessDispatchOutcomeV1::Denied);
    assert!(journal.records.is_empty());
    assert!(platform.call_log().expect("healthy fixture").is_empty());
}

#[test]
fn prepare_and_launch_receive_same_persisted_deadline() {
    let mut journal = Journal::seeded();
    let platform = VirtualProcessTreeFixtureV1::new();
    let request = input(11);

    ProcessOrchestratorV1::new()
        .dispatch_input(
            request,
            &admission(),
            &mut journal,
            &platform,
            &platform,
            &mut OutputSource::terminal(),
            &Clock::new(&[10, 10]),
            &Cancel(false),
        )
        .expect("dispatch outcome");

    let record = &journal.records["sealed-permit"];
    assert_eq!(
        platform
            .prepare_deadline()
            .expect("healthy fixture")
            .expect("prepare deadline"),
        record.deadline()
    );
    assert_eq!(
        platform
            .launch_deadline()
            .expect("healthy fixture")
            .expect("launch deadline"),
        record.deadline()
    );
}

#[test]
fn executable_substitution_after_verification_vetoes_launch_and_replays_uncertain() {
    let mut journal = Journal::seeded();
    let platform = VirtualProcessTreeFixtureV1::new();
    let input = input(5);
    let held = input.request.executable().identity();
    let observed = VerifiedExecutableV1::new(
        HeldFileIdentityV1::new(
            [9; 16],
            *held.canonical_identity_digest(),
            *held.content_digest(),
            *held.filesystem_identity_digest(),
            held.identity_version(),
        )
        .expect("nonempty observed token"),
        ProcessFileKindV1::RegularFile,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .expect("valid observed executable");
    assert_ne!(&observed, input.request.executable());
    assert_ne!(observed.identity().token(), held.token());
    assert_eq!(
        observed.identity().canonical_identity_digest(),
        held.canonical_identity_digest()
    );
    assert_eq!(observed.identity().content_digest(), held.content_digest());
    assert_eq!(
        observed.identity().filesystem_identity_digest(),
        held.filesystem_identity_digest()
    );
    assert_eq!(
        observed.identity().identity_version(),
        held.identity_version()
    );
    platform
        .set_observed_executable(observed)
        .expect("healthy fixture");
    let orchestrator = ProcessOrchestratorV1::new();
    let mut output = OutputSource::terminal();

    assert_eq!(
        orchestrator
            .dispatch_input(
                input.clone(),
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut output,
                &Clock::new(&[0]),
                &Cancel(false),
            )
            .expect("ambiguous platform settles"),
        ProcessDispatchOutcomeV1::State(ProcessLifecycleStateV1::Uncertain)
    );
    let record = &journal.records["sealed-permit"];
    assert_eq!(record.state(), ProcessLifecycleStateV1::Uncertain);
    assert_eq!(
        record.settlement().expect("uncertain settlement").proof(),
        &ProcessSettlementProofV1::Uncertain(ProcessUncertainReasonV1::EvidenceUnavailable)
    );
    assert_eq!(
        platform.call_log().expect("healthy fixture"),
        vec![VirtualProcessCallV1::ValidateAndPrepare]
    );
    assert!(!platform.has_held_binding().expect("healthy fixture"));
    assert_eq!(output.reads(), 0);
    assert_eq!(
        orchestrator
            .dispatch_input(
                input,
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut output,
                &Clock::new(&[0]),
                &Cancel(false),
            )
            .expect("uncertain replay is pure"),
        ProcessDispatchOutcomeV1::State(ProcessLifecycleStateV1::Uncertain)
    );
    assert_eq!(
        platform.call_log().expect("healthy fixture"),
        vec![VirtualProcessCallV1::ValidateAndPrepare]
    );
    assert_eq!(output.reads(), 0);
}

#[test]
fn cancellation_uses_exact_tree_control_then_forced_virtual_cleanup() {
    let mut journal = Journal::seeded();
    let platform = VirtualProcessTreeFixtureV1::with_descendants(2, 3);
    let outcome = ProcessOrchestratorV1::new()
        .dispatch_input(
            input(7),
            &admission(),
            &mut journal,
            &platform,
            &platform,
            &mut OutputSource::terminal(),
            &Clock::new(&[0, 0, 1]),
            &Cancel(false),
        )
        .expect("virtual termination result");

    assert!(matches!(outcome, ProcessDispatchOutcomeV1::Terminal(_)));
    assert_eq!(platform.descendants().expect("healthy fixture"), 0);
    assert_eq!(
        platform.unrelated_descendants().expect("healthy fixture"),
        3
    );
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
