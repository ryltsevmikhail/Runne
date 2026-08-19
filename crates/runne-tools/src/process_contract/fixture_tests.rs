use super::{
    VirtualFixtureErrorV1, VirtualGraceScriptV1, VirtualLaunchScriptV1, VirtualProcessTreeFixtureV1,
};

#[test]
fn poisoned_fixture_rejects_every_observer_and_mutator() {
    let fixture = VirtualProcessTreeFixtureV1::new();
    let input = super::orchestrator_test_support::input(19);
    let binding = input.binding.clone();
    let executable = input.request.executable().clone();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fixture.poison_for_test()));

    assert_eq!(
        fixture.set_launch_script(VirtualLaunchScriptV1::Ambiguous),
        Err(VirtualFixtureErrorV1::Poisoned)
    );
    assert_eq!(
        fixture.set_grace_script(VirtualGraceScriptV1::Ambiguous),
        Err(VirtualFixtureErrorV1::Poisoned)
    );
    assert_eq!(
        fixture.reject_prepare(),
        Err(VirtualFixtureErrorV1::Poisoned)
    );
    assert_eq!(
        fixture.set_observed_executable(executable),
        Err(VirtualFixtureErrorV1::Poisoned)
    );
    assert_eq!(
        fixture.make_force_ambiguous(),
        Err(VirtualFixtureErrorV1::Poisoned)
    );
    assert_eq!(
        fixture.set_launch_evidence_binding(binding.clone()),
        Err(VirtualFixtureErrorV1::Poisoned)
    );
    assert_eq!(
        fixture.set_control_binding(binding),
        Err(VirtualFixtureErrorV1::Poisoned)
    );
    assert_eq!(fixture.call_log(), Err(VirtualFixtureErrorV1::Poisoned));
    assert_eq!(fixture.descendants(), Err(VirtualFixtureErrorV1::Poisoned));
    assert_eq!(
        fixture.unrelated_descendants(),
        Err(VirtualFixtureErrorV1::Poisoned)
    );
}

#[test]
fn healthy_fixture_accepts_each_script_variant() {
    let fixture = VirtualProcessTreeFixtureV1::new();

    fixture
        .set_launch_script(VirtualLaunchScriptV1::NoProcessStarted)
        .expect("healthy fixture");
}
