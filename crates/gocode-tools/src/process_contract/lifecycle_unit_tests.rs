use super::ProcessLifecycleStateV1;

#[test]
fn lifecycle_accepts_only_the_closed_transition_graph() {
    let legal = [
        (
            ProcessLifecycleStateV1::Validating,
            ProcessLifecycleStateV1::Claimed,
        ),
        (
            ProcessLifecycleStateV1::Claimed,
            ProcessLifecycleStateV1::Launching,
        ),
        (
            ProcessLifecycleStateV1::Launching,
            ProcessLifecycleStateV1::NotStarted,
        ),
        (
            ProcessLifecycleStateV1::Launching,
            ProcessLifecycleStateV1::Running,
        ),
        (
            ProcessLifecycleStateV1::Launching,
            ProcessLifecycleStateV1::Uncertain,
        ),
        (
            ProcessLifecycleStateV1::Running,
            ProcessLifecycleStateV1::Terminating,
        ),
        (
            ProcessLifecycleStateV1::Running,
            ProcessLifecycleStateV1::Completed,
        ),
        (
            ProcessLifecycleStateV1::Terminating,
            ProcessLifecycleStateV1::Completed,
        ),
        (
            ProcessLifecycleStateV1::Uncertain,
            ProcessLifecycleStateV1::Uncertain,
        ),
    ];

    for (from, to) in legal {
        assert!(from.permits(to), "{from:?} -> {to:?} must be legal");
    }
    assert!(!ProcessLifecycleStateV1::Completed.permits(ProcessLifecycleStateV1::Running));
}
