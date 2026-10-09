mod policy_stop_projection_tests {
    use super::*;

    #[test]
    fn only_current_policy_stop_reasons_prove_policy_projection() {
        let policy_event = TaskRunEvent::TaskRunFailed {
            reason: "local_command_policy_stopped_v1".into(),
        };
        for reason in 2..=5 {
            assert!(policy_stop_reason_matches(Some(reason), &policy_event));
        }
        for reason in [None, Some(1), Some(6)] {
            assert!(!policy_stop_reason_matches(reason, &policy_event));
        }
        assert!(!policy_stop_reason_matches(
            Some(3),
            &TaskRunEvent::CancellationCompleted
        ));
    }
}
