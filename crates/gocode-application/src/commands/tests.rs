    use super::*;

    const VALID_UUID: &str = "018f2e3a-7000-7000-8000-000000000000";

    #[test]
    fn test_command_outcome_clone_eq() {
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let c1 = CommandOutcome::TaskRunCreated {
            taskrun_id: tr_id,
            new_version: 1,
        };
        let c2 = c1.clone();
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_command_outcome_attempt_started_holds_attempt_id() {
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let att_id: AttemptId = "018f2e3a-7000-7000-8000-000000000001".parse().unwrap();
        let outcome = CommandOutcome::AttemptStarted {
            taskrun_id: tr_id,
            attempt_id: att_id,
            new_version: 4,
        };
        if let CommandOutcome::AttemptStarted { attempt_id, .. } = &outcome {
            assert_eq!(*attempt_id, att_id);
        } else {
            panic!("expected AttemptStarted");
        }
    }
