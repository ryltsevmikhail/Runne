    const VALID_UUID: &str = "018f2e3a-7000-7000-8000-000000000000";
    const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000001";
    const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-000000000002";
    const ATTEMPT_ID: &str = "018f2e3a-7000-7000-8000-000000000003";
    const ATTEMPT_ID2: &str = "018f2e3a-7000-7000-8000-000000000004";
    const TASKRUN_ID: &str = "018f2e3a-7000-7000-8000-000000000005";

    fn make_create() -> CreateTaskRun {
        CreateTaskRun {
            taskrun_id: VALID_UUID.parse().unwrap(),
            conversation_id: CONVERSATION_ID.parse().unwrap(),
            workspace_id: WORKSPACE_ID.parse().unwrap(),
        }
    }

    fn make_submit() -> SubmitTaskRun {
        SubmitTaskRun {
            taskrun_id: TASKRUN_ID.parse().unwrap(),
            conversation_id: CONVERSATION_ID.parse().unwrap(),
            workspace_id: WORKSPACE_ID.parse().unwrap(),
        }
    }

    fn make_envelope(
        sequence: u64,
        payload: TaskRunEvent,
        taskrun_id: TaskRunId,
    ) -> EventEnvelope<TaskRunEvent> {
        make_envelope_with_correlation(
            sequence,
            payload,
            taskrun_id,
            AggregateId::TaskRun(taskrun_id),
        )
    }

    fn make_envelope_with_correlation(
        sequence: u64,
        payload: TaskRunEvent,
        taskrun_id: TaskRunId,
        correlation_id: AggregateId,
    ) -> EventEnvelope<TaskRunEvent> {
        use crate::event::{Actor, CommandContext, DomainEventDraft};
        use crate::id::{IdempotencyKey, IntegrityDigest};
        use crate::timestamp::Timestamp;
        let draft = DomainEventDraft::new(
            AggregateId::TaskRun(taskrun_id),
            correlation_id,
            1,
            Sensitivity::Public,
            payload,
        );
        let ctx = CommandContext {
            command_id: VALID_UUID.parse().unwrap(),
            idempotency_key: IdempotencyKey::new("test").unwrap(),
            actor: Actor::new("test").unwrap(),
        };
        use crate::event::materialize_batch;
        let ids = &[VALID_UUID.parse().unwrap()];
        let uncommitted = materialize_batch(vec![draft], ids, None, &ctx)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        uncommitted.into_envelope(
            sequence,
            Timestamp::from_unix_micros(1000),
            IntegrityDigest::from_bytes([0; 32]),
        )
    }

    fn create_aggregate() -> TaskRun {
        let cmd = make_create();
        TaskRun::decide_create(cmd).unwrap();
        let events = &[make_envelope(
            1,
            TaskRunEvent::TaskRunCreated,
            VALID_UUID.parse().unwrap(),
        )];
        TaskRun::replay(events).unwrap()
    }

    fn running_aggregate() -> TaskRun {
        let mut aggregate = create_aggregate();
        aggregate
            .apply_payload(&TaskRunEvent::TaskRunQueued)
            .unwrap();
        aggregate
            .apply_payload(&TaskRunEvent::TaskRunAdmitted)
            .unwrap();
        aggregate
            .apply_payload(&TaskRunEvent::AttemptStarted {
                attempt_id: ATTEMPT_ID.parse().unwrap(),
            })
            .unwrap();
        aggregate
    }
