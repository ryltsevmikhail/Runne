
// ─── Golden trace 8: Replay round-trip ────────────────────────────────────

#[test]
fn golden_replay_roundtrip_complete_lifecycle() {
    use gocode_domain::event::EventEnvelope;
    use gocode_domain::event::{
        Actor, CommandContext, DomainEventDraft, Sensitivity, materialize_batch,
    };
    use gocode_domain::id::IntegrityDigest;
    use gocode_domain::timestamp::Timestamp;

    let tr_id: TaskRunId = TR_ID.parse().unwrap();
    let aid: AttemptId = ATT_ID.parse().unwrap();

    fn make_envelope(
        seq: u64,
        payload: TaskRunEvent,
        tr_id: TaskRunId,
    ) -> EventEnvelope<TaskRunEvent> {
        let draft = DomainEventDraft::new(
            AggregateId::TaskRun(tr_id),
            AggregateId::TaskRun(tr_id),
            1,
            Sensitivity::Public,
            payload,
        );
        let ctx = CommandContext {
            command_id: "018f2e3a-7000-7000-8000-000000000000".parse().unwrap(),
            idempotency_key: IdempotencyKey::new("roundtrip").unwrap(),
            actor: Actor::new("roundtrip").unwrap(),
        };
        let ids = &["018f2e3a-7000-7000-8000-000000000000"
            .parse::<gocode_domain::id::EventId>()
            .unwrap()];
        let ue = materialize_batch(vec![draft], ids, None, &ctx)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        ue.into_envelope(
            seq,
            Timestamp::from_unix_micros(1000),
            IntegrityDigest::from_bytes([0; 32]),
        )
    }

    let events = &[
        make_envelope(1, TaskRunEvent::TaskRunCreated, tr_id),
        make_envelope(2, TaskRunEvent::TaskRunQueued, tr_id),
        make_envelope(3, TaskRunEvent::TaskRunAdmitted, tr_id),
        make_envelope(4, TaskRunEvent::AttemptStarted { attempt_id: aid }, tr_id),
        make_envelope(
            5,
            TaskRunEvent::TaskRunCompleted {
                result: TerminalResult::Success,
            },
            tr_id,
        ),
    ];

    let agg = TaskRun::replay(events).unwrap();

    // Expected: Succeeded, 1 attempt in history, matching ID
    assert_eq!(agg.state(), TaskRunState::Succeeded);
    assert_eq!(*agg.id(), tr_id);
    assert_eq!(agg.attempt_history(), &[aid]);
    assert_eq!(agg.terminal_result(), Some(&TerminalResult::Success));
    assert!(agg.active_attempt().is_none());
}

// ─── Golden trace 9: Retry cycle with new attempt ID ──────────────────────

#[test]
fn golden_retry_with_new_attempt() {
    let mut agg = created_aggregate();
    agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
    agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
    let aid1: AttemptId = ATT_ID.parse().unwrap();
    agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid1 })
        .unwrap();

    let aid2: AttemptId = ATT_ID2.parse().unwrap();
    let drafts = agg
        .decide(TaskRunCommand::StartRetry { attempt_id: aid2 })
        .unwrap();
    assert_eq!(
        *drafts[0].payload(),
        TaskRunEvent::RetryStarted { attempt_id: aid2 }
    );

    agg.apply_payload(&TaskRunEvent::RetryStarted { attempt_id: aid2 })
        .unwrap();
    assert_eq!(agg.state(), TaskRunState::Retrying);
    assert_eq!(agg.active_attempt(), Some(&aid2));
    assert_eq!(agg.attempt_history(), &[aid1, aid2]);

    // Complete retry
    agg.apply_payload(&TaskRunEvent::RetryCompleted { attempt_id: aid2 })
        .unwrap();
    assert_eq!(agg.state(), TaskRunState::Running);
    assert_eq!(agg.active_attempt(), Some(&aid2));
}

// ─── Phase 5: Loop ID types ─────────────────────────────────────────────

#[test]
fn golden_cycle_id_roundtrip() {
    let raw = "018f2e3a-7000-7000-8000-000000000005";
    let id: gocode_domain::id::CycleId = raw.parse().unwrap();
    assert_eq!(id.to_string(), raw);
}
