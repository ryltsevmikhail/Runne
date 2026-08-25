#[test]
fn strict_delivery_rejects_extra_and_missing_fields() {
    let mut extra = fixture();
    extra
        .as_object_mut()
        .unwrap()
        .insert("unexpected".into(), serde_json::json!(true));
    assert_eq!(
        validate(&mut validator(), extra).unwrap_err().kind(),
        ReplayClientErrorKind::SchemaMismatch
    );

    let mut missing = fixture();
    missing.as_object_mut().unwrap().remove("eventType");
    assert_eq!(
        validate(&mut validator(), missing).unwrap_err().kind(),
        ReplayClientErrorKind::SchemaMismatch
    );
}

#[test]
fn strict_delivery_rejects_malformed_identity_digest_cursor_and_schema() {
    let cases = [
        ("eventId", serde_json::json!("not-a-uuid")),
        ("integrityDigest", serde_json::json!("AA")),
        ("cursor", serde_json::json!("gocode-replay-cursor-v1.00")),
        ("schemaVersion", serde_json::json!(2)),
    ];
    for (field, replacement) in cases {
        let mut value = fixture();
        value
            .as_object_mut()
            .unwrap()
            .insert(field.to_owned(), replacement);
        assert!(validate(&mut validator(), value).is_err(), "{field}");
    }
}

#[test]
fn strict_delivery_rejects_unknown_payload_wrong_aggregate_and_binding() {
    let mut payload = fixture();
    payload["payload"]["unexpected"] = serde_json::json!(true);
    assert_eq!(
        validate(&mut validator(), payload).unwrap_err().kind(),
        ReplayClientErrorKind::SchemaMismatch
    );

    let mut aggregate = fixture();
    aggregate["aggregateId"] = serde_json::json!("018f2e3a-7000-7000-8000-000000000119");
    assert_eq!(
        validate(&mut validator(), aggregate).unwrap_err().kind(),
        ReplayClientErrorKind::AggregateMismatch
    );

    let mut validator = validator();
    validate(&mut validator, fixture()).unwrap();
    let mut binding = fixture();
    binding["eventId"] = serde_json::json!("018f2e3a-7000-7000-8000-000000000119");
    binding["sequence"] = serde_json::json!(3);
    binding["replayBindingId"] = serde_json::json!("018f2e3a700070008000000000000122");
    assert_eq!(
        validate(&mut validator, binding).unwrap_err().kind(),
        ReplayClientErrorKind::BindingMismatch
    );
}

#[test]
fn task_run_delivery_exposes_only_closed_typed_timeline_data() {
    let task_run_id = "018f2e3a-7000-7000-8000-000000000210";
    let mut value = fixture();
    value["aggregateId"] = serde_json::json!(task_run_id);
    value["aggregateType"] = serde_json::json!("taskRun");
    value["correlationId"] = serde_json::json!(task_run_id);
    value["correlationType"] = serde_json::json!("taskRun");
    value["eventType"] = serde_json::json!("taskRun.attempt.started");
    value["payload"] = serde_json::json!({
        "attemptId": "018f2e3a-7000-7000-8000-000000000211",
        "type": "taskRun.attempt.started"
    });
    let mut validator = DeliveryValidator::new(
        ReplayScope::new(ReplayAggregateKind::TaskRun, CanonicalId::parse(task_run_id).unwrap()),
        ReplayIdentityTracker::new(),
    );

    let delivery = validate(&mut validator, value).expect("typed task run delivery");

    let CanonicalReplayPayload::TaskRun(payload) = delivery.event().payload() else {
        panic!("task run payload");
    };
    assert_eq!(payload.kind(), TaskRunTimelineKind::AttemptStarted);
    assert_eq!(payload.attempt_id(), CanonicalId::parse("018f2e3a-7000-7000-8000-000000000211").ok());
}

#[test]
fn dedup_is_exact_and_never_auto_advances_conflicting_identity() {
    let mut validator = validator();
    assert_eq!(
        validate(&mut validator, fixture()).unwrap().disposition(),
        ReplayDeliveryDisposition::New
    );
    assert_eq!(
        validate(&mut validator, fixture()).unwrap().disposition(),
        ReplayDeliveryDisposition::Duplicate
    );

    let mut conflicting_cursor = fixture();
    conflicting_cursor["cursor"] = serde_json::json!("gocode-replay-cursor-v1.7b2261223a317d");
    assert_eq!(
        validate(&mut validator, conflicting_cursor)
            .unwrap_err()
            .kind(),
        ReplayClientErrorKind::EventIdentityConflict
    );
}

#[test]
fn new_event_sequence_must_increase_monotonically() {
    let mut validator = validator();
    validate(&mut validator, fixture()).unwrap();
    let mut next = fixture();
    next["eventId"] = serde_json::json!("018f2e3a-7000-7000-8000-000000000119");
    next["cursor"] = serde_json::json!("gocode-replay-cursor-v1.7b2261223a317d");
    assert_eq!(
        validate(&mut validator, next).unwrap_err().kind(),
        ReplayClientErrorKind::NonMonotonicSequence
    );

    let mut gap = fixture();
    gap["eventId"] = serde_json::json!("018f2e3a-7000-7000-8000-000000000119");
    gap["cursor"] = serde_json::json!("gocode-replay-cursor-v1.7b2261223a317d");
    gap["sequence"] = serde_json::json!(4);
    assert_eq!(
        validate(&mut validator, gap).unwrap_err().kind(),
        ReplayClientErrorKind::NonMonotonicSequence
    );
}

#[test]
fn retained_baseline_requires_the_next_exact_suffix_sequence() {
    let scope = ReplayScope::new(
        ReplayAggregateKind::Conversation,
        CanonicalId::parse("018f2e3a-7000-7000-8000-000000000110").unwrap(),
    );
    for (sequence, expected) in [
        (0, ReplayClientErrorKind::NonMonotonicSequence),
        (1, ReplayClientErrorKind::NonMonotonicSequence),
        (100, ReplayClientErrorKind::NonMonotonicSequence),
    ] {
        let mut validator =
            DeliveryValidator::from_retained_baseline(scope, ReplayIdentityTracker::new(), 100)
                .expect("baseline");
        let mut value = fixture();
        value["sequence"] = serde_json::json!(sequence);
        assert_eq!(
            validate(&mut validator, value).unwrap_err().kind(),
            expected
        );
    }
    let mut validator =
        DeliveryValidator::from_retained_baseline(scope, ReplayIdentityTracker::new(), 100)
            .expect("baseline");
    let mut next = fixture();
    next["sequence"] = serde_json::json!(101);
    assert_eq!(
        validate(&mut validator, next).unwrap().disposition(),
        ReplayDeliveryDisposition::New
    );
}

#[test]
fn reconnect_binding_changes_do_not_change_stable_event_identity() {
    let identities = ReplayIdentityTracker::new();
    let scope = ReplayScope::new(
        ReplayAggregateKind::Conversation,
        CanonicalId::parse("018f2e3a-7000-7000-8000-000000000110").unwrap(),
    );
    let mut first = DeliveryValidator::new(scope, identities.clone());
    validate(&mut first, fixture()).unwrap();

    let mut rebound = fixture();
    rebound["replayBindingId"] = serde_json::json!("018f2e3a700070008000000000000122");
    let mut second = DeliveryValidator::new(scope, identities);
    assert_eq!(
        validate(&mut second, rebound).unwrap().disposition(),
        ReplayDeliveryDisposition::Duplicate
    );
}

#[test]
fn persistence_handoff_uses_exact_validated_bytes_and_opaque_cursor() {
    let delivery = validate(&mut validator(), fixture()).expect("validated delivery");
    let mut observed = None;
    delivery.persist_with(|handoff| {
        observed = Some((
            handoff.cursor_value().to_owned(),
            handoff.canonical_event_bytes().to_vec(),
            handoff.event_digest().to_owned(),
        ));
    });
    let (cursor, bytes, digest) = observed.expect("handoff");

    assert_eq!(cursor, "gocode-replay-cursor-v1.7b7d");
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), digest);
    assert_eq!(digest, hex::encode(delivery.canonical_digest()));
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("canonical JSON");
    assert!(value.get("cursor").is_none());
    assert!(value.get("replayBindingId").is_none());
}
