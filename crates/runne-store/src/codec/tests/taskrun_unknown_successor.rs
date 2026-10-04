#[test]
fn unknown_successor_events_round_trip_with_new_codec_versions() {
    let successor: TaskRunId = "018f0000-0000-7000-8000-000000000002".parse().unwrap();
    let predecessor: TaskRunId = TR_ID.parse().unwrap();
    let attempt: AttemptId = ATT_ID.parse().unwrap();
    let digest = IntegrityDigest::from_bytes([0x5a; 32]);

    let task_event = TaskRunEvent::UserSupersedeUnknown {
        predecessor_attempt_id: attempt,
        successor_taskrun_id: successor,
        acknowledgement_digest: digest,
    };
    let task_codec = TaskRunEventCodec;
    let task_bytes = task_codec.encode(&task_event).unwrap();
    assert_eq!(&task_bytes[..2], &6u16.to_be_bytes());
    assert_eq!(task_codec.decode(&task_bytes).unwrap(), task_event);

    for version in 1..6u16 {
        let mut unsupported = task_bytes.clone();
        unsupported[..2].copy_from_slice(&version.to_be_bytes());
        assert!(
            task_codec.decode(&unsupported).is_err(),
            "unknown-successor event must not be accepted under historical codec v{version}"
        );
    }

    let conversation_event = ConversationEvent::GenerationSupersededUnknown {
        taskrun_id: predecessor,
        attempt_id: attempt,
        successor_taskrun_id: successor,
        acknowledgement_digest: digest,
    };
    let conversation_codec = ConversationEventCodec;
    let conversation_bytes = conversation_codec.encode(&conversation_event).unwrap();
    assert_eq!(&conversation_bytes[..2], &2u16.to_be_bytes());
    assert_eq!(
        conversation_codec.decode(&conversation_bytes).unwrap(),
        conversation_event
    );
}
