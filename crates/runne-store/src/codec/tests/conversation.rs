// ── ConversationEvent round-trip ──────────────────────────────────

#[test]
fn conversation_event_codec_created_has_stable_bytes() {
    let codec = ConversationEventCodec;
    let workspace_id: WorkspaceId = WS_ID.parse().unwrap();
    let original = ConversationEvent::ConversationCreated { workspace_id };

    let bytes = codec.encode(&original).unwrap();

    let mut expected = vec![0x00, 0x01, TAG_CONVERSATION_CREATED];
    expected.extend_from_slice(workspace_id.as_bytes());
    assert_eq!(bytes, expected);
    assert_eq!(codec.decode(&bytes).unwrap(), original);
}

#[test]
fn conversation_event_codec_closed_has_stable_bytes() {
    let codec = ConversationEventCodec;
    let bytes = codec
        .encode(&ConversationEvent::ConversationClosed)
        .unwrap();

    assert_eq!(bytes, [0x00, 0x01, TAG_CONVERSATION_CLOSED]);
    assert_eq!(
        codec.decode(&bytes).unwrap(),
        ConversationEvent::ConversationClosed
    );
}

#[test]
fn accounting_unknown_failure_reason_has_stable_round_trip_tag() {
    let codec = ConversationEventCodec;
    let taskrun_id: TaskRunId = TR_ID.parse().unwrap();
    let attempt_id: AttemptId = ATT_ID.parse().unwrap();
    let original = ConversationEvent::GenerationFailed {
        taskrun_id,
        attempt_id,
        reason: runne_domain::conversation::GenerationFailureReason::ProviderAccountingUnknown,
    };
    let bytes = codec.encode(&original).unwrap();
    assert_eq!(codec.decode(&bytes).unwrap(), original);
    assert_eq!(&bytes[..3], &[0x00, 0x02, TAG_GENERATION_FAILED]);
    assert_eq!(&bytes[3..19], taskrun_id.as_bytes());
    assert_eq!(&bytes[19..35], attempt_id.as_bytes());
    assert_eq!(bytes[35], REASON_PROVIDER_ACCOUNTING_UNKNOWN);
}

#[test]
fn accounting_unknown_reason_is_rejected_under_historical_codec_v1() {
    let codec = ConversationEventCodec;
    let mut bytes = vec![0x00, 0x01, TAG_GENERATION_FAILED];
    bytes.extend_from_slice(TR_ID.parse::<TaskRunId>().unwrap().as_bytes());
    bytes.extend_from_slice(ATT_ID.parse::<AttemptId>().unwrap().as_bytes());
    bytes.push(REASON_PROVIDER_ACCOUNTING_UNKNOWN);

    assert!(matches!(
        codec.decode(&bytes),
        Err(StoreCodecError::UnknownTag {
            tag: REASON_PROVIDER_ACCOUNTING_UNKNOWN,
            context: "GenerationFailureReason",
        })
    ));
}

#[test]
fn conversation_message_events_roundtrip_sensitive_text_and_execution_ids() {
    let codec = ConversationEventCodec;
    let message_id: MessageId = CONV_ID.parse().unwrap();
    let taskrun_id: TaskRunId = TR_ID.parse().unwrap();
    let attempt_id: AttemptId = ATT_ID.parse().unwrap();

    for original in [
        ConversationEvent::UserMessageAppended {
            message_id,
            taskrun_id,
            attempt_id,
            text: MessageText::new("hello").unwrap(),
        },
        ConversationEvent::AssistantMessageAppended {
            message_id,
            taskrun_id,
            attempt_id,
            text: MessageText::new("world").unwrap(),
        },
    ] {
        let bytes = codec.encode(&original).unwrap();
        assert_eq!(codec.decode(&bytes).unwrap(), original);
    }
}

#[test]
fn conversation_message_codec_rejects_oversized_text_before_allocation() {
    let codec = ConversationEventCodec;
    let mut bytes = vec![0x00, 0x01, TAG_USER_MESSAGE_APPENDED];
    bytes.extend_from_slice(CONV_ID.parse::<MessageId>().unwrap().as_bytes());
    bytes.extend_from_slice(TR_ID.parse::<TaskRunId>().unwrap().as_bytes());
    bytes.extend_from_slice(ATT_ID.parse::<AttemptId>().unwrap().as_bytes());
    bytes.extend_from_slice(&((MAX_MESSAGE_TEXT_BYTES as u64) + 1).to_be_bytes());

    assert!(matches!(
        codec.decode(&bytes),
        Err(StoreCodecError::Oversized {
            field: "message_text",
            ..
        })
    ));
}

#[test]
fn conversation_event_codec_rejects_unknown_version_tag_and_trailing_bytes() {
    let codec = ConversationEventCodec;
    let mut unknown_version = vec![0xff, 0xff, TAG_CONVERSATION_CLOSED];
    assert!(matches!(
        codec.decode(&unknown_version),
        Err(StoreCodecError::UnsupportedVersion { .. })
    ));

    unknown_version[0] = 0x00;
    unknown_version[1] = 0x01;
    unknown_version[2] = 0xff;
    assert!(matches!(
        codec.decode(&unknown_version),
        Err(StoreCodecError::UnknownTag { .. })
    ));

    let mut trailing = codec
        .encode(&ConversationEvent::ConversationClosed)
        .unwrap();
    trailing.push(0);
    assert!(matches!(
        codec.decode(&trailing),
        Err(StoreCodecError::TrailingBytes { remaining: 1 })
    ));
}

#[test]
fn conversation_event_codec_rejects_non_uuid_v7_workspace() {
    let codec = ConversationEventCodec;
    let mut bytes = vec![0x00, 0x01, TAG_CONVERSATION_CREATED];
    bytes.extend_from_slice(&[0; 16]);

    assert!(matches!(
        codec.decode(&bytes),
        Err(StoreCodecError::UnknownTag {
            context: "ConversationCreated workspace UUIDv7",
            ..
        })
    ));
}
