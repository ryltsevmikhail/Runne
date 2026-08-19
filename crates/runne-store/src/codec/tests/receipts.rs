    #[test]
    fn conversation_receipt_codec_has_stable_roundtrip_bytes() {
        let codec = ConversationReceiptCodec;
        let conversation_id: ConversationId = CONV_ID.parse().unwrap();
        let workspace_id: WorkspaceId = WS_ID.parse().unwrap();
        let receipt = ConversationReceipt {
            conversation_id,
            workspace_id,
            new_version: 1,
            committed_at: runne_domain::timestamp::Timestamp::from_unix_micros(1_234_567),
        };

        let bytes = codec.encode(&receipt).unwrap();

        let mut expected = vec![0, 1];
        expected.extend_from_slice(conversation_id.as_bytes());
        expected.extend_from_slice(workspace_id.as_bytes());
        expected.extend_from_slice(&1_u64.to_be_bytes());
        expected.extend_from_slice(&1_234_567_i64.to_be_bytes());
        assert_eq!(bytes, expected);
        assert_eq!(codec.decode(&bytes).unwrap(), receipt);
    }

    #[test]
    fn conversation_receipt_codec_rejects_negative_timestamp_and_trailing_bytes() {
        let codec = ConversationReceiptCodec;
        let receipt = ConversationReceipt {
            conversation_id: CONV_ID.parse().unwrap(),
            workspace_id: WS_ID.parse().unwrap(),
            new_version: 1,
            committed_at: runne_domain::timestamp::Timestamp::from_unix_micros(1),
        };
        let mut negative = codec.encode(&receipt).unwrap();
        let timestamp_start = negative.len() - 8;
        negative[timestamp_start..].copy_from_slice(&(-1_i64).to_be_bytes());
        assert!(matches!(
            codec.decode(&negative),
            Err(StoreCodecError::UnknownTag {
                context: "ConversationReceipt negative commit timestamp",
                ..
            })
        ));

        let mut trailing = codec.encode(&receipt).unwrap();
        trailing.push(0);
        assert!(matches!(
            codec.decode(&trailing),
            Err(StoreCodecError::TrailingBytes { remaining: 1 })
        ));
    }

    // ── IdempotencyScope round-trip ────────────────────────────────────

    #[test]
    fn test_idempotency_scope_codec_roundtrip_existing() {
        let codec = IdempotencyScopeCodec;
        let tr_id: TaskRunId = TR_ID.parse().unwrap();
        let original = IdempotencyScope {
            runtime_authority_id: runne_application::ports::RuntimeAuthorityId("host-1".into()),
            principal_id: runne_application::ports::PrincipalId("user-1".into()),
            operation: OperationTag::Queue,
            aggregate_scope: AggregateScope::ExistingTaskRun { taskrun_id: tr_id },
        };
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_idempotency_scope_codec_roundtrip_new() {
        let codec = IdempotencyScopeCodec;
        let conv_id: ConversationId = CONV_ID.parse().unwrap();
        let ws_id: WorkspaceId = WS_ID.parse().unwrap();
        let original = IdempotencyScope {
            runtime_authority_id: runne_application::ports::RuntimeAuthorityId("host-1".into()),
            principal_id: runne_application::ports::PrincipalId("user-1".into()),
            operation: OperationTag::CreateTaskRun,
            aggregate_scope: AggregateScope::NewTaskRun {
                conversation_id: conv_id,
                workspace_id: ws_id,
            },
        };
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn idempotency_scope_codec_roundtrips_new_conversation() {
        let codec = IdempotencyScopeCodec;
        let original = IdempotencyScope {
            runtime_authority_id: runne_application::ports::RuntimeAuthorityId("host-1".into()),
            principal_id: runne_application::ports::PrincipalId("user-1".into()),
            operation: OperationTag::CreateConversation,
            aggregate_scope: AggregateScope::NewConversation {
                conversation_id: CONV_ID.parse().unwrap(),
                workspace_id: WS_ID.parse().unwrap(),
            },
        };

        let bytes = codec.encode(&original).unwrap();

        assert_eq!(codec.decode(&bytes).unwrap(), original);
    }
