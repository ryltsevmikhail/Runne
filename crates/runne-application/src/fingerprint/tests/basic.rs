    const CONV_ID_STR: &str = "018f2e3a-7000-7000-8000-000000000001";
    const WS_ID_STR: &str = "018f2e3a-7000-7000-8000-000000000002";
    const TR_ID_STR: &str = "018f2e3a-7000-7000-8000-000000000003";

    #[test]
    fn test_for_create_deterministic() {
        let conv_id: ConversationId = CONV_ID_STR.parse().unwrap();
        let ws_id: WorkspaceId = WS_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_create(&conv_id, &ws_id);
        let fp2 = CommandFingerprint::for_create(&conv_id, &ws_id);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.as_bytes(), fp2.as_bytes());
    }

    #[test]
    fn test_for_create_different_conv_is_different() {
        let conv1: ConversationId = CONV_ID_STR.parse().unwrap();
        let conv2: ConversationId = "018f2e3a-7000-7000-8000-00000000000a".parse().unwrap();
        let ws_id: WorkspaceId = WS_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_create(&conv1, &ws_id);
        let fp2 = CommandFingerprint::for_create(&conv2, &ws_id);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn create_conversation_has_a_distinct_deterministic_domain() {
        let conversation_id: ConversationId = CONV_ID_STR.parse().unwrap();
        let workspace_id: WorkspaceId = WS_ID_STR.parse().unwrap();

        let first = CommandFingerprint::for_create_conversation(
            &conversation_id,
            &workspace_id,
            ConversationContextScope::Workspace,
        );
        let second = CommandFingerprint::for_create_conversation(
            &conversation_id,
            &workspace_id,
            ConversationContextScope::Workspace,
        );

        assert_eq!(first, second);
        assert_ne!(
            first,
            CommandFingerprint::for_create(&conversation_id, &workspace_id)
        );
        // The security-significant delivery-context scope is part of the
        // semantic identity: flipping it changes the fingerprint.
        assert_ne!(
            first,
            CommandFingerprint::for_create_conversation(
                &conversation_id,
                &workspace_id,
                ConversationContextScope::TextOnly,
            )
        );
        // The legacy scope-less format stays a distinct, stable digest so
        // durable receipt checks can recognize pre-scope receipts.
        assert_ne!(
            first,
            CommandFingerprint::for_create_conversation_legacy(&conversation_id, &workspace_id)
        );
    }

    #[test]
    fn test_for_queue_deterministic() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_queue(&tr_id, 0);
        let fp2 = CommandFingerprint::for_queue(&tr_id, 0);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_for_queue_different_version_is_different() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_queue(&tr_id, 0);
        let fp2 = CommandFingerprint::for_queue(&tr_id, 1);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_for_admit_deterministic() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_admit(&tr_id, 1);
        let fp2 = CommandFingerprint::for_admit(&tr_id, 1);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_for_start_attempt_deterministic() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_start_attempt(&tr_id, 1);
        let fp2 = CommandFingerprint::for_start_attempt(&tr_id, 1);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_for_complete_success_deterministic() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let result = TerminalResult::Success;
        let fp1 = CommandFingerprint::for_complete(&tr_id, &result, 3).unwrap();
        let fp2 = CommandFingerprint::for_complete(&tr_id, &result, 3).unwrap();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_for_complete_failure_deterministic() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let result = TerminalResult::Failure {
            reason: "test failure".into(),
        };
        let fp1 = CommandFingerprint::for_complete(&tr_id, &result, 3).unwrap();
        let fp2 = CommandFingerprint::for_complete(&tr_id, &result, 3).unwrap();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_for_complete_success_vs_failure_different() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp_success =
            CommandFingerprint::for_complete(&tr_id, &TerminalResult::Success, 3).unwrap();
        let fp_failure = CommandFingerprint::for_complete(
            &tr_id,
            &TerminalResult::Failure {
                reason: "err".into(),
            },
            3,
        )
        .unwrap();
        assert_ne!(fp_success, fp_failure);
    }

    #[test]
    fn test_for_complete_reason_too_long() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let long_reason = "x".repeat(MAX_TERMINAL_REASON_BYTES + 1);
        let result = TerminalResult::Failure {
            reason: long_reason.clone(),
        };
        let err = CommandFingerprint::for_complete(&tr_id, &result, 3).unwrap_err();
        assert_eq!(
            err,
            FingerprintError::TerminalReasonTooLong {
                max: MAX_TERMINAL_REASON_BYTES,
                actual: long_reason.len(),
            }
        );
    }

    #[test]
    fn test_for_complete_reason_at_limit_ok() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let reason = "x".repeat(MAX_TERMINAL_REASON_BYTES);
        let result = TerminalResult::Failure {
            reason: reason.clone(),
        };
        let fp = CommandFingerprint::for_complete(&tr_id, &result, 3).unwrap();
        assert_eq!(fp.as_bytes().len(), 32);
    }
