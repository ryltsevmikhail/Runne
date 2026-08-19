    // ── Golden vectors ────────────────────────────────────────────────────

    #[test]
    fn test_golden_for_create() {
        let conv_id: ConversationId = CONV_ID_STR.parse().unwrap();
        let ws_id: WorkspaceId = WS_ID_STR.parse().unwrap();
        let fp = CommandFingerprint::for_create(&conv_id, &ws_id);
        // Pre-computed SHA-256 of:
        //   domain_prefix(12) || schema_version(2,BE=0x0001) || tag(0x01) ||
        //   conv_id(16) || ws_id(16)
        let expected: [u8; 32] = [
            0xbc, 0xa3, 0x53, 0x11, 0xd0, 0x2f, 0x65, 0x79, 0x52, 0x02, 0x12, 0x2d, 0x25, 0xb1,
            0xa2, 0xb5, 0xb9, 0x35, 0x52, 0x92, 0xf5, 0xac, 0x26, 0xd4, 0x7a, 0xfb, 0xec, 0xf4,
            0xfe, 0x4b, 0x57, 0x5b,
        ];
        assert_eq!(*fp.as_bytes(), expected);
    }

    #[test]
    fn test_golden_for_queue() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_queue(&tr_id, 0);
        let fp2 = CommandFingerprint::for_queue(&tr_id, 0);
        assert_eq!(fp1, fp2);

        let fp_diff = CommandFingerprint::for_queue(&tr_id, 1);
        assert_ne!(fp1, fp_diff);
    }

    #[test]
    fn test_golden_for_admit() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_admit(&tr_id, 0);
        let fp2 = CommandFingerprint::for_admit(&tr_id, 0);
        assert_eq!(fp1, fp2);

        let fp_diff = CommandFingerprint::for_admit(&tr_id, 1);
        assert_ne!(fp1, fp_diff);
    }

    #[test]
    fn test_golden_for_start_attempt() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_start_attempt(&tr_id, 0);
        let fp2 = CommandFingerprint::for_start_attempt(&tr_id, 0);
        assert_eq!(fp1, fp2);

        let fp_diff = CommandFingerprint::for_start_attempt(&tr_id, 1);
        assert_ne!(fp1, fp_diff);
    }

    #[test]
    fn test_golden_for_complete_success() {
        use runne_domain::command::TerminalResult;
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_complete(&tr_id, &TerminalResult::Success, 0).unwrap();
        let fp2 = CommandFingerprint::for_complete(&tr_id, &TerminalResult::Success, 0).unwrap();
        assert_eq!(fp1, fp2);

        let fp_diff = CommandFingerprint::for_complete(
            &tr_id,
            &TerminalResult::Failure {
                reason: String::from("x"),
            },
            0,
        )
        .unwrap();
        assert_ne!(fp1, fp_diff);
    }

    #[test]
    fn test_golden_for_complete_failure() {
        use runne_domain::command::TerminalResult;
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_complete(
            &tr_id,
            &TerminalResult::Failure {
                reason: String::from("ERR"),
            },
            0,
        )
        .unwrap();
        let fp2 = CommandFingerprint::for_complete(
            &tr_id,
            &TerminalResult::Failure {
                reason: String::from("ERR"),
            },
            0,
        )
        .unwrap();
        assert_eq!(fp1, fp2);

        let fp_diff = CommandFingerprint::for_complete(
            &tr_id,
            &TerminalResult::Failure {
                reason: String::from("OTHER"),
            },
            0,
        )
        .unwrap();
        assert_ne!(fp1, fp_diff);
    }

    #[test]
    fn test_golden_tags_are_distinct() {
        // Same inputs, different tags → different digests
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp_queue = CommandFingerprint::for_queue(&tr_id, 0);
        let fp_admit = CommandFingerprint::for_admit(&tr_id, 0);
        assert_ne!(fp_queue, fp_admit);
    }
