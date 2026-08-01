    #[test]
    fn phase5_command_outcome_codec_roundtrips_tags_six_through_sixteen() {
        let taskrun_id: TaskRunId = TR_ID.parse().unwrap();
        let cycle_id: CycleId = CONV_ID.parse().unwrap();
        let attempt_id: AttemptId = ATT_ID.parse().unwrap();
        let checkpoint_id: CheckpointId = WS_ID.parse().unwrap();
        let outcomes = vec![
            CommandOutcome::CycleStarted {
                taskrun_id,
                cycle_id,
                new_version: 1,
            },
            CommandOutcome::ContextCommitted {
                taskrun_id,
                cycle_id,
                new_version: 2,
            },
            CommandOutcome::PlanCommitted {
                taskrun_id,
                plan_ref: Box::new(phase5_plan_ref()),
                new_version: 3,
            },
            CommandOutcome::StepOutcomeRecorded {
                taskrun_id,
                step_id: WS_ID.parse().unwrap(),
                new_version: 4,
            },
            CommandOutcome::LoopDispositionCommitted {
                taskrun_id,
                cycle_id,
                final_state: TaskRunState::Waiting,
                new_version: 6,
            },
            CommandOutcome::NextCycleAllocated {
                taskrun_id,
                successor_cycle_id: WS_ID.parse().unwrap(),
                new_version: 7,
            },
            CommandOutcome::LoopWaitResumed {
                taskrun_id,
                cycle_id,
                new_version: 9,
            },
            CommandOutcome::RetryScheduled {
                taskrun_id,
                new_attempt_id: attempt_id,
                due_at_unix_us: 100,
                new_version: 10,
            },
            CommandOutcome::RetryActivated {
                taskrun_id,
                attempt_id,
                new_version: 11,
            },
            CommandOutcome::RecoveryResumed {
                taskrun_id,
                attempt_id,
                new_version: 12,
            },
            CommandOutcome::LoopCheckpointCommitted {
                taskrun_id,
                checkpoint_id,
                event_position: 13,
                new_version: 15,
            },
        ];
        let codec = CommandOutcomeCodec;

        for (outcome, expected_tag) in outcomes.iter().zip(0x06u8..=0x10) {
            let bytes = codec.encode(outcome).unwrap();
            assert_eq!(bytes[2], expected_tag);
            assert_eq!(codec.decode(&bytes).unwrap(), *outcome);

            let mut unsupported = bytes.clone();
            unsupported[1] = 2;
            assert!(matches!(
                codec.decode(&unsupported),
                Err(StoreCodecError::UnsupportedVersion { .. })
            ));

            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(matches!(
                codec.decode(&trailing),
                Err(StoreCodecError::TrailingBytes { .. })
            ));

            assert!(matches!(
                codec.decode(&bytes[..bytes.len() - 1]),
                Err(StoreCodecError::Truncated)
            ));
        }
    }

    // ── CommandOutcome round-trip ──────────────────────────────────────

    #[test]
    fn test_command_outcome_codec_roundtrip_created() {
        let codec = CommandOutcomeCodec;
        let tr_id: TaskRunId = TR_ID.parse().unwrap();
        let original = CommandOutcome::TaskRunCreated {
            taskrun_id: tr_id,
            new_version: 1,
        };
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_command_outcome_codec_roundtrip_attempt_started() {
        let codec = CommandOutcomeCodec;
        let tr_id: TaskRunId = TR_ID.parse().unwrap();
        let att_id: AttemptId = ATT_ID.parse().unwrap();
        let original = CommandOutcome::AttemptStarted {
            taskrun_id: tr_id,
            attempt_id: att_id,
            new_version: 4,
        };
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }
