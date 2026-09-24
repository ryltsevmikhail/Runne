    #[test]
    fn test_taskrun_event_codec_roundtrip_created() {
        let codec = TaskRunEventCodec;
        let original = TaskRunEvent::TaskRunCreated;
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn submitted_prompt_round_trips_and_is_length_bounded() {
        let codec = TaskRunEventCodec;
        let event = TaskRunEvent::TaskRunSubmitted {
            conversation_id: CONV_ID.parse().unwrap(),
            workspace_id: WS_ID.parse().unwrap(),
            input: runne_domain::task_run::TaskRunInput::new("summarize this repository".into())
                .unwrap(),
        };
        let bytes = codec.encode(&event).unwrap();
        assert_eq!(bytes[2], 0x22);
        assert_eq!(codec.decode(&bytes).unwrap(), event);
        let mut oversized = bytes.clone();
        oversized[35..39].copy_from_slice(&65_537u32.to_be_bytes());
        assert!(codec.decode(&oversized).is_err());
        assert!(codec.decode(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn phase5_taskrun_event_codec_roundtrips_all_thirteen_tags() {
        let cycle_id: CycleId = CONV_ID.parse().unwrap();
        let attempt_id: AttemptId = ATT_ID.parse().unwrap();
        let checkpoint_id: CheckpointId = WS_ID.parse().unwrap();
        let digest = IntegrityDigest::from_bytes([8; 32]);
        let step_ref = phase5_step_ref();
        let wake_evidence = WakeEvidenceRef {
            cycle_id,
            condition_digest: IntegrityDigest::from_bytes([9; 32]),
            source: WakeEvidenceSource::Approval,
            evidence_id: WS_ID.parse().unwrap(),
            evidence_digest: IntegrityDigest::from_bytes([10; 32]),
            observed_at_unix_us: 100,
            authority_revision: "approval-v1".into(),
        };
        let events = vec![
            TaskRunEvent::LoopCycleStarted {
                cycle_id,
                attempt_id,
                sequence: 0,
                parent_cycle_id: None,
            },
            TaskRunEvent::ContextCommitted {
                cycle_id,
                manifest_ref: phase5_context_ref(),
            },
            TaskRunEvent::PlanCommitted {
                cycle_id,
                plan_revision_ref: phase5_plan_ref(),
                input_digest: IntegrityDigest::from_bytes([11; 32]),
                output_digest: IntegrityDigest::from_bytes([12; 32]),
                expected_proposal_indexes: vec![0],
            },
            TaskRunEvent::StepOutcomeRecorded {
                cycle_id,
                outcome: StepOutcomeRecord {
                    proposal_index: 0,
                    step_id: WS_ID.parse().unwrap(),
                    outcome_type: StepOutcomeType::Succeeded,
                    result_ref: Some(
                        ResultRef::new(
                            TR_ID.parse().unwrap(),
                            "text/plain",
                            IntegrityDigest::from_bytes([13; 32]),
                        )
                        .unwrap(),
                    ),
                    effect_id: None,
                    evidence_digests: vec![IntegrityDigest::from_bytes([14; 32])],
                },
            },
            TaskRunEvent::LoopCycleCompleted {
                cycle_id,
                attempt_id,
                disposition: LoopDisposition::Wait {
                    reason: "approval".into(),
                    wake_condition: WakeCondition {
                        kind: WakeConditionKind::Approval,
                        condition_ref: "approval:1".into(),
                        condition_digest: IntegrityDigest::from_bytes([9; 32]),
                    },
                },
            },
            TaskRunEvent::NextCycleCreated {
                parent_cycle_id: cycle_id,
                successor_cycle_id: WS_ID.parse().unwrap(),
                attempt_id,
                sequence: 1,
            },
            TaskRunEvent::RetryScheduled {
                ordinal: 1,
                old_attempt_id: attempt_id,
                new_attempt_id: WS_ID.parse().unwrap(),
                abandoned_cycle_id: cycle_id,
                step_outcome_ref: step_ref.clone(),
                retry_policy_digest: digest,
                budget_reservation_ref: phase5_budget_ref(),
                delay_ms: 25,
                due_at_unix_us: 125,
            },
            TaskRunEvent::LoopCheckpointRecorded {
                checkpoint_id,
                event_position: 20,
                body: LoopCheckpointBody {
                    schema_version: "1".into(),
                    cycle_id,
                    attempt_id,
                    plan_revision_ref: Some(phase5_plan_ref()),
                    context_manifest_ref: Some(phase5_context_ref()),
                    step_outcome_refs: vec![step_ref],
                },
                integrity_digest: digest,
            },
            TaskRunEvent::ActivateScheduledRetryAttempt {
                ordinal: 1,
                attempt_id: WS_ID.parse().unwrap(),
                activated_at_unix_us: 125,
            },
            TaskRunEvent::RecoveryResumeStarted {
                new_attempt_id: WS_ID.parse().unwrap(),
                new_generation: 1,
                abandoned_cycle_id: Some(cycle_id),
                context_manifest_ref: phase5_context_ref(),
                checkpoint_ref: CheckpointRef {
                    checkpoint_id,
                    event_position: 20,
                    integrity_digest: digest,
                },
                reconciliation_ref: ReconciliationResultRef {
                    reconciliation_run_id: WS_ID.parse().unwrap(),
                    taskrun_id: TR_ID.parse().unwrap(),
                    predecessor_attempt_id: attempt_id,
                    recovery_generation: 0,
                    reconciled_stream_position: 19,
                    status: ReconciliationStatus::Reconciled,
                    unresolved_effect_count: 0,
                    result_digest: digest,
                },
            },
            TaskRunEvent::LoopCheckpointStarted {
                checkpoint_id,
                event_position: 20,
                integrity_digest: digest,
            },
            TaskRunEvent::LoopCheckpointCommitted {
                checkpoint_id,
                event_position: 20,
                integrity_digest: digest,
            },
            TaskRunEvent::LoopWakeAccepted {
                cycle_id,
                wake_evidence_ref: wake_evidence,
            },
        ];

        let codec = TaskRunEventCodec;
        let expected_tags = 0x15u8..=0x21;
        for (event, expected_tag) in events.iter().zip(expected_tags) {
            let bytes = codec.encode(event).unwrap();
            assert_eq!(bytes[2], expected_tag);
            assert_eq!(codec.decode(&bytes).unwrap(), *event);

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

    #[test]
    fn test_taskrun_event_codec_roundtrip_queued() {
        let codec = TaskRunEventCodec;
        let original = TaskRunEvent::TaskRunQueued;
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_taskrun_event_codec_roundtrip_attempt_started() {
        let codec = TaskRunEventCodec;
        let aid: AttemptId = ATT_ID.parse().unwrap();
        let original = TaskRunEvent::AttemptStarted { attempt_id: aid };
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_taskrun_event_codec_roundtrip_completed_success() {
        let codec = TaskRunEventCodec;
        let original = TaskRunEvent::TaskRunCompleted {
            result: TerminalResult::Success,
        };
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_taskrun_event_codec_roundtrip_completed_failure() {
        let codec = TaskRunEventCodec;
        let original = TaskRunEvent::TaskRunCompleted {
            result: TerminalResult::Failure {
                reason: "test error".into(),
            },
        };
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_taskrun_event_codec_rejects_unknown_version() {
        let codec = TaskRunEventCodec;
        let mut bytes = codec.encode(&TaskRunEvent::TaskRunCreated).unwrap();
        // Corrupt version bytes
        bytes[0] = 0xFF;
        bytes[1] = 0xFF;
        let err = codec.decode(&bytes).unwrap_err();
        assert!(matches!(err, StoreCodecError::UnsupportedVersion { .. }));
    }

    #[test]
    fn test_taskrun_event_codec_rejects_unknown_tag() {
        let codec = TaskRunEventCodec;
        let mut bytes = codec.encode(&TaskRunEvent::TaskRunCreated).unwrap();
        bytes[2] = 0xFF;
        let err = codec.decode(&bytes).unwrap_err();
        assert!(matches!(err, StoreCodecError::UnknownTag { .. }));
    }

    #[test]
    fn test_taskrun_event_codec_rejects_trailing_bytes() {
        let codec = TaskRunEventCodec;
        let mut bytes = codec.encode(&TaskRunEvent::TaskRunCreated).unwrap();
        bytes.push(0x00);
        let err = codec.decode(&bytes).unwrap_err();
        assert!(matches!(err, StoreCodecError::TrailingBytes { .. }));
    }
