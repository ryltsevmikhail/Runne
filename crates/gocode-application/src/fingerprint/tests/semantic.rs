    #[test]
    fn phase5_semantic_fingerprint_matrix() {
        let taskrun_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let cycle_id = CONV_ID_STR.parse().unwrap();
        let start = StartLoopCycleInput {
            taskrun_id,
            expected_version: 7,
        };
        assert_eq!(
            CommandFingerprint::for_start_loop_cycle(&start),
            CommandFingerprint::for_start_loop_cycle(&start)
        );
        assert_ne!(
            CommandFingerprint::for_start_loop_cycle(&start),
            CommandFingerprint::for_start_loop_cycle(&StartLoopCycleInput {
                expected_version: 8,
                ..start.clone()
            })
        );

        let fail = CompleteLoopCycleInput {
            taskrun_id,
            expected_version: 9,
            cycle_id,
            disposition: LoopDisposition::Fail {
                reason: "failed".into(),
                unresolved_proposals: vec![1],
            },
        };
        let changed_unresolved = CompleteLoopCycleInput {
            disposition: LoopDisposition::Fail {
                reason: "failed".into(),
                unresolved_proposals: vec![2],
            },
            ..fail.clone()
        };
        assert_ne!(
            CommandFingerprint::for_complete_loop_cycle(&fail),
            CommandFingerprint::for_complete_loop_cycle(&changed_unresolved)
        );

        let wake = ResumeLoopWaitInput {
            taskrun_id,
            expected_version: 10,
            wake_evidence_ref: WakeEvidenceRef {
                cycle_id,
                condition_digest: gocode_domain::id::IntegrityDigest::from_bytes([1; 32]),
                source: WakeEvidenceSource::Approval,
                evidence_id: WS_ID_STR.parse().unwrap(),
                evidence_digest: gocode_domain::id::IntegrityDigest::from_bytes([2; 32]),
                observed_at_unix_us: 11,
                authority_revision: "approval-v1".into(),
            },
        };
        let mut changed_wake = wake.clone();
        changed_wake.wake_evidence_ref.evidence_digest =
            gocode_domain::id::IntegrityDigest::from_bytes([3; 32]);
        assert_ne!(
            CommandFingerprint::for_resume_loop_wait(&wake),
            CommandFingerprint::for_resume_loop_wait(&changed_wake)
        );
    }
