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
            condition_digest: runne_domain::id::IntegrityDigest::from_bytes([1; 32]),
            source: WakeEvidenceSource::Approval,
            evidence_id: WS_ID_STR.parse().unwrap(),
            evidence_digest: runne_domain::id::IntegrityDigest::from_bytes([2; 32]),
            observed_at_unix_us: 11,
            authority_revision: "approval-v1".into(),
        },
    };
    let mut changed_wake = wake.clone();
    changed_wake.wake_evidence_ref.evidence_digest =
        runne_domain::id::IntegrityDigest::from_bytes([3; 32]);
    assert_ne!(
        CommandFingerprint::for_resume_loop_wait(&wake),
        CommandFingerprint::for_resume_loop_wait(&changed_wake)
    );
}

#[test]
fn explicit_model_changes_submit_fingerprint_but_absent_model_stays_frozen() {
    let conversation = CONV_ID_STR.parse().unwrap();
    let workspace = WS_ID_STR.parse().unwrap();
    let no_model = runne_domain::task_run::TaskRunInput::new("same prompt".into()).unwrap();
    let current_none = CommandFingerprint::for_submit(&conversation, &workspace, &no_model);
    let mut historical = begin(TAG_SUBMIT_TASK_RUN);
    historical.update(conversation.as_bytes());
    historical.update(workspace.as_bytes());
    update_string(&mut historical, "same prompt");
    assert_eq!(
        current_none,
        CommandFingerprint(historical.finalize().into())
    );
    let model_a = runne_domain::task_run::TaskRunInput::new("same prompt".into())
        .unwrap()
        .with_requested_model("model-a".into())
        .unwrap();
    let model_b = runne_domain::task_run::TaskRunInput::new("same prompt".into())
        .unwrap()
        .with_requested_model("model-b".into())
        .unwrap();
    assert_ne!(
        CommandFingerprint::for_submit(&conversation, &workspace, &model_a),
        CommandFingerprint::for_submit(&conversation, &workspace, &model_b),
    );
    let profile_a = no_model
        .clone()
        .with_selected_profile(
            runne_domain::task_run::SelectedProviderProfile::new("profile/a".into(), [1; 32])
                .unwrap(),
        )
        .unwrap();
    let profile_id_changed = no_model
        .clone()
        .with_selected_profile(
            runne_domain::task_run::SelectedProviderProfile::new("profile/b".into(), [1; 32])
                .unwrap(),
        )
        .unwrap();
    let profile_digest_changed = no_model
        .with_selected_profile(
            runne_domain::task_run::SelectedProviderProfile::new("profile/a".into(), [2; 32])
                .unwrap(),
        )
        .unwrap();
    assert_ne!(
        CommandFingerprint::for_submit(&conversation, &workspace, &profile_a),
        CommandFingerprint::for_submit(&conversation, &workspace, &profile_id_changed)
    );
    assert_ne!(
        CommandFingerprint::for_submit(&conversation, &workspace, &profile_a),
        CommandFingerprint::for_submit(&conversation, &workspace, &profile_digest_changed)
    );
}
