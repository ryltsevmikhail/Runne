use super::*;
use crate::permissions_tests::intent as mode_intent;
use crate::permissions_tests::{COMMAND, saved_record, session_info};

fn response_intent(decision: runne_runtime_client::ApprovalDecisionDto) -> ApprovalResponseIntent {
    ApprovalResponseIntent {
        approval_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000011").unwrap(),
        command_id: CanonicalId::parse(COMMAND).unwrap(),
        idempotency_key: "approval-key-01".to_owned(),
        decision,
    }
}

fn snapshot() -> ApprovalSnapshot {
    ApprovalSnapshot {
        approval_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000011").unwrap(),
        task_run_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000012").unwrap(),
        attempt_id: Some(CanonicalId::parse("018f2e3a-7000-7000-8000-000000000013").unwrap()),
        invocation_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000014").unwrap(),
        action: "file.create".to_owned(),
        resource: "workspace:/new.txt".to_owned(),
        action_digest: [0x11; 32],
        policy_revision: 7,
        request_version: 3,
        approval_generation: 4,
        expires_at: unix_millis().unwrap() + 60_000,
        risk_summary: "create a file".to_owned(),
        state: runne_runtime_client::ApprovalStateDto::Pending,
    }
}

#[test]
fn approval_record_roundtrips_exact_bounded_witness_without_disclosure_text() {
    let session = session_info();
    let stable = StableRuntimeIdentity::from_session(&session).unwrap();
    let audit = RuntimeAuditSnapshot::from_session(&session).unwrap();
    let intent = response_intent(runne_runtime_client::ApprovalDecisionDto::Approve);
    let approval = snapshot();
    let bytes = make_approval_recovery_record(&intent, &approval, stable, audit).unwrap();
    let record = decode_approval_recovery_record(&bytes).unwrap();
    assert_eq!(record.approval_id, approval.approval_id);
    assert_eq!(record.task_run_id, approval.task_run_id);
    assert_eq!(record.expected_version, approval.request_version);
    assert_eq!(record.approval_generation, approval.approval_generation);
    let json = String::from_utf8(bytes).unwrap();
    assert!(!json.contains(&approval.action));
    assert!(!json.contains(&approval.resource));
    assert!(!json.contains(&approval.risk_summary));
}

#[test]
fn approval_record_roundtrips_zero_authorization_epoch() {
    let mut session = session_info();
    session.authorization_epoch = 0;
    let bytes = make_approval_recovery_record(
        &response_intent(runne_runtime_client::ApprovalDecisionDto::Approve),
        &snapshot(),
        StableRuntimeIdentity::from_session(&session).unwrap(),
        RuntimeAuditSnapshot::from_session(&session).unwrap(),
    )
    .unwrap();
    assert_eq!(
        decode_approval_recovery_record(&bytes)
            .unwrap()
            .audit
            .authorization_epoch,
        0
    );
}

#[test]
fn review_digest_binds_decision_and_full_canonical_disclosure() {
    let session = session_info();
    let stable = StableRuntimeIdentity::from_session(&session).unwrap();
    let intent = response_intent(runne_runtime_client::ApprovalDecisionDto::Approve);
    let approval = snapshot();
    let digest = approval_review_digest(&intent, &approval, &stable);
    let denied = response_intent(runne_runtime_client::ApprovalDecisionDto::Deny);
    assert_ne!(digest, approval_review_digest(&denied, &approval, &stable));
    let mut changed = approval;
    changed.resource.push_str("/changed");
    assert_ne!(digest, approval_review_digest(&intent, &changed, &stable));
}

#[test]
fn shared_recovery_decoder_recognizes_mode_and_approval_record_kinds() {
    let mode = saved_record(&mode_intent());
    assert!(matches!(
        decode_any_command_record(&mode),
        Ok(RecoveredCommandRecord::PermissionMode(_))
    ));
    let session = session_info();
    let bytes = make_approval_recovery_record(
        &response_intent(runne_runtime_client::ApprovalDecisionDto::Deny),
        &snapshot(),
        StableRuntimeIdentity::from_session(&session).unwrap(),
        RuntimeAuditSnapshot::from_session(&session).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        decode_any_command_record(&bytes),
        Ok(RecoveredCommandRecord::ApprovalDecision(_))
    ));
    assert!(matches!(
        decode_mode_recovery_record(&bytes, CanonicalId::parse(COMMAND).unwrap()),
        Err(CliError::PermissionRecoveryConflict(_))
    ));
    assert!(matches!(
        decode_any_command_record(b"{"),
        Err(RecoveryError::Corrupt)
    ));
}
