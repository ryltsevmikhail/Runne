use super::*;
use runne_api::PermissionControlResultV1;
use std::cell::Cell;
use std::collections::VecDeque;

const COMMAND_ID: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1];

fn pending() -> runne_api::PermissionModeNativePendingV2 {
    pending_for(COMMAND_ID)
}

fn pending_for(command_id: [u8; 16]) -> runne_api::PermissionModeNativePendingV2 {
    runne_api::PermissionModeNativePendingV2 {
        workspace_id: "00000000-0000-7000-8000-000000000002".to_owned(),
        principal_id: "principal".to_owned(),
        context: runne_api::PermissionModeNativePendingContextV2 {
            runtime_authority: "runtime".to_owned(),
            store_lineage_id: [1; 16],
            stable_subject_digest: [2; 32],
            protected_launch_authority_id: [3; 16],
            desktop_authority_id: [4; 16],
            daemon_instance_id: [5; 16],
            protected_session_id: [6; 16],
            launch_generation: 7,
            native_key_epoch: 8,
            command_id: uuid::Uuid::from_bytes(command_id).to_string(),
            idempotency_key: "mode-change".to_owned(),
            public_request_digest: [9; 32],
            predecessor_transcript_digest: [10; 32],
            issued_at_unix_ms: 100,
            expires_at_unix_ms: 200,
        },
    }
}

fn committed_status() -> PermissionModeCommandStatusV2 {
    serde_json::from_value(serde_json::json!({
        "state": "committed",
        "receipt": {
            "commandId": COMMAND_ID,
            "idempotencyKey": "mode-change",
            "intentDigest": vec![11_u8; 32],
            "authorizationRevision": 12,
            "selectedMode": "risk_based",
            "history": {
                "selectedMode": "risk_based",
                "effective": { "state": "notReady", "reason": "preset_unavailable" },
                "authorizationRevision": 12,
                "presetVersion": 1,
                "managedPolicyVersion": 13,
                "containment": null,
                "networkState": "unavailable",
                "expiresAtUnixMs": null
            }
        }
    }))
    .expect("canonical committed command status")
}

fn committed_result() -> PermissionControlResultV1 {
    PermissionControlResultV1 {
        code: PermissionControlResultCodeV1::Committed,
        command_id: COMMAND_ID,
        public_request_digest: [9; 32],
        receipt_digest: Some([11; 32]),
        authorization_revision: Some(12),
        managed_policy_revision: Some(13),
    }
}

fn pending_result() -> PermissionControlResultV1 {
    PermissionControlResultV1 {
        code: PermissionControlResultCodeV1::Pending,
        command_id: COMMAND_ID,
        public_request_digest: [9; 32],
        receipt_digest: None,
        authorization_revision: None,
        managed_policy_revision: None,
    }
}

fn cancelled_result() -> PermissionControlResultV1 {
    PermissionControlResultV1 {
        code: PermissionControlResultCodeV1::Cancelled,
        command_id: COMMAND_ID,
        public_request_digest: [9; 32],
        receipt_digest: None,
        authorization_revision: None,
        managed_policy_revision: None,
    }
}

fn pending_status(command_id: [u8; 16]) -> PermissionModeCommandStatusV2 {
    serde_json::from_value(serde_json::json!({
        "state": "pending_native_confirmation",
        "commandId": command_id,
        "expiresAtUnixMs": 200
    }))
    .expect("canonical pending status")
}

fn cancelled_status(command_id: [u8; 16]) -> PermissionModeCommandStatusV2 {
    serde_json::from_value(serde_json::json!({
        "state": "cancelled",
        "commandId": command_id
    }))
    .expect("canonical cancelled status")
}

#[tokio::test]
async fn unknown_rpc_waits_read_only_for_terminal_before_next_command() {
    let pending = pending();
    let mut statuses = VecDeque::from([
        Ok(pending_status(COMMAND_ID)),
        Ok(cancelled_status(COMMAND_ID)),
    ]);
    let status_reads = Cell::new(0);
    let resolved = super::recovery::wait_for_terminal(
        &pending,
        None,
        || {
            status_reads.set(status_reads.get() + 1);
            std::future::ready(statuses.pop_front().expect("expected a readback"))
        },
        || false,
        std::time::Duration::ZERO,
    )
    .await;
    assert!(
        resolved,
        "matching terminal readback releases the worker to poll again"
    );
    assert_eq!(status_reads.get(), 2);

    let next_command_id = [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 2];
    let next_pending = pending_for(next_command_id);
    let next_resolved = super::recovery::wait_for_terminal(
        &next_pending,
        None,
        || {
            status_reads.set(status_reads.get() + 1);
            std::future::ready(Ok(cancelled_status(next_command_id)))
        },
        || false,
        std::time::Duration::ZERO,
    )
    .await;
    assert!(next_resolved, "the following distinct command can proceed");
    assert_eq!(status_reads.get(), 3);
}

#[tokio::test]
async fn pending_and_transient_read_error_wait_for_terminal_readback() {
    let pending = pending();
    let result = pending_result();
    let mut statuses = VecDeque::from([
        Err(()),
        Ok(pending_status(COMMAND_ID)),
        Ok(committed_status()),
    ]);
    let status_reads = Cell::new(0);
    let resolved = super::recovery::wait_for_terminal(
        &pending,
        Some(&result),
        || {
            status_reads.set(status_reads.get() + 1);
            std::future::ready(statuses.pop_front().expect("expected a readback"))
        },
        || false,
        std::time::Duration::ZERO,
    )
    .await;
    assert!(resolved);
    assert_eq!(status_reads.get(), 3);
}

#[tokio::test]
async fn wrong_command_or_contradictory_terminal_readback_never_resolves() {
    let pending = pending();
    let wrong_id = [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 2];
    let reads = Cell::new(0);
    let wrong_command_resolved = super::recovery::wait_for_terminal(
        &pending,
        None,
        || {
            reads.set(reads.get() + 1);
            std::future::ready(Ok(cancelled_status(wrong_id)))
        },
        || reads.get() >= 3,
        std::time::Duration::ZERO,
    )
    .await;
    assert!(!wrong_command_resolved);
    assert_eq!(reads.get(), 3);

    let mut mismatched_result = committed_result();
    mismatched_result.receipt_digest = Some([12; 32]);
    let reads = Cell::new(0);
    let contradictory_resolved = super::recovery::wait_for_terminal(
        &pending,
        Some(&mismatched_result),
        || {
            reads.set(reads.get() + 1);
            std::future::ready(Ok(committed_status()))
        },
        || reads.get() >= 3,
        std::time::Duration::ZERO,
    )
    .await;
    assert!(!contradictory_resolved);
    assert_eq!(reads.get(), 3);
}

#[tokio::test]
async fn authenticated_terminal_readback_recovers_after_transient_read_error() {
    let pending = pending();
    let result = committed_result();
    let mut statuses = VecDeque::from([Err(()), Ok(committed_status())]);
    let status_reads = Cell::new(0);
    let resolved = super::recovery::wait_for_terminal(
        &pending,
        Some(&result),
        || {
            status_reads.set(status_reads.get() + 1);
            std::future::ready(statuses.pop_front().expect("expected a readback"))
        },
        || false,
        std::time::Duration::ZERO,
    )
    .await;
    assert!(resolved);
    assert_eq!(status_reads.get(), 2);
}

#[tokio::test]
async fn authenticated_cancelled_result_requires_matching_terminal_readback() {
    let pending = pending();
    let result = cancelled_result();
    let status_reads = Cell::new(0);
    let resolved = super::recovery::wait_for_terminal(
        &pending,
        Some(&result),
        || {
            status_reads.set(status_reads.get() + 1);
            std::future::ready(Ok(cancelled_status(COMMAND_ID)))
        },
        || false,
        std::time::Duration::ZERO,
    )
    .await;
    assert!(resolved);
    assert_eq!(status_reads.get(), 1);
}

#[test]
fn unknown_rpc_readback_is_bound_to_the_original_command() {
    let pending = pending();
    let matching = serde_json::from_value(serde_json::json!({
        "state": "cancelled",
        "commandId": COMMAND_ID
    }))
    .expect("cancelled status");
    assert!(status_belongs_to_pending_command(&matching, &pending));
    assert!(status_belongs_to_pending_command(
        &committed_status(),
        &pending
    ));

    let other_id = [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 2];
    let unrelated = serde_json::from_value(serde_json::json!({
        "state": "pending_native_confirmation",
        "commandId": other_id,
        "expiresAtUnixMs": 200
    }))
    .expect("unrelated pending status");
    assert!(!status_belongs_to_pending_command(&unrelated, &pending));
}

#[test]
fn committed_readback_requires_the_same_command_request_and_receipt() {
    let pending = pending();
    let status = committed_status();
    assert!(readback_matches(&committed_result(), &status, &pending));

    let mut changed = committed_result();
    changed.command_id[15] = 2;
    assert!(!readback_matches(&changed, &status, &pending));
    let mut changed = committed_result();
    changed.public_request_digest[0] ^= 1;
    assert!(!readback_matches(&changed, &status, &pending));
    let mut changed = committed_result();
    changed.receipt_digest = Some([12; 32]);
    assert!(!readback_matches(&changed, &status, &pending));
    let mut changed = committed_result();
    changed.managed_policy_revision = Some(14);
    assert!(!readback_matches(&changed, &status, &pending));
}
