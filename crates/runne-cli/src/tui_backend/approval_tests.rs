use super::*;
use crate::permissions_tests::{COMMAND, MemoryIndex, current_status, session_info};
use crate::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
#[path = "../cli/permissions/approval_response_tests/fakes.rs"]
#[allow(
    dead_code,
    clippy::duplicate_mod,
    reason = "fixture imports each parent test module private ports; sharing would broaden test-only visibility"
)]
mod fakes;

#[tokio::test]
async fn tui_acknowledgement_loss_reconciles_and_reopen_never_posts_twice() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = fakes::FakeApprovalRuntime::new(fakes::approval(), events.clone());
    runtime.unknown_after_post.store(true, Ordering::Relaxed);
    let consent = TerminalConsent {
        displayed: runtime.approval.clone(),
        decision: ApprovalDecisionDto::Approve,
    };
    let index = fakes::memory_index(events);
    let mut intent = fakes::response_intent(ApprovalDecisionDto::Approve);
    intent.command_id = intent.approval_id;
    intent.idempotency_key = format!("tui-approval:{}", intent.approval_id);
    assert!(
        super::super::approval_retry::execute(&runtime, intent.clone(), &index, &consent)
            .await
            .is_ok()
    );
    assert!(
        super::super::approval_retry::execute(&runtime, intent, &index, &consent)
            .await
            .is_ok()
    );
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn tui_changed_displayed_scope_does_not_write_recovery_or_post() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = fakes::FakeApprovalRuntime::new(fakes::approval(), events.clone());
    let mut displayed = runtime.approval.clone();
    displayed.resource = "workspace:/other-file".into();
    let consent = TerminalConsent {
        displayed,
        decision: ApprovalDecisionDto::Approve,
    };
    let index = fakes::memory_index(events);
    assert!(
        super::super::approval_retry::execute(
            &runtime,
            fakes::response_intent(ApprovalDecisionDto::Approve),
            &index,
            &consent
        )
        .await
        .is_err()
    );
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 0);
    assert!(index.records.lock().unwrap().is_empty());
}

#[tokio::test]
async fn tui_before_post_crash_allows_fresh_deny_after_proven_no_commit() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = fakes::FakeApprovalRuntime::new(fakes::approval(), events.clone());
    let index = fakes::memory_index(events);
    let mut intent = fakes::response_intent(ApprovalDecisionDto::Approve);
    intent.command_id = intent.approval_id;
    intent.idempotency_key = format!("tui-approval:{}", intent.approval_id);
    let stable = StableRuntimeIdentity::from_session(&session_info()).unwrap();
    let audit = RuntimeAuditSnapshot::from_session(&session_info()).unwrap();
    let bytes =
        make_approval_recovery_record(&intent, &runtime.approval, stable.clone(), audit).unwrap();
    index
        .create_exclusive(&scope_digest(&stable), intent.command_id, &bytes)
        .unwrap();
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 0);
    intent.decision = ApprovalDecisionDto::Deny;
    let consent = TerminalConsent {
        displayed: runtime.approval.clone(),
        decision: intent.decision,
    };
    assert!(
        super::super::approval_retry::execute(&runtime, intent, &index, &consent)
            .await
            .is_ok()
    );
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 1);
    assert_eq!(index.records.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn tui_unknown_old_outcome_never_posts_a_new_decision() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut runtime = fakes::FakeApprovalRuntime::new(fakes::approval(), events.clone());
    runtime.wrong_ack_task = true;
    let index = fakes::memory_index(events);
    let mut intent = fakes::response_intent(ApprovalDecisionDto::Approve);
    intent.command_id = intent.approval_id;
    intent.idempotency_key = format!("tui-approval:{}", intent.approval_id);
    let consent = TerminalConsent {
        displayed: runtime.approval.clone(),
        decision: intent.decision,
    };
    assert!(
        super::super::approval_retry::execute(&runtime, intent.clone(), &index, &consent)
            .await
            .is_err()
    );
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 1);
    intent.decision = ApprovalDecisionDto::Deny;
    let deny = TerminalConsent {
        displayed: runtime.approval.clone(),
        decision: intent.decision,
    };
    assert!(
        super::super::approval_retry::execute(&runtime, intent, &index, &deny)
            .await
            .is_err()
    );
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 1);
    assert_eq!(index.records.lock().unwrap().len(), 1);
}
