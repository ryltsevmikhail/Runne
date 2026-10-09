use super::*;
use crate::permissions_tests::{COMMAND, MemoryIndex, current_status, saved_record, session_info};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

const APPROVAL: &str = "018f2e3a-7000-7000-8000-000000000011";
const TASK_RUN: &str = "018f2e3a-7000-7000-8000-000000000012";

struct FakeApprovalRuntime {
    session_reads: AtomicUsize,
    approval_reads: AtomicUsize,
    unknown_after_post: AtomicBool,
    changed_tuple_on_refetch: bool,
    changed_session_after_first: bool,
    wrong_ack_task: bool,
    approval: ApprovalSnapshot,
    server: Arc<FakeApprovalServer>,
    durable_record_path: Option<PathBuf>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

#[derive(Default)]
struct FakeApprovalServer {
    posts: AtomicUsize,
    ack: Mutex<Option<ApprovalAck>>,
}

impl FakeApprovalRuntime {
    fn new(approval: ApprovalSnapshot, events: Arc<Mutex<Vec<&'static str>>>) -> Self {
        Self::with_server(approval, events, Arc::default())
    }

    fn with_server(
        approval: ApprovalSnapshot,
        events: Arc<Mutex<Vec<&'static str>>>,
        server: Arc<FakeApprovalServer>,
    ) -> Self {
        Self {
            session_reads: AtomicUsize::new(0),
            approval_reads: AtomicUsize::new(0),
            unknown_after_post: AtomicBool::new(false),
            changed_tuple_on_refetch: false,
            changed_session_after_first: false,
            wrong_ack_task: false,
            approval,
            server,
            durable_record_path: None,
            events,
        }
    }

    fn event(&self, name: &'static str) {
        self.events.lock().unwrap().push(name);
    }
}

impl PermissionsRuntime for FakeApprovalRuntime {
    fn permission_mode_status(
        &self,
        _workspace_id: CanonicalId,
    ) -> PermissionFuture<'_, runne_runtime_client::PermissionModeStatusV1> {
        Box::pin(async { Ok(current_status()) })
    }

    fn permission_mode_command_status(
        &self,
        _workspace_id: CanonicalId,
        _command_id: CanonicalId,
    ) -> PermissionFuture<'_, runne_runtime_client::PermissionModeCommandStatusV2> {
        Box::pin(async { panic!("approval response must not read permission-mode commands") })
    }

    fn list_pending_approvals(
        &self,
    ) -> PermissionFuture<'_, Vec<runne_runtime_client::ApprovalSummaryDto>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

impl ApprovalResponseRuntime for FakeApprovalRuntime {
    fn approval_session_info(&self) -> runne_runtime_client::RuntimeSessionInfo {
        let call = self.session_reads.fetch_add(1, Ordering::Relaxed);
        let mut info = session_info();
        if self.changed_session_after_first && call > 0 {
            info.principal_id.push_str("-changed");
        }
        info
    }

    fn read_approval(
        &self,
        _approval_id: CanonicalId,
    ) -> ApprovalRuntimeFuture<'_, ApprovalSnapshot> {
        self.event("approval_get");
        let call = self.approval_reads.fetch_add(1, Ordering::Relaxed);
        let mut approval = self.approval.clone();
        if self.changed_tuple_on_refetch && call > 0 {
            approval.resource.push_str("/changed");
        }
        Box::pin(async move { Ok(approval) })
    }

    fn decide_approval(
        &self,
        record: &ApprovalDecisionRecoveryRecordV1,
    ) -> ApprovalRuntimeFuture<'_, ApprovalAck> {
        if let Some(path) = &self.durable_record_path {
            let bytes = std::fs::read(path).expect("recovery record is on disk before POST");
            assert!(decode_approval_recovery_record(&bytes).is_ok());
            self.event("record_durable");
        }
        self.event("post");
        self.server.posts.fetch_add(1, Ordering::Relaxed);
        let state = match record.decision {
            StoredApprovalDecision::Approve => runne_runtime_client::ApprovalStateDto::Approved,
            StoredApprovalDecision::Deny => runne_runtime_client::ApprovalStateDto::Denied,
        };
        let task_run_id = if self.wrong_ack_task {
            CanonicalId::parse("018f2e3a-7000-7000-8000-000000000099").unwrap()
        } else {
            record.task_run_id
        };
        let ack = ApprovalAck {
            approval_id: record.approval_id,
            task_run_id,
            new_version: record.expected_version + 1,
            state,
        };
        *self.server.ack.lock().unwrap() = Some(ack);
        if self.unknown_after_post.load(Ordering::Relaxed) {
            Box::pin(async { Err(ApprovalRuntimeError::UnknownAfterSend) })
        } else {
            Box::pin(async move { Ok(ack) })
        }
    }

    fn reconcile_approval(
        &self,
        _record: &ApprovalDecisionRecoveryRecordV1,
    ) -> ApprovalRuntimeFuture<'_, ApprovalReconciliation> {
        self.event("reconcile");
        let result = (*self.server.ack.lock().unwrap()).map_or(
            ApprovalReconciliation::NotCommittedRetryable,
            ApprovalReconciliation::DurablyRecorded,
        );
        Box::pin(async move { Ok(result) })
    }
}

struct MockConsent {
    failure: Option<ApprovalConfirmationError>,
    barrier: Option<Arc<Barrier>>,
    calls: AtomicUsize,
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl MockConsent {
    fn allowed(events: Arc<Mutex<Vec<&'static str>>>) -> Self {
        Self {
            failure: None,
            barrier: None,
            calls: AtomicUsize::new(0),
            events,
        }
    }

    fn unavailable(events: Arc<Mutex<Vec<&'static str>>>) -> Self {
        Self {
            failure: Some(ApprovalConfirmationError::Unavailable),
            barrier: None,
            calls: AtomicUsize::new(0),
            events,
        }
    }
}

#[derive(Clone, Copy)]
struct MockToken {
    digest: [u8; 32],
    expiry: i64,
}

impl ApprovalConsent for MockConsent {
    type Token = MockToken;

    fn present(
        &self,
        _intent: &ApprovalResponseIntent,
        approval: &ApprovalSnapshot,
        digest: [u8; 32],
    ) -> Result<Self::Token, ApprovalConfirmationError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.events.lock().unwrap().push("confirm");
        if let Some(barrier) = &self.barrier {
            barrier.wait();
        }
        if let Some(error) = self.failure {
            return Err(error);
        }
        Ok(MockToken {
            digest,
            expiry: approval.expires_at,
        })
    }

    fn consume(&self, token: Self::Token, digest: [u8; 32], expires_at: i64) -> bool {
        self.events.lock().unwrap().push("consume");
        token.digest == digest && token.expiry == expires_at && expires_at > unix_millis().unwrap()
    }
}

fn response_intent(decision: runne_runtime_client::ApprovalDecisionDto) -> ApprovalResponseIntent {
    ApprovalResponseIntent {
        approval_id: CanonicalId::parse(APPROVAL).unwrap(),
        command_id: CanonicalId::parse(COMMAND).unwrap(),
        idempotency_key: "approval-key-01".to_owned(),
        decision,
    }
}

fn approval() -> ApprovalSnapshot {
    ApprovalSnapshot {
        approval_id: CanonicalId::parse(APPROVAL).unwrap(),
        task_run_id: CanonicalId::parse(TASK_RUN).unwrap(),
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

fn memory_index(events: Arc<Mutex<Vec<&'static str>>>) -> MemoryIndex {
    MemoryIndex {
        events,
        ..MemoryIndex::default()
    }
}

#[tokio::test]
async fn approve_and_deny_confirm_exact_review_then_durable_record_precedes_single_post() {
    for decision in [
        runne_runtime_client::ApprovalDecisionDto::Approve,
        runne_runtime_client::ApprovalDecisionDto::Deny,
    ] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let runtime = FakeApprovalRuntime::new(approval(), events.clone());
        let index = memory_index(events.clone());
        let consent = MockConsent::allowed(events.clone());
        assert!(
            execute_approval_response_with_consent(
                &runtime,
                response_intent(decision),
                &index,
                &consent,
            )
            .await
            .is_ok()
        );
        assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 1);
        assert_eq!(index.records.lock().unwrap().len(), 1);
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &[
                "approval_get",
                "confirm",
                "approval_get",
                "consume",
                "record_durable",
                "post"
            ]
        );
    }
}

#[tokio::test]
async fn cancel_unavailable_expiry_and_changed_tuple_never_create_or_post() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = FakeApprovalRuntime::new(approval(), events.clone());
    let index = memory_index(events.clone());
    let consent = MockConsent {
        failure: Some(ApprovalConfirmationError::Declined),
        barrier: None,
        calls: AtomicUsize::new(0),
        events: events.clone(),
    };
    assert!(
        execute_approval_response_with_consent(
            &runtime,
            response_intent(runne_runtime_client::ApprovalDecisionDto::Approve),
            &index,
            &consent,
        )
        .await
        .is_err()
    );
    assert!(index.records.lock().unwrap().is_empty());
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 0);

    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = FakeApprovalRuntime::new(approval(), events.clone());
    let index = memory_index(events.clone());
    assert!(
        execute_approval_response_with_consent(
            &runtime,
            response_intent(runne_runtime_client::ApprovalDecisionDto::Approve),
            &index,
            &MockConsent::unavailable(events.clone()),
        )
        .await
        .is_err()
    );
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 0);

    let events = Arc::new(Mutex::new(Vec::new()));
    let mut expired = approval();
    expired.expires_at = 1;
    let runtime = FakeApprovalRuntime::new(expired, events.clone());
    let index = memory_index(events.clone());
    let consent = MockConsent::allowed(events.clone());
    assert!(
        execute_approval_response_with_consent(
            &runtime,
            response_intent(runne_runtime_client::ApprovalDecisionDto::Approve),
            &index,
            &consent,
        )
        .await
        .is_err()
    );
    assert_eq!(consent.calls.load(Ordering::Relaxed), 0);
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 0);

    let events = Arc::new(Mutex::new(Vec::new()));
    let mut runtime = FakeApprovalRuntime::new(approval(), events.clone());
    runtime.changed_tuple_on_refetch = true;
    let index = memory_index(events.clone());
    let consent = MockConsent::allowed(events.clone());
    assert!(matches!(
        execute_approval_response_with_consent(
            &runtime,
            response_intent(runne_runtime_client::ApprovalDecisionDto::Approve),
            &index,
            &consent,
        )
        .await,
        Err(CliError::PermissionRecoveryConflict(_))
    ));
    assert!(index.records.lock().unwrap().is_empty());
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn session_change_and_cross_kind_or_corrupt_records_stop_before_post() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut runtime = FakeApprovalRuntime::new(approval(), events.clone());
    runtime.changed_session_after_first = true;
    let index = memory_index(events.clone());
    let consent = MockConsent::allowed(events.clone());
    assert!(matches!(
        execute_approval_response_with_consent(
            &runtime,
            response_intent(runne_runtime_client::ApprovalDecisionDto::Approve),
            &index,
            &consent,
        )
        .await,
        Err(CliError::PermissionRecoveryConflict(_))
    ));
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 0);

    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = FakeApprovalRuntime::new(approval(), events.clone());
    let index = memory_index(events.clone());
    let mode_bytes = saved_record(&crate::permissions_tests::intent());
    index
        .records
        .lock()
        .unwrap()
        .push(("other-scope".to_owned(), COMMAND.to_owned(), mode_bytes));
    assert!(matches!(
        execute_approval_response_with_consent(
            &runtime,
            response_intent(runne_runtime_client::ApprovalDecisionDto::Approve),
            &index,
            &MockConsent::allowed(events.clone()),
        )
        .await,
        Err(CliError::PermissionRecoveryConflict(_))
    ));
    assert_eq!(runtime.approval_reads.load(Ordering::Relaxed), 0);
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 0);

    index.records.lock().unwrap().clear();
    index.records.lock().unwrap().push((
        "other-scope".to_owned(),
        COMMAND.to_owned(),
        b"{".to_vec(),
    ));
    assert!(matches!(
        execute_approval_response_with_consent(
            &runtime,
            response_intent(runne_runtime_client::ApprovalDecisionDto::Approve),
            &index,
            &MockConsent::allowed(events.clone()),
        )
        .await,
        Err(CliError::PermissionRecoveryCorrupt(_))
    ));
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn linux_record_reopen_recovers_fake_lost_ack_without_prompt_or_resend() {
    let home = dirs::home_dir().expect("home directory for a private temporary state root");
    let directory = tempfile::Builder::new()
        .prefix("runne-approval-recovery-")
        .tempdir_in(home)
        .expect("private temporary state directory");
    let state_dir = directory.path().join("state");
    let events = Arc::new(Mutex::new(Vec::new()));
    let server = Arc::new(FakeApprovalServer::default());
    let intent = response_intent(runne_runtime_client::ApprovalDecisionDto::Deny);
    let mut first = FakeApprovalRuntime::with_server(approval(), events.clone(), server.clone());
    first.unknown_after_post.store(true, Ordering::Relaxed);
    let stable = StableRuntimeIdentity::from_session(&first.approval_session_info()).unwrap();
    let scope = scope_digest(&stable);
    first.durable_record_path = Some(
        state_dir
            .join("runne/cli/permission-intents")
            .join(&scope)
            .join(format!("{}.json", intent.command_id)),
    );
    let index = LinuxPermissionRecoveryIndex::new(state_dir.clone());
    let consent = MockConsent::allowed(events.clone());

    assert!(
        execute_approval_response_with_consent(&first, intent.clone(), &index, &consent)
            .await
            .is_ok()
    );
    assert_eq!(server.posts.load(Ordering::Relaxed), 1);
    assert_eq!(consent.calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        events.lock().unwrap().as_slice(),
        &[
            "approval_get",
            "confirm",
            "approval_get",
            "consume",
            "record_durable",
            "post",
            "reconcile"
        ]
    );

    let bytes = index
        .read_existing(&scope, intent.command_id)
        .unwrap()
        .expect("durable Linux recovery file");
    assert!(bytes.len() <= MAX_RECOVERY_RECORD_BYTES);
    for disclosure in [
        first.approval.action.as_bytes(),
        first.approval.resource.as_bytes(),
        first.approval.risk_summary.as_bytes(),
    ] {
        assert!(
            !bytes
                .windows(disclosure.len())
                .any(|window| window == disclosure)
        );
    }
    let record = decode_approval_recovery_record(&bytes).unwrap();
    assert_eq!(record.command_id, intent.command_id);
    assert_eq!(record.idempotency_key, intent.idempotency_key);
    assert_eq!(record.decision, StoredApprovalDecision::Deny);
    drop(index);

    // Reopen the real filesystem index and rebuild only the fake client adapter;
    // the simulated canonical server receipt survives independently of both.
    events.lock().unwrap().clear();
    let reopened = LinuxPermissionRecoveryIndex::new(state_dir);
    let restarted = FakeApprovalRuntime::with_server(approval(), events.clone(), server.clone());
    let no_prompt = MockConsent::unavailable(events.clone());
    assert!(
        execute_approval_response_with_consent(&restarted, intent, &reopened, &no_prompt,)
            .await
            .is_ok()
    );
    assert_eq!(server.posts.load(Ordering::Relaxed), 1);
    assert_eq!(no_prompt.calls.load(Ordering::Relaxed), 0);
    assert_eq!(events.lock().unwrap().as_slice(), &["reconcile"]);
}

#[tokio::test]
async fn lost_ack_and_restart_reconcile_only_without_resending() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = FakeApprovalRuntime::new(approval(), events.clone());
    runtime.unknown_after_post.store(true, Ordering::Relaxed);
    let index = memory_index(events.clone());
    assert!(
        execute_approval_response_with_consent(
            &runtime,
            response_intent(runne_runtime_client::ApprovalDecisionDto::Deny),
            &index,
            &MockConsent::allowed(events.clone()),
        )
        .await
        .is_ok()
    );
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 1);
    events.lock().unwrap().clear();
    let restart = FakeApprovalRuntime::new(approval(), events.clone());
    assert!(matches!(
        execute_approval_response_with_consent(
            &restart,
            response_intent(runne_runtime_client::ApprovalDecisionDto::Deny),
            &index,
            &MockConsent::unavailable(events.clone()),
        )
        .await,
        Err(CliError::PermissionCommandUnknown(_))
    ));
    assert_eq!(restart.server.posts.load(Ordering::Relaxed), 0);
    assert_eq!(events.lock().unwrap().as_slice(), &["reconcile"]);
}

#[tokio::test]
async fn wrong_task_run_ack_is_not_reported_as_success() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut runtime = FakeApprovalRuntime::new(approval(), events.clone());
    runtime.wrong_ack_task = true;
    let index = memory_index(events.clone());
    assert!(matches!(
        execute_approval_response_with_consent(
            &runtime,
            response_intent(runne_runtime_client::ApprovalDecisionDto::Approve),
            &index,
            &MockConsent::allowed(events),
        )
        .await,
        Err(CliError::PermissionCommandUnknown(_))
    ));
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 1);
}

#[test]
fn concurrent_identical_command_ids_post_at_most_once() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = Arc::new(FakeApprovalRuntime::new(approval(), events.clone()));
    let index = Arc::new(memory_index(events.clone()));
    let barrier = Arc::new(Barrier::new(2));
    let consent = Arc::new(MockConsent {
        failure: None,
        barrier: Some(barrier),
        calls: AtomicUsize::new(0),
        events: events.clone(),
    });
    std::thread::scope(|scope| {
        for _ in 0..2 {
            let runtime = Arc::clone(&runtime);
            let index = Arc::clone(&index);
            let consent = Arc::clone(&consent);
            scope.spawn(move || {
                let local = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap();
                let _ = local.block_on(execute_approval_response_with_consent(
                    &*runtime,
                    response_intent(runne_runtime_client::ApprovalDecisionDto::Approve),
                    &*index,
                    &*consent,
                ));
            });
        }
    });
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 1);
    assert_eq!(index.records.lock().unwrap().len(), 1);
}
