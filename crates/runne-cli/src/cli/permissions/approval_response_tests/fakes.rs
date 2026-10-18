use super::*;

const APPROVAL: &str = "018f2e3a-7000-7000-8000-000000000011";
const TASK_RUN: &str = "018f2e3a-7000-7000-8000-000000000012";

pub(super) struct FakeApprovalRuntime {
    session_reads: AtomicUsize,
    pub(super) approval_reads: AtomicUsize,
    pub(super) unknown_after_post: AtomicBool,
    pub(super) changed_tuple_on_refetch: bool,
    pub(super) changed_session_after_first: bool,
    pub(super) wrong_ack_task: bool,
    pub(super) approval: ApprovalSnapshot,
    pub(super) server: Arc<FakeApprovalServer>,
    pub(super) durable_record_path: Option<PathBuf>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

#[derive(Default)]
pub(super) struct FakeApprovalServer {
    pub(super) posts: AtomicUsize,
    ack: Mutex<Option<ApprovalAck>>,
}

impl FakeApprovalRuntime {
    pub(super) fn new(approval: ApprovalSnapshot, events: Arc<Mutex<Vec<&'static str>>>) -> Self {
        Self::with_server(approval, events, Arc::default())
    }

    pub(super) fn with_server(
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

pub(super) struct MockConsent {
    pub(super) failure: Option<ApprovalConfirmationError>,
    pub(super) barrier: Option<Arc<Barrier>>,
    pub(super) calls: AtomicUsize,
    pub(super) events: Arc<Mutex<Vec<&'static str>>>,
}

impl MockConsent {
    pub(super) fn allowed(events: Arc<Mutex<Vec<&'static str>>>) -> Self {
        Self {
            failure: None,
            barrier: None,
            calls: AtomicUsize::new(0),
            events,
        }
    }

    pub(super) fn unavailable(events: Arc<Mutex<Vec<&'static str>>>) -> Self {
        Self {
            failure: Some(ApprovalConfirmationError::Unavailable),
            barrier: None,
            calls: AtomicUsize::new(0),
            events,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct MockToken {
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

pub(super) fn response_intent(
    decision: runne_runtime_client::ApprovalDecisionDto,
) -> ApprovalResponseIntent {
    ApprovalResponseIntent {
        approval_id: CanonicalId::parse(APPROVAL).unwrap(),
        command_id: CanonicalId::parse(COMMAND).unwrap(),
        idempotency_key: "approval-key-01".to_owned(),
        decision,
    }
}

pub(super) fn approval() -> ApprovalSnapshot {
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

pub(super) fn memory_index(events: Arc<Mutex<Vec<&'static str>>>) -> MemoryIndex {
    MemoryIndex {
        events,
        ..MemoryIndex::default()
    }
}
