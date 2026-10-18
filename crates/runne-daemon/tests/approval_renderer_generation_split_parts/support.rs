use std::{path::Path, sync::Arc, time::Duration};

use runne_application::ports::RuntimeAuthorityId;
use runne_daemon::application::DaemonApplication;
use runne_daemon::config::ConfigurationSnapshot;
use runne_daemon::error::DaemonError;
use runne_domain::id::{ApprovalId, InvocationId, TaskRunId};
use runne_runtime_client::{
    ApprovalDecisionDto, ApprovalStateDto, AuthenticatedRuntimeClient, CanonicalId,
    CommandIdentity, CommandReconciliationDisposition, CommandReconciliationOutcome,
    CommandReconciliationRequest, LocalRuntimeProfile,
};
use runne_store::{ProjectWorkspaceStore, store::StoreTransaction};
use tokio::sync::oneshot;

use super::owner_private;

pub(super) fn decision_witness(
    identity: &CommandIdentity,
    approval: &runne_runtime_client::ApprovalSummaryDto,
    decision: ApprovalDecisionDto,
    generation: u64,
) -> CommandReconciliationRequest {
    CommandReconciliationRequest::approval_decision(
        identity.clone(),
        approval.approval_id(),
        approval.request_version(),
        decision,
        *approval.action_digest(),
        approval.policy_revision(),
        generation,
    )
    .expect("valid approval decision witness")
}

pub(super) fn assert_approval_reconciliation(
    disposition: CommandReconciliationDisposition,
    approval_id: CanonicalId,
    task_run_id: CanonicalId,
    state: ApprovalStateDto,
) {
    let CommandReconciliationDisposition::DurablyRecorded(
        CommandReconciliationOutcome::ApprovalDecision(acknowledgement),
    ) = disposition
    else {
        panic!("expected durable approval decision receipt")
    };
    assert_eq!(acknowledgement.approval_id(), approval_id);
    assert_eq!(acknowledgement.task_run_id(), task_run_id);
    assert_eq!(acknowledgement.state(), state);
    assert_eq!(acknowledgement.new_version(), 2);
}

pub(super) async fn start_daemon(
    config: &ConfigurationSnapshot,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), DaemonError>>,
) {
    let application = DaemonApplication::start(config)
        .await
        .expect("start real Store-backed daemon");
    let (stop, stopped) = oneshot::channel();
    let daemon = tokio::spawn(application.run(async move {
        stopped
            .await
            .map_err(|_| DaemonError::Bootstrap("test shutdown sender dropped".to_owned()))
    }));
    (stop, daemon)
}

pub(super) async fn connect_runtime(profile_path: &Path) -> AuthenticatedRuntimeClient {
    LocalRuntimeProfile::load(profile_path)
        .expect("load authenticated local-runtime profile")
        .connect(Duration::from_secs(10))
        .await
        .expect("fresh authenticated runtime client")
}

pub(super) async fn stop_daemon(
    stop: oneshot::Sender<()>,
    daemon: tokio::task::JoinHandle<Result<(), DaemonError>>,
) {
    stop.send(()).expect("stop daemon");
    tokio::time::timeout(Duration::from_secs(15), daemon)
        .await
        .expect("daemon shutdown timeout")
        .expect("daemon task")
        .expect("daemon shutdown");
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct ApprovalReceiptSnapshot {
    pub(super) task_run_id: String,
    pub(super) action_digest: Vec<u8>,
    pub(super) policy_revision: i64,
    pub(super) request_version: i64,
    pub(super) renderer_generation: i64,
    pub(super) expires_at: i64,
    pub(super) state: i64,
    pub(super) decision_command_id: Option<Vec<u8>>,
    pub(super) decision_idempotency_key: Option<String>,
    pub(super) decision_principal_id: Option<String>,
    pub(super) decision: Option<i64>,
    pub(super) decided_at: Option<i64>,
    pub(super) updated_at: i64,
}

pub(super) fn read_approval_receipt(
    db_path: &str,
    approval_id: CanonicalId,
) -> ApprovalReceiptSnapshot {
    let connection =
        rusqlite::Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open daemon database read-only");
    connection
        .query_row(
            "SELECT task_run_id, action_digest, policy_revision, request_version,
                    renderer_generation, expires_at, state, decision_command_id,
                    decision_idempotency_key, decision_principal_id, decision,
                    decided_at, updated_at
             FROM approvals WHERE approval_id = ?1",
            [approval_id.to_string()],
            |row| {
                Ok(ApprovalReceiptSnapshot {
                    task_run_id: row.get(0)?,
                    action_digest: row.get(1)?,
                    policy_revision: row.get(2)?,
                    request_version: row.get(3)?,
                    renderer_generation: row.get(4)?,
                    expires_at: row.get(5)?,
                    state: row.get(6)?,
                    decision_command_id: row.get(7)?,
                    decision_idempotency_key: row.get(8)?,
                    decision_principal_id: row.get(9)?,
                    decision: row.get(10)?,
                    decided_at: row.get(11)?,
                    updated_at: row.get(12)?,
                })
            },
        )
        .expect("read canonical approval decision receipt")
}

pub(super) async fn seed_pending_approval_generation_three(
    db_path: &str,
) -> (ApprovalId, [u8; 32]) {
    let parent = Path::new(db_path).parent().expect("daemon database parent");
    std::fs::create_dir_all(parent).expect("create daemon database directory");
    owner_private::secure_directory(parent);

    let authority_id = runne_store::schema::generate_authority_id();
    let connection = runne_store::schema::open_managed_connection(
        Path::new(db_path),
        runne_store::schema::ConnectionMode::Writer,
    )
    .expect("open fixture database for initialization");
    runne_store::schema::apply_migrations(&connection).expect("apply store migrations");
    runne_store::schema::ensure_authority_id(&connection, &authority_id)
        .expect("seed daemon authority");
    runne_store::schema::ensure_event_log_lineage_id(&connection).expect("seed event-log lineage");
    drop(connection);

    let authority = authority_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let guard = Arc::new(runne_security::SecretBroker::new().prohibited_content_guard());
    let store = StoreTransaction::open(db_path, RuntimeAuthorityId(authority), guard)
        .expect("open the same database through the public Store fixture API");
    let repository = ProjectWorkspaceStore::from_store(store.clone());
    let approval_id = ApprovalId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
    let action_digest = [0x42; 32];
    let task_run_id = TaskRunId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
    let invocation_id = InvocationId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
    let summary = runne_api::ApprovalRequestHostPort::create_pending_approval(
        &repository,
        runne_api::ApprovalCreateCommand::new(
            approval_id,
            task_run_id,
            None,
            invocation_id,
            runne_api::ApiPrincipalId::new("local-owner").expect("daemon owner principal"),
            "execute",
            "workspace",
            action_digest,
            7,
            3,
            i64::MAX,
            "requires approval",
        )
        .expect("valid generation-3 approval fixture"),
    )
    .await
    .expect("create pending approval through Store");
    assert_eq!(summary.state(), runne_api::ApprovalState::Pending);
    assert_eq!(summary.request_version(), 1);
    assert_eq!(summary.approval_generation(), 3);

    drop(repository);
    drop(store);
    (approval_id, action_digest)
}
