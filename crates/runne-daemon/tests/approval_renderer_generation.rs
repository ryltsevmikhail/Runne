#![cfg(unix)]

use std::{path::Path, path::PathBuf, sync::Arc, time::Duration};

use runne_app_core::RuntimeAvailability;
use runne_application::ports::RuntimeAuthorityId;
use runne_daemon::application::DaemonApplication;
use runne_daemon::config::{BuiltInDefaults, ConfigurationSnapshot};
use runne_daemon::error::DaemonError;
use runne_domain::id::{ApprovalId, InvocationId, TaskRunId};
use runne_runtime_client::{
    ApprovalDecisionDto, ApprovalStateDto, AuthenticatedRuntimeClient, CanonicalId,
    CommandIdentity, CommandReconciliationDisposition, CommandReconciliationOutcome,
    CommandReconciliationRequest, LocalRuntimeProfile, RuntimeApiErrorKind,
};
use runne_secure_store::SecureStore;
use runne_store::{ProjectWorkspaceStore, store::StoreTransaction};
use tokio::sync::oneshot;

#[path = "support/owner_private.rs"]
mod owner_private;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn desktop_confirmation_uses_persisted_approval_generation_after_reload() {
    let directory = owner_private::tempdir();
    let mut defaults = BuiltInDefaults::new(directory.path());
    defaults.http_bind = "127.0.0.1:0".to_owned();
    let config = ConfigurationSnapshot::from_defaults(&defaults);
    let (approval_id, action_digest) =
        seed_pending_approval_generation_three(&config.db_path).await;

    let application = DaemonApplication::start(&config)
        .await
        .expect("start real Store-backed daemon");
    let (stop, stopped) = oneshot::channel();
    let daemon = tokio::spawn(application.run(async move {
        stopped
            .await
            .map_err(|_| DaemonError::Bootstrap("test shutdown sender dropped".to_owned()))
    }));

    let runtime_profile =
        PathBuf::from(&config.replay_integrity_key_path).with_file_name("client-profile.json");
    let local_database_path = directory.path().join("desktop.sqlite3");
    let security_profile = [0xD3; 32];
    let secure: Arc<dyn SecureStore> =
        Arc::new(runne_secure_store::test_support::DeterministicSecureStore::new(security_profile));
    let core = runne_app_core::test_support::open_anchored_external_local_core(
        &local_database_path,
        runtime_profile,
        secure,
        security_profile,
    )
    .expect("open desktop AppCore fixture");
    assert_eq!(
        core.connect_runtime().await.expect("connect over HTTP"),
        RuntimeAvailability::Live
    );

    // This is the AppCore confirmation boundary after a renderer reload; it
    // does not simulate or claim an actual GUI page-load or human interaction.
    let action_digest_hex = action_digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let confirmation = async {
        let binding = core
            .prepare_approval_confirmation(
                &approval_id.to_string(),
                1,
                ApprovalDecisionDto::Approve,
                &action_digest_hex,
                7,
                2,
            )
            .await
            .expect("prepare native confirmation using renderer generation 2");
        core.commit_approval_confirmation(&binding).await
    }
    .await;

    drop(core);
    stop.send(()).expect("stop daemon");
    tokio::time::timeout(Duration::from_secs(15), daemon)
        .await
        .expect("daemon shutdown timeout")
        .expect("daemon task")
        .expect("daemon shutdown");

    let connection = rusqlite::Connection::open_with_flags(
        &config.db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("open stopped daemon database read-only");
    let (stored_generation, stored_state): (i64, i64) = connection
        .query_row(
            "SELECT renderer_generation, state FROM approvals WHERE approval_id = ?1",
            [approval_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read canonical approval row after daemon stop");
    assert_eq!(stored_generation, 3);
    assert_eq!(stored_state, 2, "approval must be durably approved");

    let acknowledgement = confirmation.expect(
        "pending approval persisted at generation 3 must commit with canonical generation 3 even though the renderer is generation 2",
    );
    assert_eq!(
        acknowledgement.approval_id().to_string(),
        approval_id.to_string()
    );
    assert_eq!(
        acknowledgement.state(),
        runne_runtime_client::ApprovalStateDto::Approved
    );
    assert_eq!(acknowledgement.new_version(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_http_approval_receipt_reconciles_after_daemon_reopen() {
    let mut changed_decision_errors = Vec::new();
    for (decision, expected_state, stored_decision, stored_state) in [
        (
            ApprovalDecisionDto::Approve,
            ApprovalStateDto::Approved,
            1_i64,
            2_i64,
        ),
        (
            ApprovalDecisionDto::Deny,
            ApprovalStateDto::Denied,
            2_i64,
            3_i64,
        ),
    ] {
        let directory = owner_private::tempdir();
        let mut defaults = BuiltInDefaults::new(directory.path());
        defaults.http_bind = "127.0.0.1:0".to_owned();
        let config = ConfigurationSnapshot::from_defaults(&defaults);
        let (approval_id, _) = seed_pending_approval_generation_three(&config.db_path).await;
        let profile_path =
            PathBuf::from(&config.replay_integrity_key_path).with_file_name("client-profile.json");

        let (stop, daemon) = start_daemon(&config).await;
        let first_client = connect_runtime(&profile_path).await;
        let approval_id = CanonicalId::parse(&approval_id.to_string()).unwrap();
        let approval = first_client
            .get_approval(approval_id)
            .await
            .expect("read generation-3 approval over authenticated HTTP");
        assert_eq!(approval.request_version(), 1);
        assert_eq!(approval.approval_generation(), 3);
        let command_id = CanonicalId::now_v7();
        let idempotency_key = format!("approval-recovery-{stored_decision}");
        let identity = CommandIdentity::new(command_id, idempotency_key.clone())
            .expect("exact decision command identity");

        // The single decision POST's ACK is deliberately discarded. Reconciliation
        // after a real daemon/SQLite reopen is the sole completion evidence below.
        let request = decision_witness(
            &identity,
            &approval,
            decision,
            approval.approval_generation(),
        );
        let _ = first_client
            .decide_approval(
                runne_runtime_client::ApprovalDecisionRequest::new(
                    identity.clone(),
                    approval.approval_id(),
                    approval.request_version(),
                    decision,
                    *approval.action_digest(),
                    approval.policy_revision(),
                    approval.approval_generation(),
                )
                .expect("valid generation-3 decision"),
            )
            .await
            .expect("send one real HTTP approval decision");
        drop(first_client);
        stop_daemon(stop, daemon).await;

        let before = read_approval_receipt(&config.db_path, approval_id);
        let expected_command_bytes = hex::decode(command_id.to_string().replace('-', "")).unwrap();
        assert_eq!(before.task_run_id, approval.task_run_id().to_string());
        assert_eq!(before.action_digest.as_slice(), approval.action_digest());
        assert_eq!(
            before.policy_revision,
            i64::try_from(approval.policy_revision()).unwrap()
        );
        assert_eq!(before.request_version, 2);
        assert_eq!(before.renderer_generation, 3);
        assert_eq!(before.expires_at, approval.expires_at());
        assert_eq!(before.state, stored_state);
        assert_eq!(before.decision, Some(stored_decision));
        assert_eq!(
            before.decision_command_id.as_deref(),
            Some(expected_command_bytes.as_slice())
        );
        assert_eq!(
            before.decision_idempotency_key.as_deref(),
            Some(idempotency_key.as_str())
        );
        assert_eq!(before.decision_principal_id.as_deref(), Some("local-owner"));

        let (stop, daemon) = start_daemon(&config).await;
        let restarted_client = connect_runtime(&profile_path).await;
        let receipt = restarted_client
            .reconcile_command(request.clone())
            .await
            .expect("read exact approval command receipt over fresh authenticated HTTP");
        assert_approval_reconciliation(
            receipt,
            approval.approval_id(),
            approval.task_run_id(),
            expected_state,
        );
        assert_eq!(read_approval_receipt(&config.db_path, approval_id), before);

        let repeated = restarted_client
            .reconcile_command(request)
            .await
            .expect("repeat read-only exact command reconciliation");
        assert_approval_reconciliation(
            repeated,
            approval.approval_id(),
            approval.task_run_id(),
            expected_state,
        );
        assert_eq!(read_approval_receipt(&config.db_path, approval_id), before);

        let changed_decision = decision_witness(
            &identity,
            &approval,
            match decision {
                ApprovalDecisionDto::Approve => ApprovalDecisionDto::Deny,
                ApprovalDecisionDto::Deny => ApprovalDecisionDto::Approve,
            },
            approval.approval_generation(),
        );
        changed_decision_errors.push(
            restarted_client
                .reconcile_command(changed_decision)
                .await
                .unwrap_err()
                .kind(),
        );
        let changed_generation = decision_witness(
            &identity,
            &approval,
            decision,
            approval.approval_generation() + 1,
        );
        assert_eq!(
            restarted_client
                .reconcile_command(changed_generation)
                .await
                .unwrap_err()
                .kind(),
            RuntimeApiErrorKind::Conflict
        );
        assert_eq!(read_approval_receipt(&config.db_path, approval_id), before);
        drop(restarted_client);
        stop_daemon(stop, daemon).await;
    }
    assert_eq!(
        changed_decision_errors,
        [RuntimeApiErrorKind::Conflict, RuntimeApiErrorKind::Conflict],
        "a different decision witness must be reported as a conflict"
    );
}

fn decision_witness(
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

fn assert_approval_reconciliation(
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

async fn start_daemon(
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

async fn connect_runtime(profile_path: &Path) -> AuthenticatedRuntimeClient {
    LocalRuntimeProfile::load(profile_path)
        .expect("load authenticated local-runtime profile")
        .connect(Duration::from_secs(10))
        .await
        .expect("fresh authenticated runtime client")
}

async fn stop_daemon(
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
struct ApprovalReceiptSnapshot {
    task_run_id: String,
    action_digest: Vec<u8>,
    policy_revision: i64,
    request_version: i64,
    renderer_generation: i64,
    expires_at: i64,
    state: i64,
    decision_command_id: Option<Vec<u8>>,
    decision_idempotency_key: Option<String>,
    decision_principal_id: Option<String>,
    decision: Option<i64>,
    decided_at: Option<i64>,
    updated_at: i64,
}

fn read_approval_receipt(db_path: &str, approval_id: CanonicalId) -> ApprovalReceiptSnapshot {
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

async fn seed_pending_approval_generation_three(db_path: &str) -> (ApprovalId, [u8; 32]) {
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
