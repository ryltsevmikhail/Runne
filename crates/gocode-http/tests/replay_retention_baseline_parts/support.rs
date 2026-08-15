use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::Request;
use gocode_api::{ApiPrincipalId, DaemonInstanceId, RuntimeSessionBinding, StableRuntimeBinding};
use gocode_application::commands::{CommandOutcome, CreateTaskRunInput, QueueTaskRunInput};
use gocode_application::conversation_service::ConversationService;
use gocode_application::ports::{
    ReplayAuthorizationLease, ReplayAuthorizationPort, ReplayAuthorizationRequest, ReplayError,
    RuntimeAuthorityId,
};
use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use gocode_application::replay_service::ReplayService;
use gocode_application::service::TaskRunService;
use gocode_domain::event::Sensitivity;
use gocode_domain::id::{ConversationId, EventLogLineageId, TaskRunId, WorkspaceId};
use gocode_http::auth::{SessionAuthLayer, session_authorization_header};
use gocode_http::limits::LimitsConfig;
use gocode_http::middleware::request_id_middleware;
use gocode_http::replay::{ReplayHttpBinding, ReplayHttpState, replay_router};
use gocode_store::replay_store::ReplayStore;
use gocode_store::schema::{
    ConnectionMode, apply_migrations, ensure_authority_id, ensure_exact_event_log_lineage_id,
    open_managed_connection, read_authority_id, read_event_log_lineage_id,
    reopen_managed_connection_validated,
};
use tower::ServiceExt;

pub(super) const AUTHORITY: [u8; 16] = uuid_v7(0x42);
pub(super) const LINEAGE: [u8; 16] = uuid_v7(0x43);
const SESSION_TOKEN: [u8; 32] = [0x44; 32];
pub(super) const SESSION_AUTHORITY: [u8; 32] = [0x45; 32];

pub(super) struct AvailableGuard;
struct AvailableAuthorization;
pub(super) enum BaselineGuard {
    Denied,
    Unavailable,
}

enum GapShape {
    Prefix,
    Interior,
}

impl ProhibitedContentPort for AvailableGuard {
    fn inspect(
        &self,
        _: CanonicalContentBoundary,
        _: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}

impl ProhibitedContentPort for BaselineGuard {
    fn inspect(
        &self,
        _: CanonicalContentBoundary,
        _: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        match self {
            Self::Denied => Ok(ContentDisposition::Prohibited { policy_epoch: 2 }),
            Self::Unavailable => Err(ContentGuardError::Unavailable),
        }
    }
}

impl ReplayAuthorizationPort for AvailableAuthorization {
    fn current_lease(
        &self,
        request: &ReplayAuthorizationRequest,
    ) -> Result<ReplayAuthorizationLease, ReplayError> {
        ReplayAuthorizationLease::new(
            request.principal_id.clone(),
            request.expected_epoch,
            Sensitivity::Sensitive,
        )
    }
}

pub(super) struct RetentionGapFixture {
    pub(super) app: axum::Router,
    pub(super) taskrun_id: TaskRunId,
    pub(super) from_cursor: String,
    path: std::path::PathBuf,
    _directory: tempfile::TempDir,
}

pub(super) async fn retention_gap_fixture() -> RetentionGapFixture {
    retention_gap_fixture_with_shape(Arc::new(AvailableGuard), GapShape::Prefix).await
}

pub(super) async fn retention_interior_gap_fixture() -> RetentionGapFixture {
    retention_gap_fixture_with_shape(Arc::new(AvailableGuard), GapShape::Interior).await
}

pub(super) async fn retention_gap_fixture_with(
    replay_guard: Arc<dyn ProhibitedContentPort>,
) -> RetentionGapFixture {
    retention_gap_fixture_with_shape(replay_guard, GapShape::Prefix).await
}

async fn retention_gap_fixture_with_shape(
    replay_guard: Arc<dyn ProhibitedContentPort>,
    shape: GapShape,
) -> RetentionGapFixture {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("gocode-daemon");
    std::fs::create_dir(&daemon).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = daemon.join("replay.sqlite");
    let writer = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&writer).unwrap();
    ensure_authority_id(&writer, &AUTHORITY).unwrap();
    ensure_exact_event_log_lineage_id(&writer, EventLogLineageId::from_bytes(LINEAGE)).unwrap();
    let reader = open_validated_reader(&path);

    let authority = RuntimeAuthorityId("retention-http-test".into());
    let guard: Arc<dyn ProhibitedContentPort> = Arc::new(AvailableGuard);
    let store = StoreTransaction::open_with_connections(
        path.to_str().unwrap(),
        writer,
        reader,
        authority.clone(),
        Arc::clone(&guard),
    )
    .unwrap();
    let conversation_id = ConversationId::from_bytes(uuid_v7(0x51));
    let workspace_id = WorkspaceId::from_bytes(uuid_v7(0x52));
    seed_workspace(&store, workspace_id);
    let conversations = ConversationService::new(store.clone(), store.clone(), authority.clone());
    conversations
        .create(
            &api_context(),
            CreateConversationInput {
                conversation_id,
                workspace_id,
                command_id: command(2),
                idempotency_key: key(2),
            },
        )
        .unwrap();
    let task_runs = TaskRunService::new(store.clone(), store.clone(), store.clone(), authority);
    let taskrun_id = match task_runs
        .create_task_run(
            &context(5),
            CreateTaskRunInput {
                conversation_id,
                workspace_id,
            },
        )
        .unwrap()
    {
        CommandOutcome::TaskRunCreated {
            taskrun_id,
            new_version: 1,
        } => taskrun_id,
        outcome => panic!("unexpected taskrun create outcome: {outcome:?}"),
    };
    assert!(matches!(
        task_runs
            .queue_task_run(
                &context(6),
                QueueTaskRunInput {
                    taskrun_id,
                    expected_version: 1,
                },
            )
            .unwrap(),
        CommandOutcome::TaskRunQueued { new_version: 2, .. }
    ));
    drop(store);

    let pre_gap_app = replay_app(&path, binding(), Arc::new(AvailableGuard));
    let response = pre_gap_app
        .clone()
        .oneshot(open_request(taskrun_id, Some(SESSION_AUTHORITY), None))
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let from_cursor =
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["events"][0]["cursor"]
            .as_str()
            .unwrap()
            .to_owned();
    drop(pre_gap_app);

    let connection = open_validated_writer(&path);
    let snapshot_head: i64 = connection.query_row(
        "SELECT head_global_position FROM aggregate_state_snapshots WHERE aggregate_type = 1 AND aggregate_id = ?1",
        [taskrun_id.as_bytes()], |row| row.get(0),
    ).unwrap();
    assert_eq!(
        snapshot_head, 3,
        "production writes must create the V17 TaskRun snapshot"
    );
    connection
        .execute(
            match shape {
                GapShape::Prefix => "DELETE FROM events WHERE global_position <= 2",
                GapShape::Interior => "DELETE FROM events WHERE global_position = 2",
            },
            [],
        )
        .unwrap();
    connection
        .execute("DELETE FROM _replay_subscriptions", [])
        .unwrap();
    drop(connection);

    let app = replay_app(&path, binding(), replay_guard);
    RetentionGapFixture {
        app,
        taskrun_id,
        from_cursor,
        path,
        _directory: directory,
    }
}

pub(super) fn replay_app(
    path: &std::path::Path,
    binding: RuntimeSessionBinding,
    replay_guard: Arc<dyn ProhibitedContentPort>,
) -> axum::Router {
    replay_app_with_v2(path, binding, replay_guard, false)
}

fn replay_app_with_v2(
    path: &std::path::Path,
    binding: RuntimeSessionBinding,
    replay_guard: Arc<dyn ProhibitedContentPort>,
    v2: bool,
) -> axum::Router {
    let connection = open_validated_writer(path);
    let service = ReplayService::new(
        Arc::new(ReplayStore::new(connection)),
        [0x46; 32],
        EventLogLineageId::from_bytes(LINEAGE),
        Arc::new(AvailableAuthorization),
    );
    let state = ReplayHttpState::new(
        service,
        ReplayHttpBinding::new(AUTHORITY, 1, 0).unwrap(),
        LimitsConfig::default(),
        replay_guard,
    );
    replay_router(state.with_baseline_resume_v2(v2))
        .layer(session_layer(binding))
        .layer(axum::middleware::from_fn(request_id_middleware))
}

pub(super) fn open_validated_writer(
    path: &std::path::Path,
) -> gocode_store::schema::ManagedConnection {
    reopen_managed_connection_validated(path, ConnectionMode::ValidatedReopen, validate_identity)
        .unwrap()
}

pub(super) fn open_validated_reader(
    path: &std::path::Path,
) -> gocode_store::schema::ManagedConnection {
    reopen_managed_connection_validated(path, ConnectionMode::Reader, validate_identity).unwrap()
}

fn validate_identity(connection: &rusqlite::Connection) -> rusqlite::Result<()> {
    if read_authority_id(connection)? == Some(AUTHORITY)
        && read_event_log_lineage_id(connection)? == Some(EventLogLineageId::from_bytes(LINEAGE))
    {
        Ok(())
    } else {
        Err(rusqlite::Error::InvalidQuery)
    }
}

include!("session.rs");
include!("resume_support.rs");
