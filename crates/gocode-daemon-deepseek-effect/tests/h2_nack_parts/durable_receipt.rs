use std::path::Path;

use gocode_application::provider::{ProviderAuthorityIssueRequest, ProviderLeaseBindingKind};
use gocode_domain::id::{AttemptId, ConversationId, EventLogLineageId, TaskRunId};
use gocode_provider::{
    CredentialLease, CredentialVersionRef, DispatchRequest, ModelRef, PrepareCredentialVersion,
    PreparedRequest, ProviderCall, ProviderCallId, ProviderCapability,
    ProviderCredentialVersionStore, ProviderId, ProviderInputRole, ProviderTextInput,
};
use gocode_provider_deepseek::{DEEPSEEK_MODEL_ID, DEEPSEEK_MODEL_REVISION};
use gocode_store::provider::{
    DurableProviderAdmission, PreparedProviderRecord, ProviderAuthorityIssueOutcome,
    ProviderRuntimeAuthorityConfig, SqliteProviderCredentialLifecycleStore,
    SqliteProviderDispatchStore, SqliteProviderExecutionStore,
};
use gocode_store::schema::{
    ConnectionMode, ManagedConnection, apply_migrations, ensure_authority_id,
    ensure_event_log_lineage_id, generate_authority_id, open_managed_connection,
    read_authority_id, read_event_log_lineage_id, reopen_managed_connection_validated,
};
use rusqlite::{Connection, Error as SqliteError, OpenFlags};

#[derive(Clone, Copy, PartialEq, Eq)]
struct MainDatabaseIdentity {
    authority_id: [u8; 16],
    lineage_id: EventLogLineageId,
}

fn durable_dispatch(
    profile: &DeepSeekResponsesTextProfile,
    effect: &dyn gocode_daemon_deepseek_effect::DeepSeekEffect,
) -> (
    DispatchRequest,
    gocode_store::provider::ProviderEffectStartReceipt,
    gocode_store::provider::CredentialDispatchBinding,
) {
    let runtime_root = tempfile::tempdir().expect("temporary runtime root");
    let daemon_directory = runtime_root.path().join("gocode-daemon");
    std::fs::create_dir(&daemon_directory).expect("daemon runtime directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(runtime_root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("runtime root permissions");
        std::fs::set_permissions(&daemon_directory, std::fs::Permissions::from_mode(0o700))
            .expect("daemon runtime directory permissions");
    }
    let path = daemon_directory.join("provider.sqlite");
    let path_str = path.to_str().expect("database path");
    let prepared = effect
        .prepare(&deepseek_call(profile))
        .expect("prepared DeepSeek request");
    let dispatch_connection =
        open_managed_connection(&path, ConnectionMode::Writer).expect("dispatch connection");
    apply_migrations(&dispatch_connection).expect("dispatch migrations");
    ensure_authority_id(&dispatch_connection, &generate_authority_id()).expect("authority ID");
    ensure_event_log_lineage_id(&dispatch_connection).expect("event-log lineage ID");
    let identity = capture_main_database_identity(&dispatch_connection).expect("main DB identity");
    let dispatch_store =
        SqliteProviderDispatchStore::open_with_connection(path_str, dispatch_connection)
            .expect("dispatch store");
    dispatch_store
        .persist_prepared(&PreparedProviderRecord {
            call_id: prepared.call().call_id(),
            call_digest_version: prepared.request_ref().digest_version(),
            prepared_digest: *prepared.request_ref().as_bytes(),
            render_digest: *prepared.render_digest(),
            profile_digest: profile.profile_digest(),
        })
        .expect("durable prepared request");
    let hot_wal_guard = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("hot WAL guard");
    hot_wal_guard
        .execute_batch("PRAGMA query_only = ON; BEGIN; SELECT authority_id FROM _authority;")
        .expect("hold hot WAL");
    let execution_connection =
        open_validated_connection(&path, identity).expect("validated execution connection");
    let _reader = open_validated_reader(&path, identity).expect("validated reader connection");
    let execution_store =
        SqliteProviderExecutionStore::open_with_connection(path_str, execution_connection)
            .expect("execution store");
    execution_store
        .install_runtime_authority(&runtime_authority(profile))
        .expect("runtime authority");
    let admission = match execution_store
        .issue(&authority_issue_request(&prepared, profile))
        .expect("durable provider authority")
    {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("new durable provider authority"),
    };
    let credential_store = SqliteProviderCredentialLifecycleStore::open_with_connection(
        open_validated_connection(&path, identity).expect("credential lifecycle connection"),
    )
    .expect("credential lifecycle store");
    let reference = CredentialVersionRef::new(ProviderId::new("deepseek").unwrap(), 1).unwrap();
    credential_store
        .create_prepared(PrepareCredentialVersion::new(reference.clone()))
        .unwrap();
    credential_store
        .activate(CredentialLease::new(reference.clone(), [1; 16], i64::MAX, 13).unwrap())
        .unwrap();
    let binding = credential_store
        .authorize_active(reference.provider(), [1; 16], 13, 100)
        .unwrap();
    receipt_from_admission(execution_store, prepared, admission, binding)
}

fn capture_main_database_identity(
    connection: &Connection,
) -> Result<MainDatabaseIdentity, SqliteError> {
    Ok(MainDatabaseIdentity {
        authority_id: read_authority_id(connection)?.ok_or(SqliteError::InvalidQuery)?,
        lineage_id: read_event_log_lineage_id(connection)?.ok_or(SqliteError::InvalidQuery)?,
    })
}

fn open_validated_connection(
    path: &Path,
    identity: MainDatabaseIdentity,
) -> Result<ManagedConnection, SqliteError> {
    reopen_managed_connection_validated(path, ConnectionMode::ValidatedReopen, |connection| {
        if capture_main_database_identity(connection)? == identity {
            Ok(())
        } else {
            Err(SqliteError::InvalidQuery)
        }
    })
}

fn open_validated_reader(
    path: &Path,
    identity: MainDatabaseIdentity,
) -> Result<ManagedConnection, SqliteError> {
    reopen_managed_connection_validated(path, ConnectionMode::Reader, |connection| {
        if capture_main_database_identity(connection)? == identity {
            Ok(())
        } else {
            Err(SqliteError::InvalidQuery)
        }
    })
}

fn receipt_from_admission(
    execution_store: SqliteProviderExecutionStore,
    prepared: PreparedRequest,
    admission: Box<DurableProviderAdmission>,
    credential: gocode_store::provider::CredentialDispatchBinding,
) -> (
    DispatchRequest,
    gocode_store::provider::ProviderEffectStartReceipt,
    gocode_store::provider::CredentialDispatchBinding,
) {
    let claim = admission.into_claim();
    let request = DispatchRequest::new(prepared, claim.clone()).expect("dispatch claim binding");
    let receipt = execution_store
        .start_effect(&claim, &credential)
        .expect("durable effect-start receipt");
    (request, receipt, credential)
}

fn deepseek_call(profile: &DeepSeekResponsesTextProfile) -> ProviderCall {
    ProviderCall::new(
        ProviderCallId::from_bytes([7; 16]),
        ModelRef::new(
            ProviderId::new("deepseek").expect("provider ID"),
            DEEPSEEK_MODEL_ID,
            DEEPSEEK_MODEL_REVISION,
        )
        .expect("DeepSeek model"),
        [9; 32],
        32,
        profile.binding_extension(),
    )
    .expect("provider call")
    .with_text_inputs(vec![ProviderTextInput::new(
        ProviderInputRole::User,
        "hello",
    )
    .expect("input")])
    .expect("text inputs")
    .with_required_capabilities(vec![ProviderCapability::Streaming])
}

fn runtime_authority(profile: &DeepSeekResponsesTextProfile) -> ProviderRuntimeAuthorityConfig {
    ProviderRuntimeAuthorityConfig {
        runtime_authority_id: [1; 16],
        database_generation: 7,
        principal_id: "principal-1".into(),
        owner_id: "owner-1".into(),
        scope: "provider.dispatch".into(),
        generation: 11,
        fencing_token: 13,
        capability_grant_id: "capability-1".into(),
        capability_revision: 2,
        capability_allowed: true,
        capability_revocation_epoch: 1,
        approval_id: "approval-1".into(),
        approval_revision: 3,
        approval_allowed: true,
        approval_revocation_epoch: 1,
        profile_digest: profile.profile_digest(),
        pricing_revision_digest: profile.pricing_revision_digest(),
        activation_binding_kind: ProviderLeaseBindingKind::ProtectedV2,
        activation_binding_digest: [4; 32],
        token_budget_limit: 10_000,
        cost_budget_limit_micros: 1_000_000,
        authority_ttl_seconds: 120,
        lease_ttl_seconds: 600,
    }
}

fn authority_issue_request(
    prepared: &PreparedRequest,
    profile: &DeepSeekResponsesTextProfile,
) -> ProviderAuthorityIssueRequest {
    ProviderAuthorityIssueRequest {
        principal_id: "principal-1".into(),
        conversation_id: ConversationId::from_bytes([6; 16]),
        taskrun_id: TaskRunId::from_bytes([7; 16]),
        execution_attempt_id: AttemptId::from_bytes([8; 16]),
        prepared: gocode_provider::PreparedProviderRecord {
            call_id: prepared.call().call_id(),
            call_digest_version: prepared.request_ref().digest_version(),
            prepared_digest: *prepared.request_ref().as_bytes(),
            render_digest: *prepared.render_digest(),
            profile_digest: profile.profile_digest(),
        },
        pricing_revision_digest: profile.pricing_revision_digest(),
        requested_input_tokens: 512,
        requested_output_tokens: 1_024,
        max_cost_micros: 50_000,
        currency: "USD".into(),
        provider_idempotency_key: "h2-nack-one-effect".into(),
    }
}
