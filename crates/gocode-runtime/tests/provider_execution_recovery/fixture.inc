struct Fixture {
    _database: validated_reopen::ValidatedTestDatabase,
    execution: Arc<SqliteProviderExecutionStore>,
    attempt_id: gocode_provider::DispatchAttemptId,
    fencing_token: u64,
    path: std::path::PathBuf,
    identity: validated_reopen::MainDatabaseIdentity,
}

fn fixture() -> Fixture {
    fixture_with_input_tokens(512)
}

fn fixture_with_input_tokens(requested_input_tokens: u64) -> Fixture {
    let database = validated_reopen::ValidatedTestDatabase::new("provider-runtime-recovery");
    let path = std::path::PathBuf::from(database.path());
    let path_text = path.to_str().unwrap();
    let identity = validated_reopen::initialize_database_identity(path_text).unwrap();
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([4; 16]),
        ModelRef::new(ProviderId::new("fixture-provider").unwrap(), "fixture-model", "2026-07-31").unwrap(),
        [5; 32],
        1_024,
        serde_json::Value::Null,
    )
    .unwrap();
    let prepared = PreparedRequest::from_call(&call).unwrap();
    let prepared_record = PreparedProviderRecord {
        call_id: call.call_id(),
        call_digest_version: prepared.request_ref().digest_version(),
        prepared_digest: *prepared.request_ref().as_bytes(),
        render_digest: *prepared.render_digest(),
        profile_digest: [2; 32],
    };
    let connection = gocode_store::schema::open_with_pragmas(path_text).unwrap();
    let dispatch = SqliteProviderDispatchStore::open_with_connection(path_text, connection).unwrap();
    dispatch.persist_prepared(&prepared_record).unwrap();
    assert!(SqliteProviderExecutionStore::open(&path).is_err());
    let connection = validated_reopen::open_validated_connection(path_text, identity).unwrap();
    let execution = Arc::new(SqliteProviderExecutionStore::open_with_connection(path_text, connection).unwrap());
    execution.install_runtime_authority(&ProviderRuntimeAuthorityConfig {
        runtime_authority_id: [1; 16], database_generation: 7, principal_id: "principal-1".to_owned(), owner_id: "runtime-owner-1".to_owned(), scope: "provider.dispatch".to_owned(), generation: 11, fencing_token: 13,
        capability_grant_id: "grant-provider-network-1".to_owned(), capability_revision: 2, capability_allowed: true, capability_revocation_epoch: 1,
        approval_id: "approval-provider-network-1".to_owned(), approval_revision: 3, approval_allowed: true, approval_revocation_epoch: 1,
        profile_digest: [2; 32], pricing_revision_digest: [3; 32], activation_binding_kind: gocode_application::provider::ProviderLeaseBindingKind::ProtectedV2,
        activation_binding_digest: [4; 32], token_budget_limit: 10_000, cost_budget_limit_micros: 1_000_000, authority_ttl_seconds: 120, lease_ttl_seconds: 600,
    }).unwrap();
    let ProviderAuthorityIssueOutcome::Winner(admitted) = execution.issue(&ProviderAuthorityIssueRequest {
        principal_id: "principal-1".to_owned(), conversation_id: ConversationId::from_bytes([6; 16]), taskrun_id: TaskRunId::from_bytes([7; 16]), execution_attempt_id: AttemptId::from_bytes([8; 16]),
        prepared: ContractPreparedProviderRecord { call_id: prepared_record.call_id, call_digest_version: prepared_record.call_digest_version, prepared_digest: prepared_record.prepared_digest, render_digest: prepared_record.render_digest, profile_digest: prepared_record.profile_digest },
        pricing_revision_digest: [3; 32], requested_input_tokens, requested_output_tokens: 1_024, max_cost_micros: 50_000, currency: "USD".to_owned(), provider_idempotency_key: "provider-runtime-recovery-1".to_owned(),
    }).unwrap() else { panic!("first issue must win") };
    dispatch.mark_streaming(&MarkProviderStreaming { attempt_id: admitted.claim().attempt_id, fencing_token: admitted.claim().fencing_token, stream_id: ProviderStreamId::from_bytes([9; 16]) }).unwrap();
    Fixture { _database: database, execution, attempt_id: admitted.claim().attempt_id, fencing_token: admitted.claim().fencing_token, path, identity }
}

fn validated_connection(fixture: &Fixture) -> rusqlite::Connection {
    let connection = validated_reopen::open_validated_connection(
        fixture.path.to_str().unwrap(),
        fixture.identity,
    )
    .unwrap();
    connection.execute_batch("PRAGMA query_only = ON;").unwrap();
    connection
}
