use std::path::Path;
use std::sync::Arc;

use runne_application::provider::{ProviderAuthorityIssueRequest, ProviderJournalKeyBinding};
use runne_provider::{
    DispatchAttemptId, ModelRef, PreparedProviderRecord as ContractPreparedProviderRecord,
    PreparedRequest, ProviderCall, ProviderCallId, ProviderId, ProviderRepositoryState,
    ProviderStreamId,
};
use runne_runtime::provider_execution::ProviderEventJournalContext;
use runne_store::provider::{
    PreparedProviderRecord, ProviderAuthorityIssueOutcome,
    ProviderRuntimeLaunchCapability, SqliteProviderExecutionStore,
};

use crate::validated_reopen::ProviderTestDatabase;

use super::task5_support::{MemoryKeyring, SECRET, runtime_authority};

pub(super) struct Task5ProductionFixture {
    database: ProviderTestDatabase,
    execution: Arc<SqliteProviderExecutionStore>,
    launch: ProviderRuntimeLaunchCapability,
    request: ProviderAuthorityIssueRequest,
    attempt: DispatchAttemptId,
    context: ProviderEventJournalContext,
    stream: ProviderStreamId,
    journal_key: ProviderJournalKeyBinding,
    taskrun_event_count: i64,
}

impl Task5ProductionFixture {
    pub(super) fn new(keyring: &MemoryKeyring) -> Self {
        let database = ProviderTestDatabase::new("provider-task5-production");
        let receipt = crate::online_stream_fixture::begin_taskrun(
            &database,
            [1; 16],
            "principal-1",
            "provider task5 fixture",
            81,
        );
        let taskrun_event_count = database
            .query_connection()
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        let call = ProviderCall::new(
            ProviderCallId::from_bytes([4; 16]),
            ModelRef::new(
                ProviderId::new("fixture-provider").unwrap(),
                "fixture-model",
                "2026-08-08",
            )
            .unwrap(),
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
        let execution = Arc::new(database.execution());
        let launch = execution
            .activate_runtime_launch(&runtime_authority())
            .unwrap();
        let dispatch = database.dispatch();
        dispatch
            .persist_prepared(&launch, &prepared_record)
            .unwrap();
        let journal_key = crate::online_proof::arm_with_keyring(execution.as_ref(), keyring, 7);
        let request = ProviderAuthorityIssueRequest {
            provider_id: call.model_ref().provider_id().clone(),
            principal_id: "principal-1".into(),
            conversation_id: receipt.conversation_id,
            taskrun_id: receipt.taskrun_id,
            execution_attempt_id: receipt.attempt_id,
            prepared: ContractPreparedProviderRecord {
                call_id: prepared_record.call_id,
                call_digest_version: prepared_record.call_digest_version,
                prepared_digest: prepared_record.prepared_digest,
                render_digest: prepared_record.render_digest,
                profile_digest: prepared_record.profile_digest,
            },
            pricing_revision_digest: [3; 32],
            requested_input_tokens: 512,
            requested_output_tokens: 1_024,
            max_cost_micros: 50_000,
            currency: "USD".into(),
            provider_idempotency_key: "provider-task5-production-1".into(),
        };
        let (binding, _) = crate::online_stream_fixture::start_bound(
            &database,
            &execution,
            &launch,
            call,
            &request,
            ProviderStreamId::from_bytes([9; 16]),
            81,
        );
        let attempt = binding.execution().attempt_id();
        let fencing_token = binding.execution().fencing_token();
        let stream = binding.execution().stream_id();
        let context = ProviderEventJournalContext {
            attempt_id: attempt,
            fencing_token,
            call_digest_version: prepared_record.call_digest_version,
            profile_digest: [2; 32],
            runtime_generation: 11,
        };
        Self {
            database,
            execution,
            launch,
            request,
            attempt,
            context,
            stream,
            journal_key,
            taskrun_event_count,
        }
    }

    pub(super) fn path(&self) -> &Path {
        self.database.as_path()
    }

    pub(super) fn revoke(&self) {
        use runne_domain::id::{CommandId, IdempotencyKey};
        use runne_provider::*;
        let store =
            runne_store::provider::SqliteProviderCredentialLifecycleStore::open_with_connection(
                self.database.connection(),
            )
            .unwrap();
        let (_, authority) = CredentialEnrollmentAuthorityPair::new().split();
        let release = authority
            .issue_qualified_credential_release_tuple(
                authority.release_manifest_digest([201; 32]).unwrap(),
            )
            .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let operation = CredentialOperationId::from_bytes([91; 16]).unwrap();
        let command = BeginCredentialOperation::new(
            CommandId::from_bytes([111; 16]),
            IdempotencyKey::new("pending-poll-revoke").unwrap(),
            operation,
            CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap(),
            self.request.provider_id.clone(),
            CredentialOperationAction::Revoke,
            None,
            Some(CredentialVersionRef::new(self.request.provider_id.clone(), 1).unwrap()),
            CredentialLifecycleRevision::new(2).unwrap(),
            CredentialFence::new(2).unwrap(),
            CredentialBindingDigest::from_measured([92; 32]).unwrap(),
            now + 600,
        )
        .unwrap()
        .with_qualified_release_tuple(release);
        ProviderCredentialEnrollmentStore::begin(&store, command).unwrap();
        assert_eq!(
            store.load_operation(operation).unwrap().state(),
            CredentialOperationState::Prepared
        );
    }

    pub(super) fn execution(&self) -> &SqliteProviderExecutionStore {
        self.execution.as_ref()
    }

    pub(super) fn reopened_execution(&self) -> SqliteProviderExecutionStore {
        self.database.execution()
    }

    pub(super) const fn attempt(&self) -> DispatchAttemptId {
        self.attempt
    }

    pub(super) const fn context(&self) -> &ProviderEventJournalContext {
        &self.context
    }

    pub(super) const fn stream(&self) -> &ProviderStreamId {
        &self.stream
    }

    pub(super) const fn journal_key(&self) -> ProviderJournalKeyBinding {
        self.journal_key
    }

    pub(super) const fn canonical_event_baseline(&self) -> u64 {
        self.taskrun_event_count as u64
    }

    pub(super) fn persisted_counts(&self) -> (i64, i64, i64, i64) {
        let connection = self.database.query_connection();
        let count = |table: &str| {
            connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap()
        };
        (
            count("provider_stream_journal"),
            count("provider_terminal_outbox"),
            count("events") - self.taskrun_event_count,
            connection
                .query_row(
                    "SELECT COUNT(*) FROM provider_poll_flights
                     WHERE dispatch_attempt_id = ?1 AND cursor = 1",
                    [self.attempt.as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .unwrap(),
        )
    }

    pub(super) fn effect_start_and_audit_counts(&self) -> (i64, i64) {
        self.database
            .query_connection()
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM provider_effect_starts
                     WHERE dispatch_attempt_id = ?1
                       AND provider_idempotency_key = ?2 AND state = 1),
                    (SELECT COUNT(*) FROM security_audit_pre_effect
                     WHERE intent_id = ('provider:' || lower(hex(?1)))
                       AND side_effect_started = 1)",
                rusqlite::params![
                    self.attempt.as_bytes().as_slice(),
                    self.request.provider_idempotency_key,
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    }

    pub(super) fn dispatch_state(&self) -> ProviderRepositoryState {
        let connection = self.database.query_connection();
        match connection
            .query_row(
                "SELECT state FROM provider_dispatch_attempts WHERE attempt_id = ?1",
                [self.attempt.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
        {
            6 => ProviderRepositoryState::Uncertain,
            state => panic!("unexpected dispatch state {state}"),
        }
    }

    pub(super) fn retry_idempotency_state(&self) -> ProviderRepositoryState {
        match self.execution.issue(&self.launch, &self.request).unwrap() {
            ProviderAuthorityIssueOutcome::Existing { state } => state,
            ProviderAuthorityIssueOutcome::Winner(_) => panic!("retry minted duplicate authority"),
        }
    }

    pub(super) fn assert_secret_absent_from_durable_files(&self) {
        for entry in std::fs::read_dir(self.path().parent().unwrap()).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap_or_default();
            assert!(!bytes.windows(SECRET.len()).any(|window| window == SECRET));
        }
    }
}
